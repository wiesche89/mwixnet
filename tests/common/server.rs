use std::iter;
use std::net::TcpListener;
use std::sync::Arc;

use grin_api::{client, json_rpc};
use grin_core::core::Transaction;
use grin_util::ToHex;
use grin_wallet_libwallet::mwixnet::{
	MwixnetServerPublicKey, RouteSwapReq, SwapReq, SwapSubmission,
};
use serde_json::json;
use tor_rtcompat::PreferredRuntime;

use grin_onion::crypto::dalek::DalekPublicKey;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use mwixnet::mix_client::MixClientImpl;
use mwixnet::store::RouteStore;
use mwixnet::tor::TorService;
use mwixnet::{tor, SwapError, SwapServer, SwapStore};
use secp256k1zkp::SecretKey;

use crate::common::node::IntegrationGrinNode;
use crate::common::wallet::{GrinWalletManager, IntegrationGrinWallet};

pub struct IntegrationSwapServer<R: tor_rtcompat::Runtime> {
	onion_pubkey: MwixnetServerPublicKey,
	tor_instance: Arc<grin_util::Mutex<TorService<R>>>,
	swap_server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
	rpc_server: jsonrpc_http_server::Server,
	_wallet: Arc<grin_util::Mutex<IntegrationGrinWallet>>,
}

impl<R: tor_rtcompat::Runtime> IntegrationSwapServer<R> {
	pub async fn async_swap(&self, request: &SwapReq) -> Result<(), SwapError> {
		let url = format!("http://{}/v1", self.rpc_server.address());
		let params = json!([request]);
		let request = json_rpc::build_request("swap", &params);
		let response: json_rpc::Response = client::post_async(&url, &request, None)
			.await
			.map_err(|e| SwapError::ClientError(e.to_string()))?;
		if let Some(error) = response.error {
			return Err(SwapError::ClientError(error.message));
		}
		let response: String =
			serde_json::from_value(response.result.unwrap_or(serde_json::Value::Null))
				.map_err(|e| SwapError::ClientError(e.to_string()))?;
		if response == "success" {
			Ok(())
		} else {
			Err(SwapError::ClientError(format!(
				"Unexpected swap API response: {}",
				response
			)))
		}
	}

	pub async fn async_route_swap(
		&self,
		request: &RouteSwapReq,
	) -> Result<SwapSubmission, SwapError> {
		let url = format!("http://{}/v1", self.rpc_server.address());
		let params = json!([SwapReq::Route(request.clone())]);
		let request = json_rpc::build_request("swap", &params);
		let response: json_rpc::Response = client::post_async(&url, &request, None)
			.await
			.map_err(|e| SwapError::ClientError(e.to_string()))?;
		if let Some(error) = response.error {
			return Err(SwapError::ClientError(error.message));
		}
		serde_json::from_value(response.result.unwrap_or(serde_json::Value::Null))
			.map_err(|e| SwapError::ClientError(e.to_string()))
	}

	pub async fn async_execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError> {
		let mut attempts = 0;
		loop {
			match self.swap_server.lock().await.execute_round().await {
				Ok(tx) => return Ok(tx),
				Err(_) if attempts < 2 => {
					attempts += 1;
					tokio::time::sleep(std::time::Duration::from_secs(2)).await;
				}
				Err(error) => return Err(error),
			}
		}
	}

	pub async fn async_check_reorg(
		&self,
		tx: &Arc<Transaction>,
	) -> Result<Option<Arc<Transaction>>, SwapError> {
		self.swap_server.lock().await.check_reorg(tx).await
	}
}

pub struct IntegrationMixServer<R: tor_rtcompat::Runtime> {
	server_key: SecretKey,
	onion_pubkey: MwixnetServerPublicKey,
	tor_instance: Arc<grin_util::Mutex<TorService<R>>>,
	rpc_server: jsonrpc_http_server::Server,
	_wallet: Arc<grin_util::Mutex<IntegrationGrinWallet>>,
}

async fn async_new_swap_server<R>(
	data_dir: &str,
	rt_handle: &tokio::runtime::Handle,
	tor_runtime: R,
	wallets: &mut GrinWalletManager,
	server_key: &SecretKey,
	node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
	mixers: &[IntegrationMixServer<R>],
) -> IntegrationSwapServer<R>
where
	R: tor_rtcompat::Runtime + tor_rtcompat::ToplevelBlockOn,
{
	let wallet = wallets.async_new_wallet(&node.lock().api_address()).await;
	let next_server = mixers.first();

	let server_config = mwixnet::ServerConfig {
		key: server_key.clone(),
		interval_s: 15,
		addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		grin_node_url: node.lock().api_address().to_string(),
		grin_node_foreign_api_secret_path: None,
		wallet_owner_url: wallet.lock().owner_address().to_string(),
		wallet_owner_secret_path: None,
		collect_fees: true,
		accept_fee_base: grin_core::global::DEFAULT_ACCEPT_FEE_BASE,
		mixer: false,
		prev_server: None,
		next_server: match next_server {
			Some(s) => Some(DalekPublicKey::from_secret(&s.server_key)),
			None => None,
		},
		route_mixers: mixers
			.iter()
			.map(|server| {
				mwixnet_protocol::PublicKey(
					DalekPublicKey::from_secret(&server.server_key)
						.as_ref()
						.to_bytes(),
				)
			})
			.collect(),
		discover_mixers: false,
		target_route_hops: (mixers.len() + 1) as u8,
	};

	// Open SwapStore
	let store = SwapStore::new(format!("{}/db", data_dir).as_str()).unwrap();
	let tor_instance = tor::async_init_tor(tor_runtime, &data_dir, &server_config)
		.await
		.unwrap();
	let tor_instance = Arc::new(grin_util::Mutex::new(tor_instance));
	let client_factory: mwixnet::mix_client::MixClientFactory = Arc::new({
		let config = server_config.clone();
		let tor = tor_instance.clone();
		move |identity| {
			let key = DalekPublicKey::from_hex(&identity.0.to_hex())
				.map_err(mwixnet::mix_client::MixClientError::Dalek)?;
			Ok(Arc::new(MixClientImpl::new(
				config.clone(),
				tor.clone(),
				key,
			)))
		}
	});
	let route_clients = mixers
		.iter()
		.map(|server| {
			Arc::new(MixClientImpl::new(
				server_config.clone(),
				tor_instance.clone(),
				DalekPublicKey::from_secret(&server.server_key),
			)) as Arc<dyn mwixnet::mix_client::MixClient>
		})
		.collect::<Vec<_>>();

	let (swap_server, rpc_server) = mwixnet::swap_listen(
		rt_handle,
		&server_config,
		route_clients.first().cloned(),
		Some(wallet.lock().get_client()),
		node.lock().to_client(),
		store,
		RouteStore::new(format!("{}/db", data_dir).as_str()).unwrap(),
		route_clients,
		mixers
			.iter()
			.map(|server| {
				mwixnet_protocol::PublicKey(
					DalekPublicKey::from_secret(&server.server_key)
						.as_ref()
						.to_bytes(),
				)
			})
			.collect(),
		client_factory,
	)
	.unwrap();

	IntegrationSwapServer {
		onion_pubkey: server_config.onion_pubkey(),
		tor_instance,
		swap_server,
		rpc_server,
		_wallet: wallet,
	}
}

async fn async_new_mix_server<R>(
	data_dir: &str,
	rt_handle: &tokio::runtime::Handle,
	tor_runtime: R,
	wallets: &mut GrinWalletManager,
	server_key: &SecretKey,
	node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
	prev_server: DalekPublicKey,
	next_server: Option<&IntegrationMixServer<R>>,
) -> IntegrationMixServer<R>
where
	R: tor_rtcompat::Runtime + tor_rtcompat::ToplevelBlockOn,
{
	let wallet = wallets.async_new_wallet(&node.lock().api_address()).await;
	let server_config = mwixnet::ServerConfig {
		key: server_key.clone(),
		interval_s: 15,
		addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		grin_node_url: node.lock().api_address().to_string(),
		grin_node_foreign_api_secret_path: None,
		wallet_owner_url: wallet.lock().owner_address().to_string(),
		wallet_owner_secret_path: None,
		collect_fees: true,
		accept_fee_base: grin_core::global::DEFAULT_ACCEPT_FEE_BASE,
		mixer: true,
		prev_server: Some(prev_server),
		next_server: match next_server {
			Some(s) => Some(DalekPublicKey::from_secret(&s.server_key)),
			None => None,
		},
		route_mixers: Vec::new(),
		discover_mixers: false,
		target_route_hops: 2,
	};

	let tor_instance = tor::async_init_tor(tor_runtime, &data_dir, &server_config)
		.await
		.unwrap();
	let tor_instance = Arc::new(grin_util::Mutex::new(tor_instance));
	let client_factory: mwixnet::mix_client::MixClientFactory = Arc::new({
		let config = server_config.clone();
		let tor = tor_instance.clone();
		move |identity| {
			let key = DalekPublicKey::from_hex(&identity.0.to_hex())
				.map_err(mwixnet::mix_client::MixClientError::Dalek)?;
			Ok(Arc::new(MixClientImpl::new(
				config.clone(),
				tor.clone(),
				key,
			)))
		}
	});

	let (_, rpc_server) = mwixnet::mix_listen(
		rt_handle,
		server_config.clone(),
		match next_server {
			Some(s) => Some(Arc::new(MixClientImpl::new(
				server_config.clone(),
				tor_instance.clone(),
				DalekPublicKey::from_secret(&s.server_key),
			))),
			None => None,
		},
		client_factory,
		Some(wallet.lock().get_client()),
		node.lock().to_client(),
		RouteStore::new(format!("{}/db", data_dir).as_str()).unwrap(),
	)
	.unwrap();

	IntegrationMixServer {
		server_key: server_key.clone(),
		onion_pubkey: server_config.onion_pubkey(),
		tor_instance,
		rpc_server,
		_wallet: wallet,
	}
}

pub struct Servers {
	pub swapper: IntegrationSwapServer<PreferredRuntime>,

	pub mixers: Vec<IntegrationMixServer<PreferredRuntime>>,
}

impl Servers {
	pub async fn async_setup(
		test_dir: &str,
		rt_handle: &tokio::runtime::Handle,
		wallets: &mut GrinWalletManager,
		node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
		num_mixers: usize,
	) -> Servers {
		// Pre-generate all server keys
		let server_keys: Vec<SecretKey> =
			iter::repeat_with(|| grin_onion::crypto::secp::random_secret(false))
				.take(num_mixers + 1)
				.collect();

		// Setup mock tor network
		let tor_runtime = PreferredRuntime::current().unwrap();

		// Build mixers in reverse order
		let mut mixers = Vec::new();
		for i in (0..num_mixers).rev() {
			let mix_server = async_new_mix_server(
				format!("{}/mixers/{}", test_dir, i).as_str(),
				rt_handle,
				tor_runtime.clone(),
				wallets,
				&server_keys[i + 1],
				&node,
				DalekPublicKey::from_secret(&server_keys[i]),
				mixers.last(),
			)
			.await;
			println!(
				"Mixer {}: identity_key={}, prev_server={}, next_server={}",
				i,
				DalekPublicKey::from_secret(&server_keys[i + 1]).to_hex(),
				DalekPublicKey::from_secret(&server_keys[i]).to_hex(),
				match mixers.last() {
					Some(s) => DalekPublicKey::from_secret(&s.server_key).to_hex(),
					None => "NONE".to_string(),
				},
			);
			mixers.push(mix_server);
		}
		mixers.reverse();

		let swapper = async_new_swap_server(
			format!("{}/swapper", test_dir).as_str(),
			rt_handle,
			tor_runtime.clone(),
			wallets,
			&server_keys[0],
			&node,
			&mixers,
		)
		.await;
		println!(
			"Swapper: identity_key={}",
			DalekPublicKey::from_secret(&server_keys[0]).to_hex()
		);

		Servers { swapper, mixers }
	}

	pub fn get_server_keys(&self) -> Vec<MwixnetServerPublicKey> {
		let mut server_keys = vec![self.swapper.onion_pubkey];
		for mixer in &self.mixers {
			server_keys.push(mixer.onion_pubkey);
		}
		server_keys
	}

	pub fn stop_all(&mut self) {
		self.swapper.rpc_server.close_handle().close();
		self.swapper
			.tor_instance
			.lock()
			.stop()
			.expect("stop swap Tor service");

		self.mixers.iter_mut().for_each(|mixer| {
			mixer.rpc_server.close_handle().close();
			mixer
				.tor_instance
				.lock()
				.stop()
				.expect("stop mixer Tor service");
		});
	}
}
