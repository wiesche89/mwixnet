#[macro_use]
extern crate clap;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration;

use clap::App;
use grin_core::global;
use grin_core::global::ChainTypes;
use grin_util::{from_hex, StopState, ToHex, ZeroingString};
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use rpassword;
use tor_rtcompat::PreferredRuntime;

use grin_onion::crypto;
use grin_onion::crypto::dalek::DalekPublicKey;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use mwixnet::config::{self, ServerConfig};
use mwixnet::mix_client::{MixClient, MixClientError, MixClientFactory, MixClientImpl};
use mwixnet::node::GrinNode;
use mwixnet::node::HttpGrinNode;
use mwixnet::servers;
use mwixnet::store::StoreError;
use mwixnet::store::{RouteStore, SwapStore};
use mwixnet::tor;
use mwixnet::wallet::{HttpWallet, Wallet};

const DEFAULT_INTERVAL: u32 = 12 * 60 * 60;

struct StderrLogger;

impl log::Log for StderrLogger {
	fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
		metadata.level() <= log::max_level()
			&& (metadata.target().starts_with("mwixnet")
				|| metadata.target().starts_with("arti_client")
				|| metadata.target().starts_with("tor_"))
	}

	fn log(&self, record: &log::Record<'_>) {
		if self.enabled(record.metadata()) {
			eprintln!("{} {} - {}", record.level(), record.target(), record.args());
		}
	}

	fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

fn init_logging() {
	if log::set_logger(&LOGGER).is_ok() {
		let level = std::env::var("MWIXNET_LOG")
			.ok()
			.and_then(|level| level.parse().ok())
			.unwrap_or(log::LevelFilter::Info);
		log::set_max_level(level);
	}
}

fn interval_elapsed(elapsed: &mut u32, interval: u32) -> bool {
	*elapsed = elapsed.saturating_add(1);
	if *elapsed >= interval {
		*elapsed = 0;
		true
	} else {
		false
	}
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	real_main()
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
	init_logging();

	let yml = load_yaml!("mwixnet.yml");
	let args = App::from_yaml(yml).get_matches();
	let server_pass_file = args.value_of("server_pass_file");
	let chain_type = if args.is_present("testnet") {
		ChainTypes::Testnet
	} else {
		ChainTypes::Mainnet
	};
	global::init_global_chain_type(chain_type);

	let config_path = match args.value_of("config_file") {
		Some(path) => PathBuf::from(path),
		None => {
			let mut grin_path = config::get_grin_path(&chain_type);
			grin_path.push("mwixnet-config.toml");
			grin_path
		}
	};

	let round_time = args
		.value_of("round_time")
		.map(|t| t.parse::<u32>().unwrap());
	let bind_addr = args.value_of("bind_addr");
	let grin_node_url = args.value_of("grin_node_url");
	let grin_node_foreign_api_secret_path = args.value_of("grin_node_foreign_api_secret_path");
	let wallet_owner_url = args.value_of("wallet_owner_url");
	let wallet_owner_secret_path = args.value_of("wallet_owner_secret_path");
	let no_fee_collection = args.is_present("no_fee_collection");
	let prev_server = args
		.value_of("prev_server")
		.map(|p| DalekPublicKey::from_hex(&p).unwrap());
	let next_server = args
		.value_of("next_server")
		.map(|p| DalekPublicKey::from_hex(&p).unwrap());

	// Write a new config file if init-config command is supplied
	if let ("init-config", Some(_)) = args.subcommand() {
		if config_path.exists() {
			panic!(
				"Config file already exists at {}",
				config_path.to_string_lossy()
			);
		}

		let server_config = ServerConfig {
			key: crypto::secp::random_secret(false),
			interval_s: round_time.unwrap_or(DEFAULT_INTERVAL),
			addr: bind_addr.unwrap_or("127.0.0.1:3000").parse()?,
			grin_node_url: match grin_node_url {
				Some(u) => u.parse()?,
				None => config::grin_node_url(&chain_type),
			},
			grin_node_foreign_api_secret_path: match grin_node_foreign_api_secret_path {
				Some(p) => Some(p.to_owned()),
				None => config::node_foreign_api_secret_path(&chain_type)
					.to_str()
					.map(|p| p.to_owned()),
			},
			wallet_owner_url: match wallet_owner_url {
				Some(u) => u.parse()?,
				None => config::wallet_owner_url(&chain_type),
			},
			wallet_owner_secret_path: match wallet_owner_secret_path {
				Some(p) => Some(p.to_owned()),
				None => config::wallet_owner_secret_path(&chain_type)
					.to_str()
					.map(|p| p.to_owned()),
			},
			collect_fees: !no_fee_collection,
			accept_fee_base: grin_core::global::DEFAULT_ACCEPT_FEE_BASE,
			mixer: prev_server.is_some(),
			prev_server,
			next_server,
			route_mixers: Vec::new(),
			discover_mixers: false,
			target_route_hops: 2,
		};

		let password = server_password(server_pass_file, true)?;
		config::write_config(&config_path, &server_config, &password)?;
		println!(
			"Config file written to {:?}. Please back this file up in a safe place.",
			config_path
		);
		return Ok(());
	}

	let password = server_password(server_pass_file, false)?;
	let mut server_config = config::load_config(&config_path, &password)?;
	if no_fee_collection {
		server_config.collect_fees = false;
	}

	// Write a new config file if init-config command is supplied
	if let ("pubkey", Some(_)) = args.subcommand() {
		if !config_path.exists() {
			panic!(
				"No public address configured (Config file not found). {}",
				config_path.to_string_lossy()
			);
		}
		let sub_args = args.subcommand_matches("pubkey").unwrap();
		let server_pubkey = server_config.server_pubkey();
		if sub_args.is_present("output_file") {
			//output server pubkey to file
			let output_file = sub_args.value_of("output_file").unwrap();
			std::fs::write(output_file, format!("{}", server_pubkey.to_hex()))?;
			println!("Server pubkey written to file: {}", output_file);
		} else {
			println!("{}", server_pubkey.to_hex());
		}
		return Ok(());
	}

	if let ("onion-pubkey", Some(_)) = args.subcommand() {
		if !config_path.exists() {
			panic!(
				"No public address configured (Config file not found). {}",
				config_path.to_string_lossy()
			);
		}
		let sub_args = args.subcommand_matches("onion-pubkey").unwrap();
		let onion_pubkey = server_config.onion_pubkey();
		if sub_args.is_present("output_file") {
			let output_file = sub_args.value_of("output_file").unwrap();
			std::fs::write(output_file, onion_pubkey.to_hex())?;
			println!("Onion pubkey written to file: {}", output_file);
		} else {
			println!("{}", onion_pubkey.to_hex());
		}
		return Ok(());
	}

	// Override grin_node_url, if supplied
	if let Some(grin_node_url) = grin_node_url {
		server_config.grin_node_url = grin_node_url.parse()?;
	}

	// Override grin_node_foreign_api_secret_path, if supplied
	if let Some(path) = grin_node_foreign_api_secret_path {
		server_config.grin_node_foreign_api_secret_path = Some(path.to_owned());
	}

	// Override wallet_owner_url, if supplied
	if let Some(wallet_owner_url) = wallet_owner_url {
		server_config.wallet_owner_url = wallet_owner_url.parse()?;
	}

	// Override wallet_owner_secret_path, if supplied
	if let Some(wallet_owner_secret_path) = wallet_owner_secret_path {
		server_config.wallet_owner_secret_path = Some(wallet_owner_secret_path.to_owned());
	}

	// Override bind_addr, if supplied
	if let Some(bind_addr) = bind_addr {
		server_config.addr = bind_addr.parse()?;
	}

	// Override prev_server, if supplied
	if let Some(prev_server) = prev_server {
		server_config.prev_server = Some(prev_server);
	}

	// Override next_server, if supplied
	if let Some(next_server) = next_server {
		server_config.next_server = Some(next_server);
	}

	// Create GrinNode
	let node = HttpGrinNode::new(
		&server_config.grin_node_url,
		&server_config.node_foreign_api_secret(),
	);

	// Node API health check
	let rt = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()?;

	let rt_handle = rt.handle().clone();

	if let Err(e) = rt_handle.block_on(node.async_get_chain_tip()) {
		eprintln!("Node communication failure. Is node listening?");
		return Err(e.into());
	};

	let db_root = config_path
		.parent()
		.ok_or(StoreError::OpenError(grin_store::lmdb::Error::FileErr(
			"db_root path error".to_string(),
		)))?
		.join("db")
		.to_str()
		.ok_or(StoreError::OpenError(grin_store::lmdb::Error::FileErr(
			"db_root path error".to_string(),
		)))?
		.to_owned();
	let route_store = RouteStore::new(&db_root)?;

	if let ("revoke-route", Some(sub_args)) = args.subcommand() {
		let bytes = from_hex(sub_args.value_of("route_id").unwrap())?;
		let route_id = mwixnet_protocol::Hash(
			bytes
				.as_slice()
				.try_into()
				.map_err(|_| "route_id must contain 32 bytes")?,
		);
		let manifest_sequence = sub_args
			.value_of("manifest_sequence")
			.unwrap()
			.parse::<u64>()?;
		let role = if server_config.mixer || server_config.prev_server.is_some() {
			mwixnet_protocol::RouteRole::Mixer
		} else {
			mwixnet_protocol::RouteRole::Swap
		};
		let routes = servers::route::RouteService::new(server_config, route_store, role, 0);
		let revocation =
			rt_handle.block_on(routes.create_revocation(route_id, manifest_sequence))?;
		let item = mwixnet_protocol::RouteRelayItem::Revocation(revocation);
		rt_handle.block_on(node.async_submit_mwixnet_route(item.clone()))?;
		rt_handle.block_on(routes.relay_submitted(&item))?;
		println!(
			"MWixnet route {} manifest {} revoked",
			route_id.0.to_hex(),
			manifest_sequence
		);
		return Ok(());
	}

	// Open wallet when collecting excess hop fees.
	let wallet: Option<Arc<dyn Wallet>> = if server_config.collect_fees {
		let wallet_pass = prompt_wallet_password(&args.value_of("wallet_pass"));
		let wallet = rt_handle.block_on(HttpWallet::async_open_wallet(
			&server_config.wallet_owner_url,
			&server_config.wallet_owner_api_secret(),
			&wallet_pass,
		));
		match wallet {
			Ok(w) => Some(Arc::new(w)),
			Err(e) => {
				eprintln!("Wallet communication failure. Is wallet listening?");
				return Err(e.into());
			}
		}
	} else {
		println!("Fee collection disabled; hop fees will be paid to miners.");
		None
	};

	let tor_runtime = rt_handle.block_on(async { PreferredRuntime::current() })?;
	tor_log_ratelim::install_runtime(tor_runtime.clone())?;

	let data_dir = config_path
		.parent()
		.ok_or("Invalid MWixnet data directory")?
		.to_str()
		.ok_or("Invalid MWixnet data directory")?
		.to_owned();
	let tor_instance = rt_handle.block_on(tor::async_init_tor(
		tor_runtime.clone(),
		&data_dir,
		&server_config,
	))?;
	let tor_instance = Arc::new(grin_util::Mutex::new(tor_instance));
	let tor_clone = tor_instance.clone();
	let client_factory: MixClientFactory = Arc::new({
		let config = server_config.clone();
		let tor = tor_instance.clone();
		move |identity| {
			let key =
				DalekPublicKey::from_hex(&identity.0.to_hex()).map_err(MixClientError::Dalek)?;
			Ok(Arc::new(MixClientImpl::new(
				config.clone(),
				tor.clone(),
				key,
			)))
		}
	});

	let stop_state = Arc::new(StopState::new());
	let stop_state_clone = stop_state.clone();

	rt_handle.spawn(async move {
		build_signals_fut().await;
		match tokio::task::spawn_blocking(move || tor_clone.lock().stop()).await {
			Ok(Ok(())) => {}
			Ok(Err(error)) => eprintln!("Could not stop Tor service cleanly: {error}"),
			Err(error) => eprintln!("Tor shutdown task failed: {error}"),
		}
		stop_state_clone.stop();
	});

	let route_identities = if !server_config.route_mixers.is_empty() {
		server_config
			.route_mixers
			.iter()
			.map(|identity| DalekPublicKey::from_hex(&identity.0.to_hex()))
			.collect::<Result<Vec<_>, _>>()?
	} else if let Some(next_server) = server_config.next_server.clone() {
		vec![next_server]
	} else if server_config.discover_mixers
		&& !server_config.mixer
		&& server_config.prev_server.is_none()
	{
		let mut cursor = None;
		let mut identities = Vec::new();
		loop {
			let page = rt_handle.block_on(node.async_get_mwixnet_offers(
				cursor,
				mwixnet_protocol::P2P_OFFER_BATCH_MAX_ITEMS as u16,
			))?;
			for item in page.items {
				if let mwixnet_protocol::MwixnetOffer::Mixer(offer) = item.offer {
					if offer.identity_public_key != server_config.mwixnet_identity()
						&& offer.capacity > 0
					{
						identities.push(offer.identity_public_key);
					}
				}
			}
			if page.next_cursor.is_none() || page.next_cursor == cursor {
				break;
			}
			cursor = page.next_cursor;
		}
		identities.sort_by_key(|identity| identity.0);
		identities.dedup();
		identities.shuffle(&mut thread_rng());
		identities.truncate(1);
		if !identities.is_empty() {
			println!("Discovered {} MWixnet mixer(s)", identities.len());
		}
		identities
			.into_iter()
			.map(|identity| DalekPublicKey::from_hex(&identity.0.to_hex()))
			.collect::<Result<Vec<_>, _>>()?
	} else {
		Vec::new()
	};
	let route_clients = route_identities
		.iter()
		.cloned()
		.map(|pk| {
			Arc::new(MixClientImpl::new(
				server_config.clone(),
				tor_instance.clone(),
				pk,
			)) as Arc<dyn MixClient>
		})
		.collect::<Vec<_>>();
	let route_public_identities = route_identities
		.iter()
		.map(|identity| mwixnet_protocol::PublicKey(identity.as_ref().to_bytes()))
		.collect::<Vec<_>>();
	let next_identity = route_identities.first().cloned();
	let next_mixer: Option<Arc<dyn MixClient>> = next_identity.map(|pk| {
		let client: Arc<dyn MixClient> = Arc::new(MixClientImpl::new(
			server_config.clone(),
			tor_instance.clone(),
			pk.clone(),
		));
		client
	});

	if server_config.mixer || server_config.prev_server.is_some() {
		// Start the JSON-RPC HTTP 'mix' server
		println!(
			"Starting MIX server\nEd25519 identity key: {}\nX25519 onion key: {}",
			server_config.server_pubkey().to_hex(),
			server_config.onion_pubkey().to_hex()
		);

		let (_, http_server) = servers::mix_rpc::listen(
			&rt_handle,
			server_config,
			next_mixer,
			client_factory,
			wallet,
			Arc::new(node),
			route_store,
		)?;

		let close_handle = http_server.close_handle();
		let round_handle = spawn(move || loop {
			if stop_state.is_stopped() {
				close_handle.close();
				break;
			}

			sleep(Duration::from_millis(100));
		});

		http_server.wait();
		round_handle.join().unwrap();
	} else {
		println!(
			"Starting SWAP server\nEd25519 identity key: {}\nX25519 onion key: {}",
			server_config.server_pubkey().to_hex(),
			server_config.onion_pubkey().to_hex()
		);

		// Open SwapStore
		let store = SwapStore::new(&db_root)?;

		// Start the mwixnet JSON-RPC HTTP 'swap' server
		let (swap_server, http_server) = servers::swap_rpc::listen(
			rt.handle(),
			&server_config,
			next_mixer,
			wallet,
			Arc::new(node),
			store,
			route_store,
			route_clients,
			route_public_identities,
			client_factory,
		)?;

		let close_handle = http_server.close_handle();
		let round_handle = spawn(move || {
			let mut rng = thread_rng();
			let mut secs = 0u32;
			let mut reorg_secs = 0u32;
			let mut reorg_window = rng.gen_range(900u32, 3600u32);
			let prev_tx = Arc::new(Mutex::new(None));
			let server = swap_server.clone();

			loop {
				if stop_state.is_stopped() {
					close_handle.close();
					break;
				}

				sleep(Duration::from_secs(1));
				let run_round = interval_elapsed(&mut secs, server_config.interval_s);
				let check_reorg = interval_elapsed(&mut reorg_secs, reorg_window);
				if check_reorg {
					reorg_window = rng.gen_range(900u32, 3600u32);
				}

				if run_round || check_reorg {
					let prev_tx_clone = prev_tx.clone();
					let server_clone = server.clone();
					rt.spawn(async move {
						if check_reorg {
							let tx = prev_tx_clone.lock().unwrap().clone();
							if let Some(tx) = tx {
								let result = server_clone.lock().await.check_reorg(&tx).await;
								let mut prev_tx = prev_tx_clone.lock().unwrap();
								*prev_tx = match result {
									Ok(Some(tx)) => Some(tx),
									_ => None,
								};
							}
						}

						if run_round {
							match server_clone.lock().await.execute_round().await {
								Ok(Some(tx)) => {
									*prev_tx_clone.lock().unwrap() = Some(tx);
								}
								Ok(None) => {}
								Err(e) => eprintln!("Swap round failed: {}", e),
							}
						}
					});
				}
			}
		});

		http_server.wait();
		round_handle.join().unwrap();
	}

	Ok(())
}

#[cfg(unix)]
async fn build_signals_fut() {
	use tokio::signal::unix::{signal, SignalKind};

	// Listen for SIGINT, SIGQUIT, and SIGTERM
	let mut terminate_signal =
		signal(SignalKind::terminate()).expect("failed to create terminate signal");
	let mut quit_signal = signal(SignalKind::quit()).expect("failed to create quit signal");
	let mut interrupt_signal =
		signal(SignalKind::interrupt()).expect("failed to create interrupt signal");

	futures::future::select_all(vec![
		Box::pin(terminate_signal.recv()),
		Box::pin(quit_signal.recv()),
		Box::pin(interrupt_signal.recv()),
	])
	.await;
}

#[cfg(not(unix))]
async fn build_signals_fut() {
	tokio::signal::ctrl_c()
		.await
		.expect("failed to install CTRL+C signal handler");
}

fn prompt_password() -> ZeroingString {
	ZeroingString::from(rpassword::prompt_password_stdout("Server password: ").unwrap())
}

fn prompt_password_confirm() -> ZeroingString {
	let mut first = "first".to_string();
	let mut second = "second".to_string();
	while first != second {
		first = rpassword::prompt_password_stdout("Server password: ").unwrap();
		second = rpassword::prompt_password_stdout("Confirm server password: ").unwrap();
	}
	ZeroingString::from(first)
}

fn prompt_wallet_password(wallet_pass: &Option<&str>) -> ZeroingString {
	match *wallet_pass {
		Some(wallet_pass) => ZeroingString::from(wallet_pass),
		None => {
			ZeroingString::from(rpassword::prompt_password_stdout("Wallet password: ").unwrap())
		}
	}
}

fn server_password(
	password_file: Option<&str>,
	confirm: bool,
) -> Result<ZeroingString, std::io::Error> {
	if let Some(path) = password_file {
		let mut password = std::fs::read_to_string(path)?;
		while password.ends_with('\n') || password.ends_with('\r') {
			password.pop();
		}
		return Ok(ZeroingString::from(password));
	}

	Ok(if confirm {
		prompt_password_confirm()
	} else {
		prompt_password()
	})
}

#[cfg(test)]
mod tests {
	use super::{global, interval_elapsed, server_password, ChainTypes};

	#[test]
	fn independent_intervals() {
		let mut round_elapsed = 0;
		let mut reorg_elapsed = 0;
		let mut rounds = 0;
		let mut reorg_checks = 0;

		for _ in 0..10 {
			rounds += interval_elapsed(&mut round_elapsed, 2) as u32;
			reorg_checks += interval_elapsed(&mut reorg_elapsed, 5) as u32;
		}

		assert_eq!(rounds, 5);
		assert_eq!(reorg_checks, 2);
	}

	#[test]
	fn chain_type_is_available_to_worker_threads() {
		global::init_global_chain_type(ChainTypes::Testnet);
		let worker_chain_type = std::thread::spawn(global::get_chain_type).join().unwrap();
		assert_eq!(worker_chain_type, ChainTypes::Testnet);
	}

	#[test]
	fn reads_server_password_file() {
		let path =
			std::env::temp_dir().join(format!("mwixnet-server-password-{}", std::process::id()));
		std::fs::write(&path, "test\r\n").unwrap();

		let password = server_password(path.to_str(), false).unwrap();
		std::fs::remove_file(path).unwrap();

		assert_eq!(&*password, "test");
	}
}
