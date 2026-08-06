use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::FutureExt;
use jsonrpc_core::{BoxFuture, Params, Value};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use rand::{seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};

use grin_core::libtx::secp_ser::string_or_u64;
use grin_core::ser::{Writeable, Writer};
use grin_onion::crypto::comsig::{comsig_serde, ComSignature};
use grin_onion::crypto::secp::Commitment;
use grin_onion::onion::Onion;
use grin_util::ToHex;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;

use crate::config::ServerConfig;
use crate::mix_client::{MixClient, MixClientFactory};
use crate::node::GrinNode;
use crate::servers::route::RouteService;
use crate::servers::swap::{SwapError, SwapServer, SwapServerImpl};
use crate::store::{RouteStore, SwapStore};
use crate::wallet::Wallet;

const MIXER_RETRY_BACKOFF: Duration = Duration::from_secs(15 * 60);

fn mixer_retry_allowed(
	retries: &HashMap<mwixnet_protocol::PublicKey, Instant>,
	identity: mwixnet_protocol::PublicKey,
	now: Instant,
) -> bool {
	retries
		.get(&identity)
		.map(|retry_at| *retry_at <= now)
		.unwrap_or(true)
}

fn dedup_mixer_candidates(candidates: &mut Vec<(mwixnet_protocol::PublicKey, u64)>) {
	candidates.sort_by(
		|(left_identity, left_sequence), (right_identity, right_sequence)| {
			left_identity
				.0
				.cmp(&right_identity.0)
				.then_with(|| right_sequence.cmp(left_sequence))
		},
	);
	candidates.dedup_by_key(|(identity, _)| identity.0);
}

fn mixer_candidate(
	offer: &mwixnet_protocol::MixerOffer,
	route_identities: &[mwixnet_protocol::PublicKey],
) -> Option<(mwixnet_protocol::PublicKey, u64)> {
	(offer.capacity > 0 && !route_identities.contains(&offer.identity_public_key))
		.then_some((offer.identity_public_key, offer.sequence))
}

fn replacement_mixer_index(configured_mixers: usize, mixer_count: usize) -> Option<usize> {
	let first_replaceable = configured_mixers.max(1);
	(mixer_count > first_replaceable).then_some(mixer_count - 1)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SwapReq {
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
	pub onion: Onion,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RouteSwapReq {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	pub wallet_request_id: mwixnet_protocol::Hash,
	pub route_id: mwixnet_protocol::Hash,
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	#[serde(with = "string_or_u64")]
	pub expires_at_height: u64,
	pub onion: Onion,
	pub onion_hash: mwixnet_protocol::Hash,
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
}

struct RouteSwapReqPayload<'a>(&'a RouteSwapReq);

impl Writeable for RouteSwapReqPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		self.0.wallet_request_id.write(writer)?;
		self.0.route_id.write(writer)?;
		writer.write_u64(self.0.manifest_sequence)?;
		writer.write_u64(self.0.expires_at_height)?;
		self.0.onion_hash.write(writer)
	}
}

impl RouteSwapReq {
	pub fn hash(&self) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::SwapReq,
			&RouteSwapReqPayload(self),
		)
	}

	pub fn validate(&self) -> bool {
		self.version == mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			&& self.msg_type == mwixnet_protocol::MwixnetType::SwapReq
			&& self.onion_hash
				== mwixnet_protocol::hash(mwixnet_protocol::MwixnetType::SwapReqOnion, &self.onion)
			&& self
				.comsig
				.verify(&self.onion.commit, &self.hash().0.to_vec())
				.is_ok()
	}
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum SwapRpcReq {
	Route(RouteSwapReq),
	Legacy(SwapReq),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapSubmissionStatus {
	Accepted,
	Batched,
	Posting,
	Posted,
	Confirmed,
	Rejected,
	Cancelled,
	Expired,
}

#[derive(Debug, Serialize)]
pub struct SwapSubmission {
	pub route_id: mwixnet_protocol::Hash,
	pub wallet_request_id: mwixnet_protocol::Hash,
	pub swap_req_hash: mwixnet_protocol::Hash,
	pub status: SwapSubmissionStatus,
	pub kernel_excess: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CancelSwapReq {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	pub route_id: mwixnet_protocol::Hash,
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	pub wallet_request_id: mwixnet_protocol::Hash,
	pub swap_req_hash: mwixnet_protocol::Hash,
	#[serde(with = "commitment_serde")]
	pub input_commitment: Commitment,
	#[serde(with = "string_or_u64")]
	pub created_at: u64,
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
}

struct CancelSwapReqPayload<'a>(&'a CancelSwapReq);

impl Writeable for CancelSwapReqPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		self.0.route_id.write(writer)?;
		writer.write_u64(self.0.manifest_sequence)?;
		self.0.wallet_request_id.write(writer)?;
		self.0.swap_req_hash.write(writer)?;
		self.0.input_commitment.write(writer)?;
		writer.write_u64(self.0.created_at)
	}
}

impl CancelSwapReq {
	pub fn hash(&self) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::CancelSwapReq,
			&CancelSwapReqPayload(self),
		)
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CancelStatus {
	Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelAck {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	pub route_id: mwixnet_protocol::Hash,
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	pub wallet_request_id: mwixnet_protocol::Hash,
	pub cancel_swap_req_hash: mwixnet_protocol::Hash,
	#[serde(with = "commitment_serde")]
	pub input_commitment: Commitment,
	pub status: CancelStatus,
	#[serde(with = "string_or_u64")]
	pub tombstone_created_at: u64,
	pub swap_identity: mwixnet_protocol::PublicKey,
	pub swap_signature: mwixnet_protocol::Signature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRouteParams {
	route_id: mwixnet_protocol::Hash,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRouteHealthParams {
	route_id: mwixnet_protocol::Hash,
	#[serde(with = "string_or_u64")]
	manifest_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelParams {
	request: CancelSwapReq,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRouteParams {
	revocation: mwixnet_protocol::RouteRevocation,
}

struct CancelAckPayload<'a>(&'a CancelAck);

impl Writeable for CancelAckPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		self.0.route_id.write(writer)?;
		writer.write_u64(self.0.manifest_sequence)?;
		self.0.wallet_request_id.write(writer)?;
		self.0.cancel_swap_req_hash.write(writer)?;
		self.0.input_commitment.write(writer)?;
		writer.write_u8(0)?;
		writer.write_u64(self.0.tombstone_created_at)?;
		self.0.swap_identity.write(writer)
	}
}

impl CancelAck {
	pub fn hash(&self) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::CancelAck,
			&CancelAckPayload(self),
		)
	}
}

mod commitment_serde {
	use super::*;
	use serde::de::Error;
	use serde::{Deserializer, Serializer};

	pub fn serialize<S>(value: &Commitment, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&value.to_hex())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Commitment, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = grin_util::from_hex(&value).map_err(D::Error::custom)?;
		if bytes.len() != 33 {
			return Err(D::Error::custom("invalid commitment length"));
		}
		Ok(Commitment::from_vec(bytes))
	}
}

#[rpc(server)]
pub trait SwapAPI {
	#[rpc(name = "health")]
	fn health(&self) -> jsonrpc_core::Result<Value>;

	#[rpc(name = "swap")]
	fn swap(&self, swap: SwapRpcReq) -> BoxFuture<jsonrpc_core::Result<Value>>;

	#[rpc(name = "get_mwixnet_offer", raw_params)]
	fn get_mwixnet_offer(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::MwixnetOffer>>;

	#[rpc(name = "get_route", raw_params)]
	fn get_route(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::RouteManifest>>;

	#[rpc(name = "get_route_health", raw_params)]
	fn get_route_health(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::RouteHealthProof>>;

	#[rpc(name = "cancel_mwixnet_request", raw_params)]
	fn cancel_mwixnet_request(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<CancelAck>>;

	#[rpc(name = "revoke_route", raw_params)]
	fn revoke_route(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<Value>>;
}

#[derive(Clone)]
struct RPCSwapServer {
	server_config: ServerConfig,
	server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
	routes: RouteService,
}

impl RPCSwapServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self, runtime_handle: tokio::runtime::Handle) -> jsonrpc_http_server::Server {
		let mut io = jsonrpc_core::IoHandler::new();
		io.extend_with(RPCSwapServer::to_delegate(self.clone()));

		ServerBuilder::new(io)
			.event_loop_executor(runtime_handle)
			.max_request_body_size(mwixnet_protocol::MWIXNET_RPC_MAX_BYTES)
			.cors(DomainsValidation::Disabled)
			.request_middleware(|request: hyper_legacy::Request<hyper_legacy::Body>| {
				if request.uri() == "/v1" {
					request.into()
				} else {
					jsonrpc_http_server::Response::bad_request("Only v1 supported").into()
				}
			})
			.start_http(&self.server_config.addr)
			.expect("Unable to start RPC server")
	}
}

impl From<SwapError> for jsonrpc_core::Error {
	fn from(e: SwapError) -> Self {
		match e {
			SwapError::Protocol(data) => jsonrpc_core::Error {
				code: jsonrpc_core::ErrorCode::ServerError(-32010),
				message: data.message.clone(),
				data: serde_json::to_value(data).ok(),
			},
			SwapError::UnknownError(_) => jsonrpc_core::Error {
				message: e.to_string(),
				code: jsonrpc_core::ErrorCode::InternalError,
				data: None,
			},
			_ => jsonrpc_core::Error::invalid_params(e.to_string()),
		}
	}
}

impl SwapAPI for RPCSwapServer {
	fn health(&self) -> jsonrpc_core::Result<Value> {
		Ok(Value::String("ok".into()))
	}

	fn swap(&self, swap: SwapRpcReq) -> BoxFuture<jsonrpc_core::Result<Value>> {
		let server = self.server.clone();
		let routes = self.routes.clone();
		async move {
			match swap {
				SwapRpcReq::Legacy(swap) => {
					server.lock().await.swap(&swap.onion, &swap.comsig).await?;
					Ok(Value::String("success".into()))
				}
				SwapRpcReq::Route(swap) => {
					if let Some(submission) = server.lock().await.route_submission(&swap).await? {
						return serde_json::to_value(submission)
							.map_err(|_| jsonrpc_core::Error::internal_error());
					}
					let expected_hops = routes
						.accepts_request(swap.route_id, swap.manifest_sequence)
						.await?;
					let submission = server.lock().await.route_swap(&swap, expected_hops).await?;
					serde_json::to_value(submission)
						.map_err(|_| jsonrpc_core::Error::internal_error())
				}
			}
		}
		.boxed()
	}

	fn get_mwixnet_offer(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::MwixnetOffer>> {
		let routes = self.routes.clone();
		async move {
			if !matches!(&params, Params::Map(values) if values.is_empty()) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected empty named parameters",
				));
			}
			routes.offer().await.map_err(Into::into)
		}
		.boxed()
	}

	fn get_route(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::RouteManifest>> {
		let routes = self.routes.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<GetRouteParams>()?;
			routes.route(params.route_id).await.map_err(Into::into)
		}
		.boxed()
	}

	fn get_route_health(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::RouteHealthProof>> {
		let routes = self.routes.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<GetRouteHealthParams>()?;
			routes
				.health(params.route_id, params.manifest_sequence)
				.await
				.map_err(Into::into)
		}
		.boxed()
	}

	fn cancel_mwixnet_request(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<CancelAck>> {
		let server = self.server.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<CancelParams>()?;
			server
				.lock()
				.await
				.cancel_route_swap(&params.request)
				.await
				.map_err(Into::into)
		}
		.boxed()
	}

	fn revoke_route(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<Value>> {
		let routes = self.routes.clone();
		let server = self.server.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<RevokeRouteParams>()?;
			let key = (
				params.revocation.route_id,
				params.revocation.manifest_sequence,
			);
			routes.revoke(params.revocation).await?;
			server
				.lock()
				.await
				.reject_route_requests(key.0, key.1)
				.await?;
			Ok(Value::Null)
		}
		.boxed()
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	rt_handle: &tokio::runtime::Handle,
	server_config: &ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	wallet: Option<Arc<dyn Wallet>>,
	node: Arc<dyn GrinNode>,
	store: SwapStore,
	route_store: RouteStore,
	route_clients: Vec<Arc<dyn MixClient>>,
	route_identities: Vec<mwixnet_protocol::PublicKey>,
	client_factory: MixClientFactory,
) -> std::result::Result<
	(
		Arc<tokio::sync::Mutex<dyn SwapServer>>,
		jsonrpc_http_server::Server,
	),
	Box<dyn std::error::Error>,
> {
	let route_client = next_server.clone();
	let server = SwapServerImpl::new(
		server_config.clone(),
		next_server,
		wallet,
		node.clone(),
		store,
	);
	let routes = RouteService::new(
		server_config.clone(),
		route_store,
		mwixnet_protocol::RouteRole::Swap,
		server.get_minimum_swap_fee(),
	);
	routes.spawn_offer_publisher(rt_handle, node.clone());
	let server: Arc<tokio::sync::Mutex<dyn SwapServer>> = Arc::new(tokio::sync::Mutex::new(server));
	if route_client.is_some() || server_config.discover_mixers {
		let route_service = routes.clone();
		let route_node = node.clone();
		let route_server = server.clone();
		let discover_mixers = server_config.discover_mixers;
		let configured_mixers = if server_config.route_mixers.is_empty() {
			usize::from(server_config.next_server.is_some())
		} else {
			server_config.route_mixers.len()
		};
		let target_mixers = usize::from(server_config.target_route_hops.saturating_sub(1))
			.min(mwixnet_protocol::MAX_ROUTE_HOPS - 1);
		rt_handle.spawn(async move {
			let mut route_client = route_client;
			let mut route_clients = route_clients;
			let mut route_identities = route_identities;
			let mut mixer_retries = HashMap::new();
			let mut active = match route_service.active_route().await {
				Ok(active) => active,
				Err(error) => {
					warn!("Unable to read active MWixnet route: {}", error);
					None
				}
			};
			let mut next_health = tokio::time::Instant::now();
			let mut next_sync = tokio::time::Instant::now();
			loop {
				match route_service.pending_relay_items().await {
					Ok(items) => {
						for item in items {
							match route_node.async_submit_mwixnet_route(item.clone()).await {
								Ok(()) => {
									if let Err(error) = route_service.relay_submitted(&item).await {
										warn!("Unable to record MWixnet relay: {}", error);
									}
								}
								Err(error) => warn!("Unable to publish MWixnet route: {}", error),
							}
						}
					}
					Err(error) => warn!("Unable to read pending MWixnet relays: {}", error),
				}
				match route_server.lock().await.route_open_requests().await {
					Ok(open_requests) => {
						if let Err(error) = route_service.update_lifecycle(&open_requests).await {
							warn!("Unable to update MWixnet route lifecycle: {}", error);
						}
					}
					Err(error) => warn!("Unable to read open MWixnet requests: {}", error),
				}
				if tokio::time::Instant::now() >= next_sync {
					let mut cursor = None;
					loop {
						match route_node
							.async_get_mwixnet_routes(
								cursor,
								mwixnet_protocol::P2P_BATCH_MAX_ROUTES as u16,
							)
							.await
						{
							Ok(page) => {
								match route_service.sync_revocations(page.items).await {
									Ok(revoked) => {
										for (route_id, sequence) in revoked {
											if let Err(error) = route_server
												.lock()
												.await
												.reject_route_requests(route_id, sequence)
												.await
											{
												warn!(
													"Unable to reject revoked MWixnet requests: {}",
													error
												);
											}
										}
									}
									Err(error) => {
										warn!(
											"Unable to apply MWixnet route revocation: {}",
											error
										);
										break;
									}
								}
								if page.next_cursor.is_none() || page.next_cursor == cursor {
									break;
								}
								cursor = page.next_cursor;
							}
							Err(error) => {
								warn!("Unable to synchronize MWixnet routes: {}", error);
								break;
							}
						}
					}
					if discover_mixers && route_clients.len() < target_mixers {
						let mut cursor = None;
						let mut available = Vec::new();
						loop {
							match route_node
								.async_get_mwixnet_offers(
									cursor,
									mwixnet_protocol::P2P_OFFER_BATCH_MAX_ITEMS as u16,
								)
								.await
							{
								Ok(page) => {
									for item in page.items {
										if let mwixnet_protocol::MwixnetOffer::Mixer(offer) =
											item.offer
										{
											if let Some(candidate) =
												mixer_candidate(&offer, &route_identities)
											{
												available.push(candidate);
											}
										}
									}
									if page.next_cursor.is_none() || page.next_cursor == cursor {
										break;
									}
									cursor = page.next_cursor;
								}
								Err(error) => {
									warn!("Unable to discover MWixnet mixers: {}", error);
									break;
								}
							}
						}
						dedup_mixer_candidates(&mut available);
						available.shuffle(&mut rand::thread_rng());
						for (identity, announced_sequence) in available {
							if route_clients.len() >= target_mixers {
								break;
							}
							if !mixer_retry_allowed(&mixer_retries, identity, Instant::now()) {
								continue;
							}
							match client_factory(identity) {
								Ok(client) => match client.get_mwixnet_offer().await {
									Ok(mwixnet_protocol::MwixnetOffer::Mixer(offer))
										if offer.identity_public_key == identity
											&& offer.sequence >= announced_sequence
											&& offer
												.validate(chrono::Utc::now().timestamp() as u64)
												.is_ok() =>
									{
										mixer_retries.remove(&identity);
										route_clients.push(client);
										route_identities.push(identity);
										info!(
										"Added discovered mixer {} to the MWixnet route candidate",
										grin_util::ToHex::to_hex(&identity.0)
									);
									}
									Ok(_) => {
										mixer_retries
											.insert(identity, Instant::now() + MIXER_RETRY_BACKOFF);
										warn!("Discovered MWixnet mixer returned an invalid offer")
									}
									Err(error) => {
										mixer_retries
											.insert(identity, Instant::now() + MIXER_RETRY_BACKOFF);
										warn!(
											"Discovered MWixnet mixer is not reachable: {}",
											error
										)
									}
								},
								Err(error) => {
									mixer_retries
										.insert(identity, Instant::now() + MIXER_RETRY_BACKOFF);
									warn!("Unable to use discovered MWixnet mixer: {}", error)
								}
							}
						}
					}
					route_client = route_clients.first().cloned();
					route_server
						.lock()
						.await
						.set_next_server(route_client.clone());
					next_sync = tokio::time::Instant::now()
						+ std::time::Duration::from_secs(rand::thread_rng().gen_range(270, 331));
				}
				if discover_mixers && route_clients.len() < target_mixers {
					tokio::time::sleep(std::time::Duration::from_secs(60)).await;
					continue;
				}
				let Some(route_client) = route_client.as_ref() else {
					tokio::time::sleep(std::time::Duration::from_secs(60)).await;
					continue;
				};
				match route_service.create_route(&route_clients).await {
					Ok(manifest) => {
						let current = (manifest.route_id, manifest.manifest_sequence);
						if active != Some(current) {
							next_health = tokio::time::Instant::now();
						}
						if tokio::time::Instant::now() >= next_health {
							match route_service
								.check_health(&manifest, route_client.as_ref())
								.await
							{
								Ok(_) => {
									info!(
										"MWixnet route {} manifest {} is active",
										grin_util::ToHex::to_hex(&manifest.route_id.0),
										manifest.manifest_sequence
									);
									if let Some(previous) =
										active.filter(|previous| *previous != current)
									{
										match route_service.drain(previous.0, previous.1).await {
											Ok(previous_manifest) => {
												if let Err(error) = route_service
													.relay_item(&previous_manifest)
													.await
												{
													warn!("Unable to drain previous MWixnet route: {}", error);
												}
											}
											Err(error) => warn!(
												"Unable to drain previous MWixnet route: {}",
												error
											),
										}
									}
									active = Some(current);
								}
								Err(error) => {
									warn!(
										"MWixnet route {} health check failed: {}",
										grin_util::ToHex::to_hex(&manifest.route_id.0),
										error
									);
									if discover_mixers
										&& matches!(
											route_service
												.route_state(
													manifest.route_id,
													manifest.manifest_sequence,
												)
												.await,
											Ok(mwixnet_protocol::RouteState::Unavailable)
										) {
										let first_replaceable = configured_mixers.max(1);
										let mut remove = Vec::new();
										for index in first_replaceable..route_clients.len() {
											let identity = route_identities[index];
											let valid = matches!(
												route_clients[index].get_mwixnet_offer().await,
												Ok(mwixnet_protocol::MwixnetOffer::Mixer(offer))
													if offer.identity_public_key == identity
														&& offer.capacity > 0
														&& offer
															.validate(chrono::Utc::now().timestamp() as u64)
															.is_ok()
											);
											if !valid {
												remove.push(index);
											}
										}
										if remove.is_empty() {
											if let Some(index) = replacement_mixer_index(
												configured_mixers,
												route_clients.len(),
											) {
												remove.push(index);
											}
										}
										for index in remove.into_iter().rev() {
											let identity = route_identities.remove(index);
											route_clients.remove(index);
											mixer_retries.insert(
												identity,
												Instant::now() + MIXER_RETRY_BACKOFF,
											);
											warn!(
												"Removed unavailable discovered mixer {} from the MWixnet route candidate",
												grin_util::ToHex::to_hex(&identity.0)
											);
											next_sync = tokio::time::Instant::now();
										}
									}
								}
							}
							match route_service.relay_item(&manifest).await {
								Ok(Some(item)) => {
									match route_node.async_submit_mwixnet_route(item.clone()).await
									{
										Ok(()) => {
											if let Err(error) =
												route_service.relay_submitted(&item).await
											{
												warn!("Unable to record MWixnet relay: {}", error);
											}
										}
										Err(error) => {
											warn!("Unable to publish MWixnet route: {}", error)
										}
									}
								}
								Ok(None) => {}
								Err(error) => {
									warn!("Unable to build MWixnet route update: {}", error)
								}
							}
							next_health = tokio::time::Instant::now()
								+ std::time::Duration::from_secs(
									rand::thread_rng().gen_range(270, 331),
								);
						}
					}
					Err(error) => warn!("Unable to create MWixnet route: {}", error),
				}
				tokio::time::sleep(std::time::Duration::from_secs(60)).await;
			}
		});
	}

	let rpc_server = RPCSwapServer {
		server_config: server_config.clone(),
		server: server.clone(),
		routes,
	};

	let http_server = rpc_server.start_http(rt_handle.clone());

	Ok((server, http_server))
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::net::TcpListener;
	use std::sync::Arc;
	use std::time::{Duration, Instant};

	use grin_core::ser::{self, ProtocolVersion};
	use grin_util::ToHex;
	use grin_wallet_libwallet::mwixnet::onion as grin_onion;
	use hyper_legacy::{Body, Client, Request, Response};
	use serde::Deserialize;
	use tokio::sync::Mutex;

	use grin_onion::create_onion;
	use grin_onion::crypto::comsig::ComSignature;
	use grin_onion::crypto::secp;

	use crate::config::ServerConfig;
	use crate::servers::route::RouteService;
	use crate::servers::swap::mock::MockSwapServer;
	use crate::servers::swap::{SwapError, SwapServer};
	use crate::servers::swap_rpc::{
		dedup_mixer_candidates, mixer_candidate, mixer_retry_allowed, replacement_mixer_index,
		CancelAck, CancelAckPayload, CancelSwapReq, CancelSwapReqPayload, RPCSwapServer,
		RouteSwapReq, RouteSwapReqPayload, SwapReq,
	};
	use crate::store::RouteStore;

	#[test]
	fn unreachable_mixer_retry_is_backed_off() {
		let identity = mwixnet_protocol::PublicKey([1; 32]);
		let start = Instant::now();
		let mut retries = HashMap::new();

		assert!(mixer_retry_allowed(&retries, identity, start));
		retries.insert(identity, start + Duration::from_secs(15 * 60));
		assert!(!mixer_retry_allowed(
			&retries,
			identity,
			start + Duration::from_secs(15 * 60 - 1)
		));
		assert!(mixer_retry_allowed(
			&retries,
			identity,
			start + Duration::from_secs(15 * 60)
		));
	}

	#[test]
	fn mixer_candidates_keep_latest_sequence() {
		let first = mwixnet_protocol::PublicKey([1; 32]);
		let second = mwixnet_protocol::PublicKey([2; 32]);
		let mut candidates = vec![(second, 1), (first, 2), (first, 3)];

		dedup_mixer_candidates(&mut candidates);

		assert_eq!(candidates, vec![(first, 3), (second, 1)]);
	}

	#[test]
	fn mixer_candidate_requires_capacity_and_new_identity() {
		let identity = mwixnet_protocol::PublicKey([1; 32]);
		let mut offer = mwixnet_protocol::MixerOffer {
			version: 1,
			msg_type: mwixnet_protocol::MwixnetType::MixerOffer,
			identity_public_key: identity,
			onion_address: mwixnet_protocol::OnionAddress([2; 32]),
			onion_public_key: mwixnet_protocol::OnionPublicKey([3; 32]),
			minimum_fee: 10,
			capacity: 1,
			valid_until: 1,
			sequence: 2,
			signature: mwixnet_protocol::Signature([0; 64]),
		};

		assert_eq!(mixer_candidate(&offer, &[]), Some((identity, 2)));
		assert_eq!(mixer_candidate(&offer, &[identity]), None);
		offer.capacity = 0;
		assert_eq!(mixer_candidate(&offer, &[]), None);
	}

	#[test]
	fn replacement_keeps_configured_mixers_and_entry() {
		assert_eq!(replacement_mixer_index(0, 1), None);
		assert_eq!(replacement_mixer_index(0, 2), Some(1));
		assert_eq!(replacement_mixer_index(1, 2), Some(1));
		assert_eq!(replacement_mixer_index(2, 2), None);
		assert_eq!(replacement_mixer_index(2, 3), Some(2));
	}

	#[derive(Deserialize)]
	struct SignedVector<T> {
		value: T,
		signed_payload_binary: String,
		hash: String,
	}

	#[derive(Deserialize)]
	struct SwapVector {
		value: RouteSwapReq,
		onion_binary: String,
		onion_hash: String,
		signed_payload_binary: String,
		hash: String,
	}

	#[derive(Deserialize)]
	struct SwapVectors {
		swap: SwapVector,
		cancel: SignedVector<CancelSwapReq>,
		ack: SignedVector<CancelAck>,
	}

	#[test]
	fn swap_vectors_match_wallet() {
		let vectors: SwapVectors =
			serde_json::from_str(include_str!("../../tests/swap_vectors.json")).unwrap();
		let swap = vectors.swap.value;
		let cancel = vectors.cancel.value;
		let ack = vectors.ack.value;
		assert_eq!(
			vectors.swap.onion_binary,
			ser::ser_vec(&swap.onion, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(
			vectors.swap.onion_hash,
			mwixnet_protocol::hash(mwixnet_protocol::MwixnetType::SwapReqOnion, &swap.onion)
				.0
				.to_hex()
		);
		assert_eq!(
			vectors.swap.signed_payload_binary,
			ser::ser_vec(&RouteSwapReqPayload(&swap), ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.swap.hash, swap.hash().0.to_hex());
		assert!(swap.validate());
		assert_eq!(
			vectors.cancel.signed_payload_binary,
			ser::ser_vec(&CancelSwapReqPayload(&cancel), ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.cancel.hash, cancel.hash().0.to_hex());
		cancel
			.comsig
			.verify(&cancel.input_commitment, &cancel.hash().0.to_vec())
			.unwrap();
		assert_eq!(
			vectors.ack.signed_payload_binary,
			ser::ser_vec(&CancelAckPayload(&ack), ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.ack.hash, ack.hash().0.to_hex());
		mwixnet_protocol::verify_signature(ack.hash(), ack.swap_identity, ack.swap_signature)
			.unwrap();
	}

	async fn body_to_string(req: Response<Body>) -> String {
		let body_bytes = hyper_legacy::body::to_bytes(req.into_body()).await.unwrap();
		String::from_utf8(body_bytes.to_vec()).unwrap()
	}

	/// Spin up a temporary web service, query the API, then cleanup and return response
	async fn async_make_request(
		server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
		req: String,
		runtime_handle: &tokio::runtime::Handle,
	) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
		grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
		let server_config = ServerConfig {
			key: secp::random_secret(false),
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			grin_node_url: "127.0.0.1:3413".parse()?,
			grin_node_foreign_api_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse()?,
			wallet_owner_secret_path: None,
			collect_fees: true,
			accept_fee_base: grin_core::global::DEFAULT_ACCEPT_FEE_BASE,
			mixer: false,
			prev_server: None,
			next_server: None,
			route_mixers: Vec::new(),
			discover_mixers: false,
			target_route_hops: 2,
		};

		let rpc_server = RPCSwapServer {
			server_config: server_config.clone(),
			server: server.clone(),
			routes: RouteService::new(
				server_config.clone(),
				RouteStore::new(&format!(
					"./target/tmp/.swap_rpc_routes_{}",
					server_config.addr.port()
				))?,
				mwixnet_protocol::RouteRole::Swap,
				0,
			),
		};

		// Start the JSON-RPC server
		let http_server = rpc_server.start_http(runtime_handle.clone());

		let uri = format!("http://{}/v1", server_config.addr);

		let request = Request::post(uri)
			.header("Content-Type", "application/json")
			.body(Body::from(req))
			.unwrap();

		let response = Client::new().request(request).await?;

		let response_str: String = body_to_string(response).await;

		// Execute one round
		server.lock().await.execute_round().await?;

		// Stop the server
		http_server.close();

		Ok(response_str)
	}

	// todo: Test all error types

	#[test]
	fn route_rpc_uses_named_params() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;
		let route_id = mwixnet_protocol::Hash([1; 32]);
		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));
		let request = format!(
			"{{\"jsonrpc\":\"2.0\",\"method\":\"get_route\",\"params\":[{}],\"id\":1}}",
			serde_json::json!(route_id)
		);
		let response = rt.block_on(async_make_request(server, request, rt.handle()))?;
		assert!(response.contains("\"code\":-32602"));

		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));
		let request = format!(
			"{{\"jsonrpc\":\"2.0\",\"method\":\"get_route\",\"params\":{{\"route_id\":{}}},\"id\":1}}",
			serde_json::json!(route_id)
		);
		let response = rt.block_on(async_make_request(server, request, rt.handle()))?;
		assert!(response.contains("\"code\":-32010"));
		Ok(())
	}

	#[test]
	fn health_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;
		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));
		let request = r#"{"jsonrpc":"2.0","method":"health","params":[],"id":1}"#;
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, request.into(), &rt_handle))?;

		assert_eq!(
			response,
			"{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}\n"
		);
		Ok(())
	}

	/// Demonstrates a successful swap response
	#[test]
	fn swap_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;
		let commitment = secp::commit(1234, &secp::random_secret(false))?;
		let onion = create_onion(&commitment, &vec![], false)?;
		let comsig = ComSignature::sign(
			1234,
			&secp::random_secret(false),
			&onion.serialize()?,
			false,
		)?;
		let swap = SwapReq {
			onion: onion.clone(),
			comsig,
		};

		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;
		let expected = "{\"jsonrpc\":\"2.0\",\"result\":\"success\",\"id\":\"1\"}\n";
		assert_eq!(response, expected);

		Ok(())
	}

	#[test]
	fn swap_bad_request() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;
		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));

		let params = "{ \"param\": \"Not a valid Swap request\" }";
		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			params
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;
		let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: data did not match any variant of untagged enum SwapRpcReq.\"},\"id\":\"1\"}\n";
		assert_eq!(response, expected);
		Ok(())
	}

	#[test]
	fn swap_rejects_legacy_request_with_route_fields(
	) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;
		let commitment = secp::commit(1234, &secp::random_secret(false))?;
		let onion = create_onion(&commitment, &vec![], false)?;
		let comsig = ComSignature::sign(
			1234,
			&secp::random_secret(false),
			&onion.serialize()?,
			false,
		)?;
		let mut swap = serde_json::to_value(SwapReq { onion, comsig })?;
		swap.as_object_mut()
			.expect("swap request is an object")
			.insert("route_id".into(), serde_json::json!(vec![0; 32]));

		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));
		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			swap
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;

		assert!(response.contains("\"code\":-32602"));
		Ok(())
	}

	/// Returns "Commitment not found" when there's no matching output in the UTXO set.
	#[test]
	fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;

		let commitment = secp::commit(1234, &secp::random_secret(false))?;
		let onion = create_onion(&commitment, &vec![], false)?;
		let comsig = ComSignature::sign(
			1234,
			&secp::random_secret(false),
			&onion.serialize()?,
			false,
		)?;
		let swap = SwapReq {
			onion: onion.clone(),
			comsig,
		};

		let mut server = MockSwapServer::new();
		server.set_response(
			&onion,
			SwapError::CoinNotFound {
				commit: commitment.clone(),
			},
		);
		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(server));

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;
		let expected = format!(
            "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32602,\"message\":\"Output {:?} does not exist, or is already spent.\"}},\"id\":\"1\"}}\n",
            commitment
        );
		assert_eq!(response, expected);
		Ok(())
	}
}
