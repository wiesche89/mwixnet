use std::sync::Arc;

use futures::FutureExt;
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core::{self, BoxFuture, IoHandler, Params, Value};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use serde::{Deserialize, Serialize};

use grin_onion::crypto::dalek::{self, DalekSignature};
use grin_onion::onion::Onion;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;

use crate::config::ServerConfig;
use crate::mix_client::{MixClient, MixClientFactory};
use crate::node::GrinNode;
use crate::servers::mix::{MixError, MixServer, MixServerImpl};
use crate::servers::route::RouteService;
use crate::store::RouteStore;
use crate::tx::TxComponents;
use crate::wallet::Wallet;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyMixReq {
	pub onions: Vec<Onion>,
	#[serde(with = "dalek::dalek_sig_serde")]
	pub sig: DalekSignature,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMixReq {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	pub route_id: mwixnet_protocol::Hash,
	#[serde(with = "grin_core::libtx::secp_ser::string_or_u64")]
	pub manifest_sequence: u64,
	pub batch_id: mwixnet_protocol::Hash,
	pub onions: Vec<Onion>,
	#[serde(with = "dalek::dalek_sig_serde")]
	pub sig: DalekSignature,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum MixReq {
	Route(RouteMixReq),
	Legacy(LegacyMixReq),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposeRouteParams {
	proposal: mwixnet_protocol::RouteProposal,
	offers: Vec<mwixnet_protocol::MwixnetOffer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateRouteParams {
	manifest: mwixnet_protocol::RouteManifest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRouteParams {
	revocation: mwixnet_protocol::RouteRevocation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRouteParams {
	request: mwixnet_protocol::HealthRequest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixResp {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub version: Option<u32>,
	#[serde(rename = "type", skip_serializing_if = "Option::is_none")]
	pub msg_type: Option<mwixnet_protocol::MwixnetType>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub batch_id: Option<mwixnet_protocol::Hash>,
	pub indices: Vec<usize>,
	pub components: TxComponents,
}

impl Writeable for MixResp {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.version != Some(mwixnet_protocol::MWIXNET_PROTOCOL_VERSION)
			|| self.msg_type != Some(mwixnet_protocol::MwixnetType::MixResp)
			|| self.batch_id.is_none()
			|| self.indices.len() > mwixnet_protocol::MAX_MIX_BATCH_SIZE
			|| self.components.kernels.len() > mwixnet_protocol::MAX_ROUTE_HOPS
			|| self.components.outputs.len() > mwixnet_protocol::MAX_MIX_BATCH_SIZE
		{
			return Err(ser::Error::CountError);
		}
		writer.write_u32(self.version.unwrap())?;
		writer.write_u8(self.msg_type.unwrap() as u8)?;
		self.batch_id.unwrap().write(writer)?;
		writer.write_u16(self.indices.len() as u16)?;
		for index in &self.indices {
			let index = u16::try_from(*index).map_err(|_| ser::Error::CountError)?;
			writer.write_u16(index)?;
		}
		writer.write_fixed_bytes(self.components.offset.as_ref())?;
		writer.write_u16(self.components.kernels.len() as u16)?;
		for kernel in &self.components.kernels {
			kernel.write(writer)?;
		}
		writer.write_u16(self.components.outputs.len() as u16)?;
		for output in &self.components.outputs {
			output.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for MixResp {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u32()?;
		let msg_type = mwixnet_protocol::MwixnetType::try_from(reader.read_u8()?)?;
		if version != mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			|| msg_type != mwixnet_protocol::MwixnetType::MixResp
		{
			return Err(ser::Error::CorruptedData);
		}
		let batch_id = mwixnet_protocol::Hash::read(reader)?;
		let index_count = reader.read_u16()? as usize;
		if index_count > mwixnet_protocol::MAX_MIX_BATCH_SIZE {
			return Err(ser::Error::CountError);
		}
		let indices = (0..index_count)
			.map(|_| reader.read_u16().map(usize::from))
			.collect::<Result<Vec<_>, _>>()?;
		let offset_bytes = reader.read_fixed_bytes(32)?;
		let offset = if offset_bytes == [0; 32] {
			secp256k1zkp::key::ZERO_KEY
		} else {
			let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::None);
			secp256k1zkp::SecretKey::from_slice(&secp, &offset_bytes)
				.map_err(|_| ser::Error::CorruptedData)?
		};
		let kernel_count = reader.read_u16()? as usize;
		if kernel_count > mwixnet_protocol::MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		let kernels = (0..kernel_count)
			.map(|_| grin_core::core::TxKernel::read(reader))
			.collect::<Result<Vec<_>, _>>()?;
		let output_count = reader.read_u16()? as usize;
		if output_count > mwixnet_protocol::MAX_MIX_BATCH_SIZE {
			return Err(ser::Error::CountError);
		}
		let outputs = (0..output_count)
			.map(|_| grin_core::core::Output::read(reader))
			.collect::<Result<Vec<_>, _>>()?;
		Ok(Self {
			version: Some(version),
			msg_type: Some(msg_type),
			batch_id: Some(batch_id),
			indices,
			components: TxComponents {
				offset,
				kernels,
				outputs,
			},
		})
	}
}

impl MixReq {
	pub fn new(onions: Vec<Onion>, sig: DalekSignature) -> Self {
		Self::Legacy(LegacyMixReq { onions, sig })
	}
}

struct RouteMixReqPayload<'a> {
	route_id: &'a mwixnet_protocol::Hash,
	manifest_sequence: u64,
	batch_id: &'a mwixnet_protocol::Hash,
	onions: &'a [Onion],
}

impl Writeable for RouteMixReqPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.route_id.write(writer)?;
		writer.write_u64(self.manifest_sequence)?;
		self.batch_id.write(writer)?;
		if self.onions.is_empty() || self.onions.len() > mwixnet_protocol::MAX_MIX_BATCH_SIZE {
			return Err(ser::Error::CountError);
		}
		writer.write_u16(self.onions.len() as u16)?;
		for onion in self.onions {
			onion.write(writer)?;
		}
		Ok(())
	}
}

impl RouteMixReq {
	/// Return the hash to sign for the given route batch.
	pub fn signing_hash(
		route_id: &mwixnet_protocol::Hash,
		manifest_sequence: u64,
		batch_id: &mwixnet_protocol::Hash,
		onions: &[Onion],
	) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::MixReq,
			&RouteMixReqPayload {
				route_id,
				manifest_sequence,
				batch_id,
				onions,
			},
		)
	}

	pub fn hash(&self) -> mwixnet_protocol::Hash {
		Self::signing_hash(
			&self.route_id,
			self.manifest_sequence,
			&self.batch_id,
			&self.onions,
		)
	}
}

impl Writeable for RouteMixReq {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.version != mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			|| self.msg_type != mwixnet_protocol::MwixnetType::MixReq
		{
			return Err(ser::Error::CorruptedData);
		}
		writer.write_u32(self.version)?;
		writer.write_u8(self.msg_type as u8)?;
		RouteMixReqPayload {
			route_id: &self.route_id,
			manifest_sequence: self.manifest_sequence,
			batch_id: &self.batch_id,
			onions: &self.onions,
		}
		.write(writer)?;
		writer.write_fixed_bytes(self.sig.as_ref().to_bytes())
	}
}

impl Readable for RouteMixReq {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u32()?;
		let msg_type = mwixnet_protocol::MwixnetType::try_from(reader.read_u8()?)?;
		if version != mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			|| msg_type != mwixnet_protocol::MwixnetType::MixReq
		{
			return Err(ser::Error::CorruptedData);
		}
		let route_id = mwixnet_protocol::Hash::read(reader)?;
		let manifest_sequence = reader.read_u64()?;
		let batch_id = mwixnet_protocol::Hash::read(reader)?;
		let count = reader.read_u16()? as usize;
		if count == 0 || count > mwixnet_protocol::MAX_MIX_BATCH_SIZE {
			return Err(ser::Error::CountError);
		}
		let onions = (0..count)
			.map(|_| Onion::read(reader))
			.collect::<Result<Vec<_>, _>>()?;
		let bytes = reader.read_fixed_bytes(64)?;
		let sig = DalekSignature::from_hex(&grin_util::ToHex::to_hex(&bytes))
			.map_err(|_| ser::Error::CorruptedData)?;
		Ok(Self {
			version,
			msg_type,
			route_id,
			manifest_sequence,
			batch_id,
			onions,
			sig,
		})
	}
}

#[rpc(server)]
pub trait MixAPI {
	#[rpc(name = "health")]
	fn health(&self) -> jsonrpc_core::Result<Value>;

	#[rpc(name = "mix")]
	fn mix(&self, mix: MixReq) -> BoxFuture<jsonrpc_core::Result<MixResp>>;

	#[rpc(name = "get_mwixnet_offer", raw_params)]
	fn get_mwixnet_offer(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::MwixnetOffer>>;

	#[rpc(name = "propose_route", raw_params)]
	fn propose_route(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::RouteAcceptance>>;

	#[rpc(name = "activate_route", raw_params)]
	fn activate_route(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<Value>>;

	#[rpc(name = "revoke_route", raw_params)]
	fn revoke_route(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<Value>>;

	#[rpc(name = "probe_route", raw_params)]
	fn probe_route(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::HealthResponse>>;
}

#[derive(Clone)]
struct RPCMixServer {
	server_config: ServerConfig,
	server: Arc<tokio::sync::Mutex<dyn MixServer>>,
	routes: RouteService,
	client_factory: MixClientFactory,
}

impl RPCMixServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self, runtime_handle: tokio::runtime::Handle) -> jsonrpc_http_server::Server {
		let mut io = IoHandler::new();
		io.extend_with(RPCMixServer::to_delegate(self.clone()));

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

impl From<MixError> for jsonrpc_core::Error {
	fn from(e: MixError) -> Self {
		match e {
			MixError::Protocol(data) => jsonrpc_core::Error {
				code: jsonrpc_core::ErrorCode::ServerError(-32010),
				message: data.message.clone(),
				data: serde_json::to_value(data).ok(),
			},
			MixError::Client(crate::mix_client::MixClientError::Protocol(data)) => {
				jsonrpc_core::Error {
					code: jsonrpc_core::ErrorCode::ServerError(-32010),
					message: data.message.clone(),
					data: serde_json::to_value(data).ok(),
				}
			}
			other => jsonrpc_core::Error::invalid_params(other.to_string()),
		}
	}
}

impl MixAPI for RPCMixServer {
	fn health(&self) -> jsonrpc_core::Result<Value> {
		Ok(Value::String("ok".into()))
	}

	fn mix(&self, mix: MixReq) -> BoxFuture<jsonrpc_core::Result<MixResp>> {
		let server = self.server.clone();
		let routes = self.routes.clone();
		let client_factory = self.client_factory.clone();
		async move {
			match mix {
				MixReq::Legacy(mix) => server
					.lock()
					.await
					.mix_outputs(&mix.onions, &mix.sig)
					.await
					.map_err(Into::into),
				MixReq::Route(mix) => {
					let (predecessor, successor, completed) = routes.begin_batch(&mix).await?;
					if let Some(response) = completed {
						return Ok(response);
					}
					let predecessor = grin_onion::crypto::dalek::DalekPublicKey::from_hex(
						&grin_util::ToHex::to_hex(&predecessor.0),
					)
					.map_err(|_| MixError::InvalidSignature)?;
					let next_server = successor
						.map(|identity| client_factory(identity))
						.transpose()
						.map_err(MixError::Client)?;
					let response = match server
						.lock()
						.await
						.route_mix(&mix, &predecessor, next_server)
						.await
					{
						Ok(response) => response,
						Err(error) => {
							routes.abort_batch(&mix).await;
							return Err(error.into());
						}
					};
					routes.complete_batch(&mix, &response).await?;
					Ok(response)
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

	fn propose_route(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::RouteAcceptance>> {
		let routes = self.routes.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<ProposeRouteParams>()?;
			routes
				.propose(params.proposal, params.offers)
				.await
				.map_err(Into::into)
		}
		.boxed()
	}

	fn activate_route(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<Value>> {
		let routes = self.routes.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<ActivateRouteParams>()?;
			routes.activate(params.manifest).await?;
			Ok(Value::Null)
		}
		.boxed()
	}

	fn revoke_route(&self, params: Params) -> BoxFuture<jsonrpc_core::Result<Value>> {
		let routes = self.routes.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<RevokeRouteParams>()?;
			routes.revoke(params.revocation).await?;
			Ok(Value::Null)
		}
		.boxed()
	}

	fn probe_route(
		&self,
		params: Params,
	) -> BoxFuture<jsonrpc_core::Result<mwixnet_protocol::HealthResponse>> {
		let routes = self.routes.clone();
		let client_factory = self.client_factory.clone();
		async move {
			if !matches!(&params, Params::Map(_)) {
				return Err(jsonrpc_core::Error::invalid_params(
					"expected named parameters",
				));
			}
			let params = params.parse::<ProbeRouteParams>()?;
			let next_server = routes
				.successor(params.request.route_id, params.request.manifest_sequence)
				.await?
				.map(|identity| client_factory(identity))
				.transpose()
				.map_err(MixError::Client)?;
			routes
				.probe(params.request, next_server.as_deref())
				.await
				.map_err(Into::into)
		}
		.boxed()
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	rt_handle: &tokio::runtime::Handle,
	server_config: ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	client_factory: MixClientFactory,
	wallet: Option<Arc<dyn Wallet>>,
	node: Arc<dyn GrinNode>,
	route_store: RouteStore,
) -> Result<
	(
		Arc<tokio::sync::Mutex<dyn MixServer>>,
		jsonrpc_http_server::Server,
	),
	Box<dyn std::error::Error>,
> {
	let server = MixServerImpl::new(server_config.clone(), next_server, wallet, node.clone());
	let routes = RouteService::new(
		server_config.clone(),
		route_store,
		mwixnet_protocol::RouteRole::Mixer,
		server.get_minimum_mix_fee(),
	);
	routes.spawn_offer_publisher(rt_handle, node.clone());
	let server = Arc::new(tokio::sync::Mutex::new(server));

	let rpc_server = RPCMixServer {
		server_config: server_config.clone(),
		server: server.clone(),
		routes,
		client_factory,
	};

	let http_server = rpc_server.start_http(rt_handle.clone());

	Ok((server, http_server))
}

#[cfg(test)]
mod tests {
	use super::grin_onion::crypto::dalek;
	use super::{MixResp, RouteMixReq, RouteMixReqPayload};
	use crate::tx::TxComponents;
	use grin_core::ser::{self, ProtocolVersion};
	use grin_util::ToHex;
	use serde::Deserialize;

	#[derive(Deserialize)]
	struct MixRequestVector {
		value: RouteMixReq,
		signed_payload_binary: String,
		binary: String,
		hash: String,
		signing_identity: String,
	}

	#[derive(Deserialize)]
	struct MixResponseVector {
		value: MixResp,
		binary: String,
	}

	#[derive(Deserialize)]
	struct IndexMappingVector {
		input_indices: Vec<usize>,
		downstream_indices: Vec<usize>,
		mapped_indices: Vec<usize>,
	}

	#[derive(Deserialize)]
	struct MixVectors {
		request: MixRequestVector,
		index_mapping: IndexMappingVector,
		empty_response: MixResponseVector,
	}

	#[test]
	fn empty_route_response_roundtrip() {
		let response = MixResp {
			version: Some(mwixnet_protocol::MWIXNET_PROTOCOL_VERSION),
			msg_type: Some(mwixnet_protocol::MwixnetType::MixResp),
			batch_id: Some(mwixnet_protocol::Hash([3; 32])),
			indices: Vec::new(),
			components: TxComponents {
				offset: secp256k1zkp::key::ZERO_KEY,
				kernels: Vec::new(),
				outputs: Vec::new(),
			},
		};
		let bytes = ser::ser_vec(&response, ProtocolVersion::local()).unwrap();
		let decoded: MixResp = ser::deserialize_default(&mut bytes.as_slice()).unwrap();
		assert_eq!(decoded.batch_id, response.batch_id);
		assert!(decoded.indices.is_empty());
		assert_eq!(decoded.components, response.components);

		let mut truncated = bytes;
		truncated.pop();
		assert!(ser::deserialize_default::<MixResp, _>(&mut truncated.as_slice()).is_err());
	}

	#[test]
	fn mix_vectors_match() {
		let vectors: MixVectors =
			serde_json::from_str(include_str!("../../tests/mix_vectors.json")).unwrap();
		let request = vectors.request.value;
		assert_eq!(
			vectors.request.signed_payload_binary,
			ser::ser_vec(
				&RouteMixReqPayload {
					route_id: &request.route_id,
					manifest_sequence: request.manifest_sequence,
					batch_id: &request.batch_id,
					onions: &request.onions,
				},
				ProtocolVersion::local(),
			)
			.unwrap()
			.to_hex()
		);
		assert_eq!(
			vectors.request.binary,
			ser::ser_vec(&request, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.request.hash, request.hash().0.to_hex());
		assert_eq!(
			request.hash(),
			RouteMixReq::signing_hash(
				&request.route_id,
				request.manifest_sequence,
				&request.batch_id,
				&request.onions,
			)
		);
		let identity = dalek::DalekPublicKey::from_hex(&vectors.request.signing_identity).unwrap();
		request
			.sig
			.verify(&identity, request.hash().as_bytes())
			.unwrap();

		let mapped = vectors
			.index_mapping
			.downstream_indices
			.iter()
			.map(|index| vectors.index_mapping.input_indices[*index])
			.collect::<Vec<_>>();
		assert_eq!(vectors.index_mapping.mapped_indices, mapped);

		let response = vectors.empty_response.value;
		assert_eq!(
			vectors.empty_response.binary,
			ser::ser_vec(&response, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert!(response.indices.is_empty());
		assert!(response.components.kernels.is_empty());
		assert!(response.components.outputs.is_empty());
	}
}
