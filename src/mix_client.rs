use std::sync::Arc;

use async_trait::async_trait;
use grin_api::json_rpc::{build_request, Response};
use grin_core::ser;
use grin_core::ser::ProtocolVersion;
use grin_wallet_util::OnionV3Address;
use serde_json;
use serde_json::json;
use thiserror::Error;
use tor_rtcompat::Runtime;

use grin_onion::crypto::dalek::{self, DalekPublicKey};
use grin_onion::onion::Onion;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;

use crate::config::ServerConfig;
use crate::servers::mix_rpc::{MixReq, MixResp, RouteMixReq};
use crate::tor::TorService;
use crate::{http, tor};

pub type MixClientFactory = Arc<
	dyn Fn(mwixnet_protocol::PublicKey) -> Result<Arc<dyn MixClient>, MixClientError> + Send + Sync,
>;

/// Error types for interacting with nodes
#[derive(Error, Debug)]
pub enum MixClientError {
	#[error("Tor Error: {0:?}")]
	Tor(tor::TorError),
	#[error("Communication Error: {0:?}")]
	CommError(http::HttpError),
	#[error("Dalek Error: {0:?}")]
	Dalek(dalek::DalekError),
	#[error("Error decoding JSON response: {0:?}")]
	DecodeResponseError(serde_json::Error),
	#[error("Error in JSON-RPC response: {0:?}")]
	ResponseError(grin_api::json_rpc::RpcError),
	#[error("MWixnet protocol error: {0}")]
	Protocol(mwixnet_protocol::ProtocolRpcError),
	#[error("Custom client error: {0:?}")]
	Custom(String),
}

/// A client for consuming a mix API
#[async_trait]
pub trait MixClient: Send + Sync {
	/// Swaps the outputs provided and returns the final swapped outputs and kernels.
	async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError>;

	async fn mix_route(
		&self,
		_route_id: mwixnet_protocol::Hash,
		_manifest_sequence: u64,
		_batch_id: mwixnet_protocol::Hash,
		_onions: &Vec<Onion>,
	) -> Result<MixResp, MixClientError> {
		Err(MixClientError::Custom(
			"route batches are not supported".into(),
		))
	}

	async fn get_mwixnet_offer(&self) -> Result<mwixnet_protocol::MwixnetOffer, MixClientError> {
		Err(MixClientError::Custom(
			"route discovery is not supported".into(),
		))
	}

	async fn propose_route(
		&self,
		_proposal: mwixnet_protocol::RouteProposal,
		_offers: Vec<mwixnet_protocol::MwixnetOffer>,
	) -> Result<mwixnet_protocol::RouteAcceptance, MixClientError> {
		Err(MixClientError::Custom(
			"route discovery is not supported".into(),
		))
	}

	async fn activate_route(
		&self,
		_manifest: mwixnet_protocol::RouteManifest,
	) -> Result<(), MixClientError> {
		Err(MixClientError::Custom(
			"route discovery is not supported".into(),
		))
	}

	async fn probe_route(
		&self,
		_request: mwixnet_protocol::HealthRequest,
	) -> Result<mwixnet_protocol::HealthResponse, MixClientError> {
		Err(MixClientError::Custom(
			"route health is not supported".into(),
		))
	}

	async fn revoke_route(
		&self,
		_revocation: mwixnet_protocol::RouteRevocation,
	) -> Result<(), MixClientError> {
		Err(MixClientError::Custom(
			"route discovery is not supported".into(),
		))
	}
}

pub struct MixClientImpl<R: Runtime> {
	config: ServerConfig,
	tor: Arc<grin_util::Mutex<TorService<R>>>,
	addr: OnionV3Address,
}

impl<R: Runtime> MixClientImpl<R> {
	pub fn new(
		config: ServerConfig,
		tor: Arc<grin_util::Mutex<TorService<R>>>,
		next_pubkey: DalekPublicKey,
	) -> Self {
		let addr = OnionV3Address::from_bytes(next_pubkey.as_ref().to_bytes());
		MixClientImpl { config, tor, addr }
	}

	async fn async_send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		addr: &OnionV3Address,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, MixClientError> {
		let url = format!("{}/v1", addr.to_http_str());
		let request_str = serde_json::to_string(&build_request(method, params)).unwrap();
		let tor_client = self
			.tor
			.lock()
			.client()
			.ok_or_else(|| MixClientError::Custom("Tor client is not running".into()))?;
		let res = tor::async_post(tor_client, &url, request_str)
			.await
			.map_err(MixClientError::Tor)?;

		let response: Response =
			serde_json::from_str(&res).map_err(MixClientError::DecodeResponseError)?;

		if let Some(ref e) = response.error {
			if let Some(data) = &e.data {
				if let Ok(error) = serde_json::from_value(data.clone()) {
					return Err(MixClientError::Protocol(error));
				}
			}
			return Err(MixClientError::ResponseError(e.clone()));
		}

		let result = match response.result.clone() {
			Some(r) => serde_json::from_value(r).map_err(MixClientError::DecodeResponseError),
			None => serde_json::from_value(serde_json::Value::Null)
				.map_err(MixClientError::DecodeResponseError),
		}?;

		Ok(result)
	}
}

#[async_trait]
impl<R: Runtime> MixClient for MixClientImpl<R> {
	async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
		let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
		let sig =
			dalek::sign(&self.config.key, serialized.as_slice()).map_err(MixClientError::Dalek)?;
		let mix = MixReq::new(onions.clone(), sig);

		self.async_send_json_request::<MixResp>(&self.addr, "mix", &json!([mix]))
			.await
	}

	async fn mix_route(
		&self,
		route_id: mwixnet_protocol::Hash,
		manifest_sequence: u64,
		batch_id: mwixnet_protocol::Hash,
		onions: &Vec<Onion>,
	) -> Result<MixResp, MixClientError> {
		let request_hash =
			RouteMixReq::signing_hash(&route_id, manifest_sequence, &batch_id, onions);
		let request = RouteMixReq {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::MixReq,
			route_id,
			manifest_sequence,
			batch_id,
			onions: onions.clone(),
			sig: dalek::sign(&self.config.key, request_hash.as_bytes())
				.map_err(MixClientError::Dalek)?,
		};
		self.async_send_json_request::<MixResp>(&self.addr, "mix", &json!([MixReq::Route(request)]))
			.await
	}

	async fn get_mwixnet_offer(&self) -> Result<mwixnet_protocol::MwixnetOffer, MixClientError> {
		self.async_send_json_request(&self.addr, "get_mwixnet_offer", &json!({}))
			.await
	}

	async fn propose_route(
		&self,
		proposal: mwixnet_protocol::RouteProposal,
		offers: Vec<mwixnet_protocol::MwixnetOffer>,
	) -> Result<mwixnet_protocol::RouteAcceptance, MixClientError> {
		self.async_send_json_request(
			&self.addr,
			"propose_route",
			&json!({ "proposal": proposal, "offers": offers }),
		)
		.await
	}

	async fn activate_route(
		&self,
		manifest: mwixnet_protocol::RouteManifest,
	) -> Result<(), MixClientError> {
		self.async_send_json_request(
			&self.addr,
			"activate_route",
			&json!({ "manifest": manifest }),
		)
		.await
	}

	async fn probe_route(
		&self,
		request: mwixnet_protocol::HealthRequest,
	) -> Result<mwixnet_protocol::HealthResponse, MixClientError> {
		self.async_send_json_request(&self.addr, "probe_route", &json!({ "request": request }))
			.await
	}

	async fn revoke_route(
		&self,
		revocation: mwixnet_protocol::RouteRevocation,
	) -> Result<(), MixClientError> {
		self.async_send_json_request(
			&self.addr,
			"revoke_route",
			&json!({ "revocation": revocation }),
		)
		.await
	}
}

#[cfg(test)]
pub mod mock {
	use super::grin_onion;
	use std::collections::HashMap;

	use async_trait::async_trait;

	use grin_onion::onion::Onion;

	use crate::servers::mix_rpc::MixResp;

	use super::{MixClient, MixClientError};

	pub struct MockMixClient {
		results: HashMap<Vec<Onion>, MixResp>,
	}

	impl MockMixClient {
		pub fn new() -> MockMixClient {
			MockMixClient {
				results: HashMap::new(),
			}
		}

		pub fn set_response(&mut self, onions: &Vec<Onion>, r: MixResp) {
			self.results.insert(onions.clone(), r);
		}
	}

	#[async_trait]
	impl MixClient for MockMixClient {
		async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			self.results
				.get(onions)
				.map(|r| Ok(r.clone()))
				.unwrap_or(Err(MixClientError::Custom(
					"No response set for input".into(),
				)))
		}
	}
}

#[cfg(test)]
pub mod test_util {
	use super::grin_onion;
	use std::sync::Arc;

	use async_trait::async_trait;
	use grin_core::ser;
	use grin_core::ser::ProtocolVersion;

	use grin_onion::crypto::dalek::{self, DalekPublicKey};
	use grin_onion::crypto::secp::SecretKey;
	use grin_onion::onion::Onion;

	use crate::servers::mix::MixServer;
	use crate::servers::mix_rpc::MixResp;

	use super::{MixClient, MixClientError};

	/// Implementation of the 'MixClient' trait that calls a mix server implementation directly.
	/// No JSON-RPC serialization or socket communication occurs.
	#[derive(Clone)]
	pub struct DirectMixClient {
		pub key: SecretKey,
		pub mix_server: Arc<dyn MixServer>,
	}

	#[async_trait]
	impl MixClient for DirectMixClient {
		async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
			let sig =
				dalek::sign(&self.key, serialized.as_slice()).map_err(MixClientError::Dalek)?;

			sig.verify(
				&DalekPublicKey::from_secret(&self.key),
				serialized.as_slice(),
			)
			.unwrap();
			Ok(self.mix_server.mix_outputs(&onions, &sig).await.unwrap())
		}
	}
}
