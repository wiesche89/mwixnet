// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Route discovery service.

use chrono::Utc;
use grin_core::ser::{self, ProtocolVersion};
use mwixnet_protocol::{
	Hash, HealthAttestation, HealthLayer, HealthRequest, HealthResponse, MixerOffer, MwixnetOffer,
	MwixnetType, ProtocolErrorCode, ProtocolRpcError, RouteAcceptance, RouteHealthCertificate,
	RouteHealthProof, RouteManifest, RouteProposal, RouteRevocation, RouteRole, RouteState,
	SwapOffer, MAX_HEALTH_CERTIFICATE_AGE, MAX_HEALTH_CHALLENGE_LIFETIME, MAX_MANIFEST_VALIDITY,
	MAX_MIX_BATCH_SIZE, MAX_REQUEST_TTL_BLOCKS, MWIXNET_PROTOCOL_VERSION,
	UNAVAILABLE_AFTER_FAILURES,
};
use rand::{thread_rng, Rng};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

use crate::config::ServerConfig;
use crate::mix_client::{MixClient, MixClientError};
use crate::node::GrinNode;
use crate::servers::mix_rpc::{MixResp, RouteMixReq};
use crate::store::{
	BatchBinding, HealthBinding, ProposalBinding, RouteRecord, RouteStore, StoreError,
};

const OFFER_VALIDITY: u64 = 24 * 60 * 60;
const ROUTE_RENEWAL_WINDOW: u64 = 60 * 60;
const HEALTH_REQUESTS_PER_MINUTE: usize = 16;
const PROPOSALS_PER_MINUTE: usize = 16;
const MIXER_ROUTE_LIMIT: usize = 32;

fn route_matches_swap_policy(offer: &SwapOffer, fee_per_hop: u64, hop_count: u8) -> bool {
	offer
		.maximum_fee_per_hop
		.map(|maximum| fee_per_hop <= maximum)
		.unwrap_or(true)
		&& offer
			.desired_min_hops
			.map(|minimum| hop_count >= minimum)
			.unwrap_or(true)
		&& offer
			.desired_max_hops
			.map(|maximum| hop_count <= maximum)
			.unwrap_or(true)
}

/// Route discovery error.
#[derive(Debug, Error)]
pub enum RouteError {
	#[error("{0}")]
	Protocol(ProtocolRpcError),
	#[error("route store error: {0}")]
	Store(#[from] StoreError),
	#[error("route client error: {0}")]
	Client(#[from] MixClientError),
}

impl RouteError {
	fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
		Self::Protocol(ProtocolRpcError::new(code, message))
	}
}

impl From<RouteError> for jsonrpc_core::Error {
	fn from(error: RouteError) -> Self {
		match error {
			RouteError::Protocol(data) => jsonrpc_core::Error {
				code: jsonrpc_core::ErrorCode::ServerError(-32010),
				message: data.message.clone(),
				data: serde_json::to_value(data).ok(),
			},
			RouteError::Store(error) => jsonrpc_core::Error {
				code: jsonrpc_core::ErrorCode::InternalError,
				message: error.to_string(),
				data: None,
			},
			RouteError::Client(error) => jsonrpc_core::Error {
				code: jsonrpc_core::ErrorCode::InternalError,
				message: error.to_string(),
				data: None,
			},
		}
	}
}

/// Coordinates offers, manifests and route health.
#[derive(Clone)]
pub struct RouteService {
	config: ServerConfig,
	store: Arc<tokio::sync::Mutex<RouteStore>>,
	role: RouteRole,
	minimum_fee: u64,
	proposal_lock: Arc<tokio::sync::Mutex<()>>,
	active_health: Arc<tokio::sync::Mutex<HashSet<(Hash, u64, Hash)>>>,
	active_batches: Arc<tokio::sync::Mutex<HashSet<(Hash, Hash)>>>,
	health_rate: Arc<tokio::sync::Mutex<(i64, usize)>>,
	proposal_rate: Arc<tokio::sync::Mutex<(i64, usize)>>,
}

impl RouteService {
	pub fn new(config: ServerConfig, store: RouteStore, role: RouteRole, minimum_fee: u64) -> Self {
		Self {
			config,
			store: Arc::new(tokio::sync::Mutex::new(store)),
			role,
			minimum_fee,
			proposal_lock: Arc::new(tokio::sync::Mutex::new(())),
			active_health: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
			active_batches: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
			health_rate: Arc::new(tokio::sync::Mutex::new((Utc::now().timestamp() / 60, 0))),
			proposal_rate: Arc::new(tokio::sync::Mutex::new((Utc::now().timestamp() / 60, 0))),
		}
	}

	pub async fn offer(&self) -> Result<MwixnetOffer, RouteError> {
		let now = Utc::now().timestamp() as u64;
		let store = self.store.lock().await;
		let previous = store.offer()?;
		if let Some(offer) = &previous {
			if offer.valid_until() > now + OFFER_VALIDITY / 2 && self.offer_matches_config(offer) {
				return Ok(offer.clone());
			}
		}
		let sequence = previous
			.as_ref()
			.map(offer_sequence)
			.unwrap_or(0)
			.checked_add(1)
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::OfferStale, "offer sequence exhausted")
			})?;
		let valid_until = now + OFFER_VALIDITY.min(MAX_MANIFEST_VALIDITY);
		let offer = match self.role {
			RouteRole::Mixer => {
				let mut offer = MixerOffer {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::MixerOffer,
					identity_public_key: self.config.mwixnet_identity(),
					onion_address: self.config.mwixnet_onion_address(),
					onion_public_key: self.config.mwixnet_onion_pubkey(),
					minimum_fee: self.minimum_fee,
					capacity: MAX_MIX_BATCH_SIZE as u32,
					valid_until,
					sequence,
					signature: mwixnet_protocol::Signature([0; 64]),
				};
				offer.signature = self.config.sign_mwixnet_hash(offer.hash());
				MwixnetOffer::Mixer(offer)
			}
			RouteRole::Swap => {
				let mut offer = SwapOffer {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::SwapOffer,
					identity_public_key: self.config.mwixnet_identity(),
					onion_address: self.config.mwixnet_onion_address(),
					onion_public_key: self.config.mwixnet_onion_pubkey(),
					minimum_fee: self.minimum_fee,
					capacity: MAX_MIX_BATCH_SIZE as u32,
					desired_min_hops: None,
					desired_max_hops: None,
					maximum_fee_per_hop: None,
					max_request_ttl_blocks: MAX_REQUEST_TTL_BLOCKS,
					valid_until,
					sequence,
					signature: mwixnet_protocol::Signature([0; 64]),
				};
				offer.signature = self.config.sign_mwixnet_hash(offer.hash());
				MwixnetOffer::Swap(offer)
			}
		};
		store.save_offer(&offer)?;
		Ok(offer)
	}

	pub fn spawn_offer_publisher(
		&self,
		rt_handle: &tokio::runtime::Handle,
		node: Arc<dyn GrinNode>,
	) {
		let service = self.clone();
		rt_handle.spawn(async move {
			loop {
				match service.offer().await {
					Ok(offer) => {
						let item = mwixnet_protocol::OfferAnnouncement::mine(offer);
						match node.async_submit_mwixnet_offer(item).await {
							Ok(()) => info!("MWixnet offer published"),
							Err(error) => warn!("Unable to publish MWixnet offer: {}", error),
						}
					}
					Err(error) => warn!("Unable to build MWixnet offer: {}", error),
				}
				tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
			}
		});
	}

	fn offer_matches_config(&self, offer: &MwixnetOffer) -> bool {
		match (self.role, offer) {
			(RouteRole::Mixer, MwixnetOffer::Mixer(offer)) => {
				offer.identity_public_key == self.config.mwixnet_identity()
					&& offer.onion_address == self.config.mwixnet_onion_address()
					&& offer.onion_public_key == self.config.mwixnet_onion_pubkey()
					&& offer.minimum_fee == self.minimum_fee
					&& offer.capacity == MAX_MIX_BATCH_SIZE as u32
			}
			(RouteRole::Swap, MwixnetOffer::Swap(offer)) => {
				offer.identity_public_key == self.config.mwixnet_identity()
					&& offer.onion_address == self.config.mwixnet_onion_address()
					&& offer.onion_public_key == self.config.mwixnet_onion_pubkey()
					&& offer.minimum_fee == self.minimum_fee
					&& offer.capacity == MAX_MIX_BATCH_SIZE as u32
					&& offer.desired_min_hops.is_none()
					&& offer.desired_max_hops.is_none()
					&& offer.maximum_fee_per_hop.is_none()
					&& offer.max_request_ttl_blocks == MAX_REQUEST_TTL_BLOCKS
			}
			_ => false,
		}
	}

	pub async fn propose(
		&self,
		proposal: RouteProposal,
		offers: Vec<MwixnetOffer>,
	) -> Result<RouteAcceptance, RouteError> {
		let _guard = self.proposal_lock.lock().await;
		let now = Utc::now().timestamp() as u64;
		let minute = Utc::now().timestamp() / 60;
		let mut rate = self.proposal_rate.lock().await;
		if rate.0 != minute {
			*rate = (minute, 0);
		}
		if rate.1 >= PROPOSALS_PER_MINUTE {
			return Err(RouteError::protocol(
				ProtocolErrorCode::LimitExceeded,
				"route proposal rate exceeded",
			));
		}
		rate.1 += 1;
		drop(rate);
		if self.role != RouteRole::Mixer || proposal.validate(now).is_err() {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route proposal",
			));
		}
		validate_offers(&proposal, &offers, now)?;
		if !self.store.lock().await.save_remote_offers(&offers)? {
			return Err(RouteError::protocol(
				ProtocolErrorCode::OfferStale,
				"offer sequence is stale or conflicts with stored content",
			));
		}
		let position = proposal
			.ordered_hops
			.iter()
			.position(|hop| hop.identity_public_key == self.config.mwixnet_identity())
			.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"server is not a proposal participant",
				)
			})?;
		if position == 0
			|| proposal.ordered_hops[position].role != RouteRole::Mixer
			|| proposal.ordered_hops[position].onion_address != self.config.mwixnet_onion_address()
			|| proposal.ordered_hops[position].onion_public_key
				!= self.config.mwixnet_onion_pubkey()
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"proposal does not contain the active server keys",
			));
		}
		let proposal_hash = proposal.hash();
		let store = self.store.lock().await;
		if let Some(binding) = store.proposal(proposal.route_id, proposal.manifest_sequence)? {
			return if binding.proposal_hash == proposal_hash {
				Ok(binding.acceptance)
			} else if binding
				.proposal
				.valid_until
				.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
				<= now
			{
				let accepted_until = proposal.valid_until.min(offers[position].valid_until());
				let mut acceptance = RouteAcceptance {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::RouteAcceptance,
					route_id: proposal.route_id,
					manifest_sequence: proposal.manifest_sequence,
					proposal_hash,
					participant_identity: self.config.mwixnet_identity(),
					accepted_until,
					signature: mwixnet_protocol::Signature([0; 64]),
				};
				acceptance.signature = self.config.sign_mwixnet_hash(acceptance.hash());
				store.save_proposal(
					proposal.route_id,
					proposal.manifest_sequence,
					&ProposalBinding {
						proposal_hash,
						proposal,
						acceptance: acceptance.clone(),
					},
				)?;
				Ok(acceptance)
			} else {
				Err(RouteError::protocol(
					ProtocolErrorCode::ProposalConflict,
					"different proposal already accepted",
				))
			};
		}
		let expected_sequence = match store.latest_route(proposal.route_id)? {
			Some(route) => route
				.manifest
				.manifest_sequence
				.checked_add(1)
				.ok_or_else(|| {
					RouteError::protocol(
						ProtocolErrorCode::ManifestExpired,
						"manifest sequence exhausted",
					)
				})?,
			None => 1,
		};
		if proposal.manifest_sequence != expected_sequence {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"proposal is not the next manifest sequence",
			));
		}
		let route_count = store
			.routes()?
			.into_iter()
			.filter(|route| {
				matches!(
					route.state,
					RouteState::Proposed
						| RouteState::Healthy
						| RouteState::Degraded
						| RouteState::Unavailable
						| RouteState::Draining
				)
			})
			.count();
		if route_count >= MIXER_ROUTE_LIMIT {
			return Err(RouteError::protocol(
				ProtocolErrorCode::LimitExceeded,
				"mixer route limit reached",
			));
		}
		let accepted_until = proposal.valid_until.min(offers[position].valid_until());
		let mut acceptance = RouteAcceptance {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::RouteAcceptance,
			route_id: proposal.route_id,
			manifest_sequence: proposal.manifest_sequence,
			proposal_hash,
			participant_identity: self.config.mwixnet_identity(),
			accepted_until,
			signature: mwixnet_protocol::Signature([0; 64]),
		};
		acceptance.signature = self.config.sign_mwixnet_hash(acceptance.hash());
		store.save_proposal(
			proposal.route_id,
			proposal.manifest_sequence,
			&ProposalBinding {
				proposal_hash,
				proposal,
				acceptance: acceptance.clone(),
			},
		)?;
		Ok(acceptance)
	}

	pub async fn create_route(
		&self,
		clients: &[Arc<dyn MixClient>],
	) -> Result<RouteManifest, RouteError> {
		if self.role != RouteRole::Swap {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"only a swap server can create routes",
			));
		}
		if clients.is_empty() || clients.len() + 1 > mwixnet_protocol::MAX_ROUTE_HOPS {
			return Err(RouteError::protocol(
				ProtocolErrorCode::LimitExceeded,
				"route mixer count is outside the protocol limits",
			));
		}
		let swap_offer = self.offer().await?;
		let swap_offer_data = match &swap_offer {
			MwixnetOffer::Swap(swap) => swap,
			MwixnetOffer::Mixer(_) => {
				return Err(RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"route proposer did not return a swap offer",
				))
			}
		};
		let mut offers = Vec::with_capacity(clients.len() + 1);
		offers.push(swap_offer.clone());
		for client in clients {
			let offer = client.get_mwixnet_offer().await?;
			if !matches!(offer, MwixnetOffer::Mixer(_)) {
				return Err(RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"route participant did not return a mixer offer",
				));
			}
			offers.push(offer);
		}
		let fee_per_hop = offers.iter().map(MwixnetOffer::minimum_fee).max().unwrap();
		let hop_count = offers.len() as u8;
		if !route_matches_swap_policy(swap_offer_data, fee_per_hop, hop_count) {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"offers cannot form the configured route",
			));
		}
		let ordered_hops = offers.iter().map(offer_hop).collect::<Vec<_>>();
		let route_id = mwixnet_protocol::route_id(fee_per_hop, &ordered_hops).map_err(|_| {
			RouteError::protocol(ProtocolErrorCode::InvalidMwixnetMessage, "invalid route")
		})?;
		let now = Utc::now().timestamp() as u64;
		let (latest, pending) = {
			let store = self.store.lock().await;
			let latest = store.latest_route(route_id)?;
			let next_sequence = latest
				.as_ref()
				.map(|route| route.manifest.manifest_sequence)
				.unwrap_or(0)
				.checked_add(1)
				.ok_or_else(|| {
					RouteError::protocol(
						ProtocolErrorCode::ManifestExpired,
						"manifest sequence exhausted",
					)
				})?;
			let pending = store.proposal(route_id, next_sequence)?;
			(latest, pending)
		};
		if let Some(route) = latest {
			if route.manifest.valid_until > now.saturating_add(ROUTE_RENEWAL_WINDOW)
				&& !matches!(
					route.state,
					RouteState::Draining | RouteState::Expired | RouteState::Revoked
				) {
				for client in clients {
					client.activate_route(route.manifest.clone()).await?;
				}
				return Ok(route.manifest);
			}
		}
		let (proposal, swap_acceptance) = match pending {
			Some(binding)
				if binding
					.proposal
					.valid_until
					.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
					> now =>
			{
				(binding.proposal, binding.acceptance)
			}
			pending => {
				let manifest_sequence = if let Some(binding) = pending {
					binding.proposal.manifest_sequence
				} else {
					self.store
						.lock()
						.await
						.latest_route(route_id)?
						.map(|route| route.manifest.manifest_sequence + 1)
						.unwrap_or(1)
				};
				let valid_until = offers.iter().map(MwixnetOffer::valid_until).min().unwrap();
				let mut proposal = RouteProposal {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::RouteProposal,
					route_id,
					manifest_sequence,
					valid_from: now,
					valid_until,
					fee_per_hop,
					ordered_hops,
					proposer_signature: mwixnet_protocol::Signature([0; 64]),
				};
				proposal.proposer_signature = self.config.sign_mwixnet_hash(proposal.hash());
				let mut acceptance = RouteAcceptance {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::RouteAcceptance,
					route_id,
					manifest_sequence,
					proposal_hash: proposal.hash(),
					participant_identity: self.config.mwixnet_identity(),
					accepted_until: valid_until,
					signature: mwixnet_protocol::Signature([0; 64]),
				};
				acceptance.signature = self.config.sign_mwixnet_hash(acceptance.hash());
				self.store.lock().await.save_proposal(
					route_id,
					manifest_sequence,
					&ProposalBinding {
						proposal_hash: proposal.hash(),
						proposal: proposal.clone(),
						acceptance: acceptance.clone(),
					},
				)?;
				(proposal, acceptance)
			}
		};
		let mut acceptances = Vec::with_capacity(clients.len() + 1);
		validate_offers(&proposal, &offers, now)?;
		if !self.store.lock().await.save_remote_offers(&offers)? {
			return Err(RouteError::protocol(
				ProtocolErrorCode::OfferStale,
				"offer sequence is stale or conflicts with stored content",
			));
		}
		acceptances.push(swap_acceptance);
		for (position, client) in clients.iter().enumerate() {
			let acceptance = client
				.propose_route(proposal.clone(), offers.clone())
				.await?;
			if acceptance.participant_identity
				!= proposal.ordered_hops[position + 1].identity_public_key
				|| acceptance.proposal_hash != proposal.hash()
			{
				return Err(RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"mixer returned an invalid route acceptance",
				));
			}
			acceptances.push(acceptance);
		}
		let mut manifest = RouteManifest {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::RouteManifest,
			route_id,
			manifest_sequence: proposal.manifest_sequence,
			proposal_hash: proposal.hash(),
			valid_from: proposal.valid_from,
			valid_until: proposal.valid_until,
			fee_per_hop,
			ordered_hops: proposal.ordered_hops,
			proposer_signature: proposal.proposer_signature,
			acceptances,
			swap_identity: self.config.mwixnet_identity(),
			signature: mwixnet_protocol::Signature([0; 64]),
		};
		manifest.signature = self.config.sign_mwixnet_hash(manifest.hash());
		manifest.validate(now).map_err(|_| {
			RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route manifest",
			)
		})?;
		for client in clients {
			client.activate_route(manifest.clone()).await?;
		}
		self.store.lock().await.save_route(&RouteRecord {
			manifest: manifest.clone(),
			state: RouteState::Proposed,
			failures: 0,
			health_proof: None,
			relay_sequence: 0,
			pending_relay: Vec::new(),
			revocations: Vec::new(),
			drain_until_height: None,
		})?;
		Ok(manifest)
	}

	pub async fn activate(&self, manifest: RouteManifest) -> Result<(), RouteError> {
		let now = Utc::now().timestamp() as u64;
		if manifest.validate(now).is_err() {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route manifest",
			));
		}
		let store = self.store.lock().await;
		if let Some(existing) = store.route(manifest.route_id, manifest.manifest_sequence)? {
			return if existing.manifest == manifest {
				if matches!(
					existing.state,
					RouteState::Draining | RouteState::Expired | RouteState::Revoked
				) {
					Err(RouteError::protocol(
						ProtocolErrorCode::RouteNotAcceptingRequests,
						"route is no longer accepting activation",
					))
				} else {
					Ok(())
				}
			} else {
				Err(RouteError::protocol(
					ProtocolErrorCode::ManifestConflict,
					"different manifest already activated",
				))
			};
		}
		let binding = store
			.proposal(manifest.route_id, manifest.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "proposal was not accepted")
			})?;
		if binding.proposal_hash != manifest.proposal_hash
			|| !manifest.acceptances.contains(&binding.acceptance)
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::ManifestConflict,
				"manifest does not contain the stored acceptance",
			));
		}
		let route_count = store
			.routes()?
			.into_iter()
			.filter(|route| {
				matches!(
					route.state,
					RouteState::Proposed
						| RouteState::Healthy
						| RouteState::Degraded
						| RouteState::Unavailable
						| RouteState::Draining
				)
			})
			.count();
		if route_count >= MIXER_ROUTE_LIMIT {
			return Err(RouteError::protocol(
				ProtocolErrorCode::LimitExceeded,
				"mixer route limit reached",
			));
		}
		store.save_route(&RouteRecord {
			manifest,
			state: RouteState::Proposed,
			failures: 0,
			health_proof: None,
			relay_sequence: 0,
			pending_relay: Vec::new(),
			revocations: Vec::new(),
			drain_until_height: None,
		})?;
		Ok(())
	}

	pub async fn probe(
		&self,
		request: HealthRequest,
		next_client: Option<&dyn MixClient>,
	) -> Result<HealthResponse, RouteError> {
		if ser::ser_vec(&request, ProtocolVersion::local())
			.map(|bytes| bytes.len() > mwixnet_protocol::HEALTH_REQUEST_MAX_BYTES)
			.unwrap_or(true)
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::LimitExceeded,
				"health request exceeds the size limit",
			));
		}
		let route = self
			.store
			.lock()
			.await
			.route(request.route_id, request.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if matches!(
			route.state,
			RouteState::Draining | RouteState::Expired | RouteState::Revoked
		) {
			return Err(RouteError::protocol(
				ProtocolErrorCode::RouteNotAcceptingRequests,
				"route is not active",
			));
		}
		let position = route
			.manifest
			.ordered_hops
			.iter()
			.position(|hop| hop.identity_public_key == self.config.mwixnet_identity())
			.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"server is not a route participant",
				)
			})?;
		if position == 0 || request.hop_position as usize != position {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid health hop position",
			));
		}
		let predecessor = route.manifest.ordered_hops[position - 1].identity_public_key;
		request.validate(predecessor).map_err(|_| {
			RouteError::protocol(
				ProtocolErrorCode::UnauthorizedPredecessor,
				"health request is not signed by the predecessor",
			)
		})?;
		{
			let minute = Utc::now().timestamp() / 60;
			let mut rate = self.health_rate.lock().await;
			if rate.0 != minute {
				*rate = (minute, 0);
			}
			if rate.1 >= HEALTH_REQUESTS_PER_MINUTE {
				return Err(RouteError::protocol(
					ProtocolErrorCode::ServerBusy,
					"health request rate exceeded",
				));
			}
			rate.1 += 1;
		}
		mwixnet_protocol::verify_signature(
			request.challenge_hash,
			route.manifest.swap_identity,
			request.challenge_signature,
		)
		.map_err(|_| {
			RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid health challenge signature",
			)
		})?;
		let cache_key = (
			request.route_id,
			request.manifest_sequence,
			request.challenge_hash,
		);
		if let Some(binding) =
			self.store
				.lock()
				.await
				.health(cache_key.0, cache_key.1, cache_key.2)?
		{
			if binding.request_hash != request.hash() {
				return Err(RouteError::protocol(
					ProtocolErrorCode::HealthChallengeReplayed,
					"challenge was already used by a different request",
				));
			}
			if let Some(response) = binding.response {
				return Ok(response);
			}
		}
		if !self.active_health.lock().await.insert(cache_key) {
			return Err(RouteError::protocol(
				ProtocolErrorCode::ServerBusy,
				"health request is already being processed",
			));
		}
		let result = async {
			self.store.lock().await.save_health(
				cache_key.0,
				cache_key.1,
				cache_key.2,
				&HealthBinding {
					stored_at: Utc::now().timestamp() as u64,
					request_hash: request.hash(),
					request: request.clone(),
					challenge: None,
					hop_nonces: Vec::new(),
					response: None,
				},
			)?;
			let response = self
				.probe_inner(&route.manifest, position, &request, next_client)
				.await?;
			let store = self.store.lock().await;
			let mut active_route = store
				.route(request.route_id, request.manifest_sequence)?
				.ok_or_else(|| {
					RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
				})?;
			if matches!(
				active_route.state,
				RouteState::Proposed
					| RouteState::Healthy
					| RouteState::Degraded
					| RouteState::Unavailable
			) {
				store.save_health(
					cache_key.0,
					cache_key.1,
					cache_key.2,
					&HealthBinding {
						stored_at: Utc::now().timestamp() as u64,
						request_hash: request.hash(),
						request: request.clone(),
						challenge: None,
						hop_nonces: Vec::new(),
						response: Some(response.clone()),
					},
				)?;
				active_route.state = RouteState::Healthy;
				active_route.failures = 0;
				store.save_route(&active_route)?;
			}
			Ok(response)
		}
		.await;
		self.active_health.lock().await.remove(&cache_key);
		result
	}

	pub async fn check_health(
		&self,
		manifest: &RouteManifest,
		client: &dyn MixClient,
	) -> Result<RouteHealthProof, RouteError> {
		let now = Utc::now().timestamp() as u64;
		let expired_challenge = self
			.store
			.lock()
			.await
			.pending_health(manifest.route_id, manifest.manifest_sequence)?
			.and_then(|binding| binding.challenge)
			.map(|challenge| {
				challenge
					.expires_at
					.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
					<= now
			})
			.unwrap_or(false);
		let mut attempts = 0;
		let result = loop {
			attempts += 1;
			let result = self.check_health_inner(manifest, client).await;
			if !matches!(&result, Err(RouteError::Client(_))) || attempts == 3 {
				break result;
			}
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
		};
		if matches!(&result, Err(error) if !matches!(error, RouteError::Client(_)) || expired_challenge)
		{
			let store = self.store.lock().await;
			if let Some(mut route) = store.route(manifest.route_id, manifest.manifest_sequence)? {
				if matches!(
					route.state,
					RouteState::Proposed
						| RouteState::Healthy
						| RouteState::Degraded
						| RouteState::Unavailable
				) {
					route.failures = route.failures.saturating_add(1);
					route.state = if route.failures >= UNAVAILABLE_AFTER_FAILURES {
						RouteState::Unavailable
					} else {
						RouteState::Degraded
					};
					store.save_route(&route)?;
				}
			}
		}
		result
	}

	async fn check_health_inner(
		&self,
		manifest: &RouteManifest,
		client: &dyn MixClient,
	) -> Result<RouteHealthProof, RouteError> {
		if self.role != RouteRole::Swap || manifest.ordered_hops.len() < 2 {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"only a swap server can check an active route",
			));
		}
		let now = Utc::now().timestamp() as u64;
		if manifest.valid_until <= now {
			return Err(RouteError::protocol(
				ProtocolErrorCode::ManifestExpired,
				"route manifest expired",
			));
		}
		let pending = self
			.store
			.lock()
			.await
			.pending_health(manifest.route_id, manifest.manifest_sequence)?
			.filter(|binding| {
				binding
					.challenge
					.as_ref()
					.map(|challenge| {
						challenge
							.expires_at
							.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
							> now
					})
					.unwrap_or(false)
			});
		let (challenge, hop_nonces, request) = if let Some(binding) = pending {
			(
				binding.challenge.unwrap(),
				binding.hop_nonces,
				binding.request,
			)
		} else {
			let mut challenge = mwixnet_protocol::HealthChallenge {
				version: MWIXNET_PROTOCOL_VERSION,
				msg_type: MwixnetType::HealthChallenge,
				route_id: manifest.route_id,
				manifest_sequence: manifest.manifest_sequence,
				nonce: Hash(thread_rng().gen()),
				created_at: now,
				expires_at: now + MAX_HEALTH_CHALLENGE_LIFETIME,
				signature: mwixnet_protocol::Signature([0; 64]),
			};
			challenge.signature = self.config.sign_mwixnet_hash(challenge.hash());
			let challenge_hash = challenge.hash();
			let hop_nonces = (1..manifest.ordered_hops.len())
				.map(|_| Hash(thread_rng().gen()))
				.collect::<Vec<_>>();
			let mut next_layer = None;
			for position in (1..manifest.ordered_hops.len()).rev() {
				let payload = mwixnet_protocol::HealthLayerPayload {
					hop_nonce: hop_nonces[position - 1],
					next_layer,
				};
				let layer = mwixnet_protocol::encrypt_health_layer(
					thread_rng().gen(),
					manifest.ordered_hops[position].onion_public_key,
					mwixnet_protocol::AeadNonce(thread_rng().gen()),
					manifest.route_id,
					manifest.manifest_sequence,
					challenge_hash,
					position as u8,
					&payload,
				)
				.map_err(|_| {
					RouteError::protocol(
						ProtocolErrorCode::HealthLayerAuthenticationFailed,
						"unable to encrypt health layer",
					)
				})?;
				next_layer =
					Some(ser::ser_vec(&layer, ProtocolVersion::local()).map_err(|_| {
						RouteError::protocol(
							ProtocolErrorCode::InvalidMwixnetMessage,
							"unable to serialize health layer",
						)
					})?);
			}
			let first_layer: HealthLayer = ser::deserialize_default(
				&mut next_layer
					.ok_or_else(|| {
						RouteError::protocol(
							ProtocolErrorCode::InvalidMwixnetMessage,
							"route has no mixer health layer",
						)
					})?
					.as_slice(),
			)
			.map_err(|_| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"unable to decode health layer",
				)
			})?;
			let mut request = HealthRequest {
				version: MWIXNET_PROTOCOL_VERSION,
				msg_type: MwixnetType::HealthRequest,
				route_id: manifest.route_id,
				manifest_sequence: manifest.manifest_sequence,
				challenge_hash,
				challenge_signature: challenge.signature,
				hop_position: 1,
				layer: first_layer,
				sender_identity: self.config.mwixnet_identity(),
				sender_signature: mwixnet_protocol::Signature([0; 64]),
			};
			request.sender_signature = self.config.sign_mwixnet_hash(request.hash());
			self.store.lock().await.save_health(
				manifest.route_id,
				manifest.manifest_sequence,
				challenge_hash,
				&HealthBinding {
					stored_at: Utc::now().timestamp() as u64,
					request_hash: request.hash(),
					request: request.clone(),
					challenge: Some(challenge.clone()),
					hop_nonces: hop_nonces.clone(),
					response: None,
				},
			)?;
			(challenge, hop_nonces, request)
		};
		let challenge_hash = challenge.hash();
		let response = client.probe_route(request.clone()).await?;
		response
			.validate(manifest, &challenge, &hop_nonces)
			.map_err(|_| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"invalid route health response",
				)
			})?;
		let verified_at = Utc::now().timestamp() as u64;
		if verified_at
			> challenge
				.expires_at
				.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::RouteUnhealthy,
				"route health response arrived after the challenge expired",
			));
		}
		let binding = HealthBinding {
			stored_at: verified_at,
			request_hash: request.hash(),
			request,
			challenge: Some(challenge.clone()),
			hop_nonces: hop_nonces.clone(),
			response: Some(response.clone()),
		};
		let mut certificate = RouteHealthCertificate {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::RouteHealthCertificate,
			route_id: manifest.route_id,
			manifest_sequence: manifest.manifest_sequence,
			challenge_hash,
			attestation_root: response.attestations[0].hash(),
			verified_at,
			expires_at: verified_at
				.saturating_add(MAX_HEALTH_CERTIFICATE_AGE)
				.min(manifest.valid_until),
			swap_identity: self.config.mwixnet_identity(),
			signature: mwixnet_protocol::Signature([0; 64]),
		};
		certificate.signature = self.config.sign_mwixnet_hash(certificate.hash());
		let proof = RouteHealthProof {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::RouteHealthProof,
			challenge,
			hop_nonces,
			response,
			certificate,
		};
		proof.validate(manifest, verified_at).map_err(|_| {
			RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route health proof",
			)
		})?;
		let store = self.store.lock().await;
		let mut route = store
			.route(manifest.route_id, manifest.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if matches!(
			route.state,
			RouteState::Proposed
				| RouteState::Healthy
				| RouteState::Degraded
				| RouteState::Unavailable
		) {
			store.save_health(
				manifest.route_id,
				manifest.manifest_sequence,
				challenge_hash,
				&binding,
			)?;
			route.state = RouteState::Healthy;
			route.failures = 0;
			route.health_proof = Some(proof.clone());
			store.save_route(&route)?;
		}
		Ok(proof)
	}

	async fn probe_inner(
		&self,
		manifest: &RouteManifest,
		position: usize,
		request: &HealthRequest,
		next_client: Option<&dyn MixClient>,
	) -> Result<HealthResponse, RouteError> {
		let payload = mwixnet_protocol::decrypt_health_layer(
			self.config.key.0,
			request.route_id,
			request.manifest_sequence,
			request.challenge_hash,
			request.hop_position,
			&request.layer,
		)
		.map_err(|_| {
			RouteError::protocol(
				ProtocolErrorCode::HealthLayerAuthenticationFailed,
				"health layer authentication failed",
			)
		})?;
		let mut attestations = if position + 1 < manifest.ordered_hops.len() {
			let next_layer = payload.next_layer.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"health onion terminated before the last mixer",
				)
			})?;
			let layer: HealthLayer =
				ser::deserialize_default(&mut next_layer.as_slice()).map_err(|_| {
					RouteError::protocol(
						ProtocolErrorCode::InvalidMwixnetMessage,
						"invalid nested health layer",
					)
				})?;
			let mut forwarded = HealthRequest {
				version: MWIXNET_PROTOCOL_VERSION,
				msg_type: MwixnetType::HealthRequest,
				route_id: request.route_id,
				manifest_sequence: request.manifest_sequence,
				challenge_hash: request.challenge_hash,
				challenge_signature: request.challenge_signature,
				hop_position: request.hop_position + 1,
				layer,
				sender_identity: self.config.mwixnet_identity(),
				sender_signature: mwixnet_protocol::Signature([0; 64]),
			};
			forwarded.sender_signature = self.config.sign_mwixnet_hash(forwarded.hash());
			let response = next_client
				.ok_or_else(|| {
					RouteError::protocol(
						ProtocolErrorCode::RouteUnknown,
						"next mixer is not configured",
					)
				})?
				.probe_route(forwarded)
				.await?;
			validate_health_tail(&response, manifest, position + 1, request.challenge_hash)?;
			response.attestations
		} else {
			if payload.next_layer.is_some() {
				return Err(RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"terminal health layer contains a successor",
				));
			}
			Vec::new()
		};
		let mut attestation = HealthAttestation {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::HealthAttestation,
			route_id: request.route_id,
			manifest_sequence: request.manifest_sequence,
			challenge_hash: request.challenge_hash,
			hop_nonce_hash: mwixnet_protocol::health_hop_nonce_hash(payload.hop_nonce),
			hop_position: request.hop_position,
			participant_identity: self.config.mwixnet_identity(),
			observed_at: Utc::now().timestamp() as u64,
			next_attestation_hash: attestations.first().map(HealthAttestation::hash),
			signature: mwixnet_protocol::Signature([0; 64]),
		};
		attestation.signature = self.config.sign_mwixnet_hash(attestation.hash());
		attestations.insert(0, attestation);
		Ok(HealthResponse {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::HealthResponse,
			route_id: request.route_id,
			manifest_sequence: request.manifest_sequence,
			challenge_hash: request.challenge_hash,
			attestations,
		})
	}

	pub async fn route(&self, route_id: Hash) -> Result<RouteManifest, RouteError> {
		self.store
			.lock()
			.await
			.latest_route(route_id)?
			.map(|record| record.manifest)
			.ok_or_else(|| RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found"))
	}

	pub async fn route_state(
		&self,
		route_id: Hash,
		manifest_sequence: u64,
	) -> Result<RouteState, RouteError> {
		self.store
			.lock()
			.await
			.route(route_id, manifest_sequence)?
			.map(|route| route.state)
			.ok_or_else(|| RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found"))
	}

	pub async fn active_route(&self) -> Result<Option<(Hash, u64)>, RouteError> {
		Ok(self
			.store
			.lock()
			.await
			.routes()?
			.into_iter()
			.filter(|route| matches!(route.state, RouteState::Healthy | RouteState::Degraded))
			.max_by_key(|route| {
				route
					.health_proof
					.as_ref()
					.map(|proof| proof.certificate.verified_at)
					.unwrap_or(0)
			})
			.map(|route| (route.manifest.route_id, route.manifest.manifest_sequence)))
	}

	pub async fn health(
		&self,
		route_id: Hash,
		sequence: u64,
	) -> Result<mwixnet_protocol::RouteHealthProof, RouteError> {
		self.store
			.lock()
			.await
			.route(route_id, sequence)?
			.and_then(|record| record.health_proof)
			.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::RouteUnhealthy,
					"route has no health proof",
				)
			})
	}

	pub async fn successor(
		&self,
		route_id: Hash,
		manifest_sequence: u64,
	) -> Result<Option<mwixnet_protocol::PublicKey>, RouteError> {
		let route = self
			.store
			.lock()
			.await
			.route(route_id, manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		let position = route
			.manifest
			.ordered_hops
			.iter()
			.position(|hop| hop.identity_public_key == self.config.mwixnet_identity())
			.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"server is not a route participant",
				)
			})?;
		Ok(route
			.manifest
			.ordered_hops
			.get(position + 1)
			.map(|hop| hop.identity_public_key))
	}

	pub async fn accepts_request(
		&self,
		route_id: Hash,
		manifest_sequence: u64,
	) -> Result<usize, RouteError> {
		let now = Utc::now().timestamp() as u64;
		let route = self
			.store
			.lock()
			.await
			.route(route_id, manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if route.manifest.valid_until <= now {
			return Err(RouteError::protocol(
				ProtocolErrorCode::ManifestExpired,
				"route manifest expired",
			));
		}
		if !matches!(route.state, RouteState::Healthy | RouteState::Degraded) {
			return Err(RouteError::protocol(
				ProtocolErrorCode::RouteNotAcceptingRequests,
				"route is not accepting requests",
			));
		}
		if route
			.health_proof
			.as_ref()
			.map(|proof| proof.certificate.expires_at <= now)
			.unwrap_or(true)
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::RouteUnhealthy,
				"route health proof expired",
			));
		}
		Ok(route.manifest.ordered_hops.len())
	}

	pub async fn update_lifecycle(
		&self,
		open_requests: &HashMap<(Hash, u64), u64>,
	) -> Result<(), RouteError> {
		let now = Utc::now().timestamp() as u64;
		let store = self.store.lock().await;
		for mut route in store.routes()? {
			let key = (route.manifest.route_id, route.manifest.manifest_sequence);
			let open_until = open_requests.get(&key).copied();
			if route.manifest.valid_until <= now
				&& matches!(
					route.state,
					RouteState::Proposed
						| RouteState::Healthy
						| RouteState::Degraded
						| RouteState::Unavailable
				) {
				route.state = if open_until.is_some() {
					RouteState::Draining
				} else {
					RouteState::Expired
				};
				route.drain_until_height = open_until;
				store.save_route(&route)?;
			} else if route.state == RouteState::Draining && open_until.is_none() {
				route.state = RouteState::Expired;
				route.drain_until_height = None;
				store.save_route(&route)?;
			}
		}
		Ok(())
	}

	pub async fn drain(
		&self,
		route_id: Hash,
		manifest_sequence: u64,
	) -> Result<RouteManifest, RouteError> {
		let store = self.store.lock().await;
		let mut route = store.route(route_id, manifest_sequence)?.ok_or_else(|| {
			RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
		})?;
		if matches!(
			route.state,
			RouteState::Healthy | RouteState::Degraded | RouteState::Unavailable
		) {
			route.state = RouteState::Draining;
			store.save_route(&route)?;
		}
		Ok(route.manifest)
	}

	pub async fn begin_batch(
		&self,
		request: &RouteMixReq,
	) -> Result<
		(
			mwixnet_protocol::PublicKey,
			Option<mwixnet_protocol::PublicKey>,
			Option<MixResp>,
		),
		RouteError,
	> {
		if request.version != MWIXNET_PROTOCOL_VERSION
			|| request.msg_type != MwixnetType::MixReq
			|| request.onions.is_empty()
			|| request.onions.len() > MAX_MIX_BATCH_SIZE
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route mix request",
			));
		}
		let batch_key = (request.route_id, request.batch_id);
		if !self.active_batches.lock().await.insert(batch_key) {
			return Err(RouteError::protocol(
				ProtocolErrorCode::ServerBusy,
				"batch is already being processed",
			));
		}
		let result = self.begin_batch_inner(request).await;
		if result
			.as_ref()
			.map(|(_, _, response)| response.is_some())
			.unwrap_or(true)
		{
			self.active_batches.lock().await.remove(&batch_key);
		}
		result
	}

	async fn begin_batch_inner(
		&self,
		request: &RouteMixReq,
	) -> Result<
		(
			mwixnet_protocol::PublicKey,
			Option<mwixnet_protocol::PublicKey>,
			Option<MixResp>,
		),
		RouteError,
	> {
		let store = self.store.lock().await;
		if let Some(binding) = store.batch(request.route_id, request.batch_id)? {
			if binding.request_hash != request.hash() {
				return Err(RouteError::protocol(
					ProtocolErrorCode::BatchConflict,
					"batch ID is bound to a different request",
				));
			}
			let route = store
				.route(request.route_id, request.manifest_sequence)?
				.ok_or_else(|| {
					RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
				})?;
			let position = route
				.manifest
				.ordered_hops
				.iter()
				.position(|hop| hop.identity_public_key == self.config.mwixnet_identity())
				.ok_or_else(|| {
					RouteError::protocol(
						ProtocolErrorCode::InvalidMwixnetMessage,
						"server is not a route participant",
					)
				})?;
			if position == 0 {
				return Err(RouteError::protocol(
					ProtocolErrorCode::UnauthorizedPredecessor,
					"swap server cannot receive a mix batch",
				));
			}
			return Ok((
				route.manifest.ordered_hops[position - 1].identity_public_key,
				route
					.manifest
					.ordered_hops
					.get(position + 1)
					.map(|hop| hop.identity_public_key),
				binding.response,
			));
		}
		let route = store
			.route(request.route_id, request.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if !matches!(
			route.state,
			RouteState::Healthy | RouteState::Degraded | RouteState::Draining
		) || (route.state != RouteState::Draining
			&& route.manifest.valid_until <= Utc::now().timestamp() as u64)
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::RouteNotAcceptingRequests,
				"route cannot start a new batch",
			));
		}
		let position = route
			.manifest
			.ordered_hops
			.iter()
			.position(|hop| hop.identity_public_key == self.config.mwixnet_identity())
			.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"server is not a route participant",
				)
			})?;
		if position == 0 {
			return Err(RouteError::protocol(
				ProtocolErrorCode::UnauthorizedPredecessor,
				"swap server cannot receive a mix batch",
			));
		}
		store.save_batch(
			request.route_id,
			request.batch_id,
			&BatchBinding {
				request_hash: request.hash(),
				request: request.clone(),
				response: None,
			},
		)?;
		Ok((
			route.manifest.ordered_hops[position - 1].identity_public_key,
			route
				.manifest
				.ordered_hops
				.get(position + 1)
				.map(|hop| hop.identity_public_key),
			None,
		))
	}

	pub async fn complete_batch(
		&self,
		request: &RouteMixReq,
		response: &MixResp,
	) -> Result<(), RouteError> {
		let result = self.complete_batch_inner(request, response).await;
		self.abort_batch(request).await;
		result
	}

	async fn complete_batch_inner(
		&self,
		request: &RouteMixReq,
		response: &MixResp,
	) -> Result<(), RouteError> {
		let store = self.store.lock().await;
		let route = store
			.route(request.route_id, request.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		let position = route
			.manifest
			.ordered_hops
			.iter()
			.position(|hop| hop.identity_public_key == self.config.mwixnet_identity())
			.ok_or_else(|| {
				RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"server is not a route participant",
				)
			})?;
		if response.version != Some(MWIXNET_PROTOCOL_VERSION)
			|| response.msg_type != Some(MwixnetType::MixResp)
			|| response.batch_id != Some(request.batch_id)
			|| response.indices.windows(2).any(|pair| pair[0] >= pair[1])
			|| response
				.indices
				.iter()
				.any(|index| *index >= request.onions.len())
			|| response.components.outputs.len() != response.indices.len()
			|| if response.indices.is_empty() {
				!response.components.kernels.is_empty()
			} else {
				response.components.kernels.len() != route.manifest.ordered_hops.len() - position
			} {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route mix response",
			));
		}
		store.save_batch(
			request.route_id,
			request.batch_id,
			&BatchBinding {
				request_hash: request.hash(),
				request: request.clone(),
				response: Some(response.clone()),
			},
		)?;
		Ok(())
	}

	pub async fn abort_batch(&self, request: &RouteMixReq) {
		self.active_batches
			.lock()
			.await
			.remove(&(request.route_id, request.batch_id));
	}

	pub async fn relay_item(
		&self,
		manifest: &RouteManifest,
	) -> Result<Option<mwixnet_protocol::RouteRelayItem>, RouteError> {
		let store = self.store.lock().await;
		let mut route = store
			.route(manifest.route_id, manifest.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if let Some(item) = route.pending_relay.first() {
			return Ok(Some(item.clone()));
		}
		let proof = match &route.health_proof {
			Some(proof) if proof.certificate.expires_at > Utc::now().timestamp() as u64 => proof,
			_ => return Ok(None),
		};
		route.relay_sequence = route.relay_sequence.checked_add(1).ok_or_else(|| {
			RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"route relay sequence exhausted",
			)
		})?;
		let sequence = route.relay_sequence;
		let item = match route.state {
			RouteState::Healthy => {
				let mut announcement = mwixnet_protocol::RouteAnnouncement {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::RouteAnnouncement,
					route_id: manifest.route_id,
					manifest_sequence: manifest.manifest_sequence,
					entry_onion: manifest.ordered_hops[0].onion_address,
					swap_identity: manifest.swap_identity,
					hop_count: manifest.ordered_hops.len() as u8,
					participant_identities: manifest
						.ordered_hops
						.iter()
						.map(|hop| hop.identity_public_key)
						.collect(),
					fee_per_hop: manifest.fee_per_hop,
					manifest_hash: manifest.hash(),
					health_hash: proof.certificate.hash(),
					status: RouteState::Healthy,
					last_verified: proof.certificate.verified_at,
					valid_until: proof.certificate.expires_at,
					sequence,
					signature: mwixnet_protocol::Signature([0; 64]),
				};
				announcement.signature = self.config.sign_mwixnet_hash(announcement.hash());
				mwixnet_protocol::RouteRelayItem::Announcement(announcement)
			}
			RouteState::Degraded
			| RouteState::Unavailable
			| RouteState::Draining
			| RouteState::Expired => {
				let mut status = mwixnet_protocol::RouteStatus {
					version: MWIXNET_PROTOCOL_VERSION,
					msg_type: MwixnetType::RouteStatus,
					route_id: manifest.route_id,
					manifest_sequence: manifest.manifest_sequence,
					manifest_hash: manifest.hash(),
					status: route.state,
					last_verified: proof.certificate.verified_at,
					valid_until: proof.certificate.expires_at,
					sequence,
					swap_identity: manifest.swap_identity,
					signature: mwixnet_protocol::Signature([0; 64]),
				};
				status.signature = self.config.sign_mwixnet_hash(status.hash());
				mwixnet_protocol::RouteRelayItem::Status(status)
			}
			RouteState::Proposed | RouteState::Revoked => return Ok(None),
		};
		route.pending_relay.push(item.clone());
		store.save_route(&route)?;
		Ok(Some(item))
	}

	pub async fn relay_submitted(
		&self,
		item: &mwixnet_protocol::RouteRelayItem,
	) -> Result<(), RouteError> {
		let store = self.store.lock().await;
		let mut route = store
			.route(item.route_id(), item.manifest_sequence())?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if route.pending_relay.first() == Some(item) {
			route.pending_relay.remove(0);
			store.save_route(&route)?;
		}
		Ok(())
	}

	pub async fn pending_relay_items(
		&self,
	) -> Result<Vec<mwixnet_protocol::RouteRelayItem>, RouteError> {
		Ok(self
			.store
			.lock()
			.await
			.routes()?
			.into_iter()
			.filter_map(|route| route.pending_relay.first().cloned())
			.collect())
	}

	pub async fn revoke(&self, revocation: RouteRevocation) -> Result<(), RouteError> {
		let now = Utc::now().timestamp() as u64;
		if revocation.validate(now).is_err() {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route revocation",
			));
		}
		let store = self.store.lock().await;
		let mut route = store
			.route(revocation.route_id, revocation.manifest_sequence)?
			.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
		if revocation.manifest_hash != route.manifest.hash()
			|| !route
				.manifest
				.ordered_hops
				.iter()
				.any(|hop| hop.identity_public_key == revocation.participant_identity)
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"revocation does not match route",
			));
		}
		if let Some(previous) = route
			.revocations
			.iter()
			.find(|previous| previous.participant_identity == revocation.participant_identity)
		{
			if previous == &revocation || previous.sequence > revocation.sequence {
				return Ok(());
			}
			if previous.sequence == revocation.sequence {
				return Err(RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"revocation sequence is bound to different content",
				));
			}
		}
		route.state = RouteState::Revoked;
		if let Some(position) = route.pending_relay.iter().position(|item| {
			matches!(item, mwixnet_protocol::RouteRelayItem::Revocation(previous)
				if previous.participant_identity == revocation.participant_identity)
		}) {
			route.pending_relay[position] =
				mwixnet_protocol::RouteRelayItem::Revocation(revocation.clone());
		} else {
			route
				.pending_relay
				.push(mwixnet_protocol::RouteRelayItem::Revocation(
					revocation.clone(),
				));
		}
		route
			.revocations
			.retain(|previous| previous.participant_identity != revocation.participant_identity);
		route.revocations.push(revocation);
		store.save_route(&route)?;
		Ok(())
	}

	pub async fn create_revocation(
		&self,
		route_id: Hash,
		manifest_sequence: u64,
	) -> Result<RouteRevocation, RouteError> {
		let identity = self.config.mwixnet_identity();
		let (existing, manifest_hash) = {
			let store = self.store.lock().await;
			let route = store.route(route_id, manifest_sequence)?.ok_or_else(|| {
				RouteError::protocol(ProtocolErrorCode::RouteUnknown, "route not found")
			})?;
			if !route
				.manifest
				.ordered_hops
				.iter()
				.any(|hop| hop.identity_public_key == identity)
			{
				return Err(RouteError::protocol(
					ProtocolErrorCode::InvalidMwixnetMessage,
					"server is not a route participant",
				));
			}
			(
				route
					.revocations
					.iter()
					.find(|revocation| revocation.participant_identity == identity)
					.cloned(),
				route.manifest.hash(),
			)
		};
		if let Some(revocation) = existing {
			return Ok(revocation);
		}

		let mut revocation = RouteRevocation {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::RouteRevocation,
			route_id,
			manifest_sequence,
			manifest_hash,
			participant_identity: identity,
			revoked_at: Utc::now().timestamp() as u64,
			sequence: 1,
			signature: mwixnet_protocol::Signature([0; 64]),
		};
		revocation.signature = self.config.sign_mwixnet_hash(revocation.hash());
		self.revoke(revocation.clone()).await?;
		Ok(revocation)
	}

	pub async fn sync_revocations(
		&self,
		items: Vec<mwixnet_protocol::RouteRelayItem>,
	) -> Result<Vec<(Hash, u64)>, RouteError> {
		let mut revoked = Vec::new();
		for item in items {
			if let mwixnet_protocol::RouteRelayItem::Revocation(revocation) = item {
				if self
					.store
					.lock()
					.await
					.route(revocation.route_id, revocation.manifest_sequence)?
					.is_some()
				{
					let key = (revocation.route_id, revocation.manifest_sequence);
					self.revoke(revocation).await?;
					revoked.push(key);
				}
			}
		}
		Ok(revoked)
	}
}

fn offer_sequence(offer: &MwixnetOffer) -> u64 {
	match offer {
		MwixnetOffer::Mixer(offer) => offer.sequence,
		MwixnetOffer::Swap(offer) => offer.sequence,
	}
}

fn validate_health_tail(
	response: &HealthResponse,
	manifest: &RouteManifest,
	start: usize,
	challenge_hash: Hash,
) -> Result<(), RouteError> {
	if response.version != MWIXNET_PROTOCOL_VERSION
		|| response.msg_type != MwixnetType::HealthResponse
		|| response.route_id != manifest.route_id
		|| response.manifest_sequence != manifest.manifest_sequence
		|| response.challenge_hash != challenge_hash
		|| response.attestations.len() != manifest.ordered_hops.len() - start
	{
		return Err(RouteError::protocol(
			ProtocolErrorCode::InvalidMwixnetMessage,
			"invalid health response",
		));
	}
	for (offset, attestation) in response.attestations.iter().enumerate() {
		let position = start + offset;
		let next = response
			.attestations
			.get(offset + 1)
			.map(HealthAttestation::hash);
		if attestation.route_id != manifest.route_id
			|| attestation.manifest_sequence != manifest.manifest_sequence
			|| attestation.challenge_hash != challenge_hash
			|| attestation.hop_position as usize != position
			|| attestation.participant_identity
				!= manifest.ordered_hops[position].identity_public_key
			|| attestation.next_attestation_hash != next
			|| mwixnet_protocol::verify_signature(
				attestation.hash(),
				attestation.participant_identity,
				attestation.signature,
			)
			.is_err()
		{
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid health attestation chain",
			));
		}
	}
	Ok(())
}

fn offer_hop(offer: &MwixnetOffer) -> mwixnet_protocol::RouteHop {
	match offer {
		MwixnetOffer::Mixer(offer) => mwixnet_protocol::RouteHop {
			role: RouteRole::Mixer,
			identity_public_key: offer.identity_public_key,
			onion_address: offer.onion_address,
			onion_public_key: offer.onion_public_key,
		},
		MwixnetOffer::Swap(offer) => mwixnet_protocol::RouteHop {
			role: RouteRole::Swap,
			identity_public_key: offer.identity_public_key,
			onion_address: offer.onion_address,
			onion_public_key: offer.onion_public_key,
		},
	}
}

fn validate_offers(
	proposal: &RouteProposal,
	offers: &[MwixnetOffer],
	now: u64,
) -> Result<(), RouteError> {
	if offers.len() != proposal.ordered_hops.len() {
		return Err(RouteError::protocol(
			ProtocolErrorCode::InvalidMwixnetMessage,
			"offer list does not match route",
		));
	}
	for (position, (hop, offer)) in proposal.ordered_hops.iter().zip(offers).enumerate() {
		if offer.validate(now).is_err()
			|| offer.identity() != hop.identity_public_key
			|| offer.valid_until() < proposal.valid_until
			|| offer.minimum_fee() > proposal.fee_per_hop
			|| !matches!(
				(position, offer),
				(0, MwixnetOffer::Swap(_)) | (1.., MwixnetOffer::Mixer(_))
			) {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid offer for route hop",
			));
		}
		let keys_match = match offer {
			MwixnetOffer::Mixer(offer) => {
				offer.onion_address == hop.onion_address
					&& offer.onion_public_key == hop.onion_public_key
			}
			MwixnetOffer::Swap(offer) => {
				offer.onion_address == hop.onion_address
					&& offer.onion_public_key == hop.onion_public_key
			}
		};
		if !keys_match {
			return Err(RouteError::protocol(
				ProtocolErrorCode::InvalidMwixnetMessage,
				"offer keys do not match route hop",
			));
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::servers::mix_rpc::MixResp;
	use async_trait::async_trait;
	use grin_onion::crypto::secp;
	use grin_onion::onion::Onion;
	use grin_onion::test_util as onion_test_util;
	use grin_wallet_libwallet::mwixnet::onion as grin_onion;
	use mwixnet_protocol::{route_id, RouteHop, Signature};

	#[test]
	fn swap_offer_limits_route_fee_and_hops() {
		let offer = SwapOffer {
			version: 1,
			msg_type: MwixnetType::SwapOffer,
			identity_public_key: mwixnet_protocol::PublicKey([1; 32]),
			onion_address: mwixnet_protocol::OnionAddress([2; 32]),
			onion_public_key: mwixnet_protocol::OnionPublicKey([3; 32]),
			minimum_fee: 10,
			capacity: 1,
			desired_min_hops: Some(2),
			desired_max_hops: Some(3),
			maximum_fee_per_hop: Some(20),
			max_request_ttl_blocks: MAX_REQUEST_TTL_BLOCKS,
			valid_until: 1,
			sequence: 1,
			signature: Signature([0; 64]),
		};

		assert!(route_matches_swap_policy(&offer, 20, 2));
		assert!(route_matches_swap_policy(&offer, 20, 3));
		assert!(!route_matches_swap_policy(&offer, 21, 2));
		assert!(!route_matches_swap_policy(&offer, 20, 1));
		assert!(!route_matches_swap_policy(&offer, 20, 4));
	}

	struct DirectRouteClient {
		mixer: RouteService,
		next: Option<Arc<dyn MixClient>>,
		reject_proposal: bool,
	}

	struct FailingHealthClient;

	#[async_trait]
	impl MixClient for FailingHealthClient {
		async fn mix_outputs(&self, _onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			Err(MixClientError::Custom("unavailable".into()))
		}

		async fn probe_route(
			&self,
			_request: HealthRequest,
		) -> Result<HealthResponse, MixClientError> {
			Err(MixClientError::Custom("unavailable".into()))
		}
	}

	struct InvalidHealthClient {
		inner: Arc<dyn MixClient>,
	}

	#[async_trait]
	impl MixClient for InvalidHealthClient {
		async fn mix_outputs(&self, _onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			Err(MixClientError::Custom("mix not used by route test".into()))
		}

		async fn probe_route(
			&self,
			request: HealthRequest,
		) -> Result<HealthResponse, MixClientError> {
			let mut response = self.inner.probe_route(request).await?;
			response.attestations[0].signature = Signature([0; 64]);
			Ok(response)
		}
	}

	#[async_trait]
	impl MixClient for DirectRouteClient {
		async fn mix_outputs(&self, _onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			Err(MixClientError::Custom("mix not used by route test".into()))
		}

		async fn get_mwixnet_offer(&self) -> Result<MwixnetOffer, MixClientError> {
			self.mixer
				.offer()
				.await
				.map_err(|error| MixClientError::Custom(error.to_string()))
		}

		async fn propose_route(
			&self,
			proposal: RouteProposal,
			offers: Vec<MwixnetOffer>,
		) -> Result<RouteAcceptance, MixClientError> {
			if self.reject_proposal {
				return Err(MixClientError::Custom(
					"proposal rejected by test client".into(),
				));
			}
			self.mixer
				.propose(proposal, offers)
				.await
				.map_err(|error| MixClientError::Custom(error.to_string()))
		}

		async fn activate_route(&self, manifest: RouteManifest) -> Result<(), MixClientError> {
			self.mixer
				.activate(manifest)
				.await
				.map_err(|error| MixClientError::Custom(error.to_string()))
		}

		async fn probe_route(
			&self,
			request: HealthRequest,
		) -> Result<HealthResponse, MixClientError> {
			self.mixer
				.probe(request, self.next.as_deref())
				.await
				.map_err(|error| MixClientError::Custom(error.to_string()))
		}
	}

	#[tokio::test]
	async fn proposal_activation_is_persistent_and_idempotent() {
		grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
		let swap_config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		let mut mixer_config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		mixer_config.mixer = true;
		let root = format!(
			"./target/tmp/.route_service_{}",
			Utc::now().timestamp_nanos_opt().unwrap()
		);
		let swap = RouteService::new(
			swap_config.clone(),
			RouteStore::new(&format!("{}/swap", root)).unwrap(),
			RouteRole::Swap,
			10,
		);
		let mixer = RouteService::new(
			mixer_config.clone(),
			RouteStore::new(&format!("{}/mixer", root)).unwrap(),
			RouteRole::Mixer,
			20,
		);
		let swap_offer = swap.offer().await.unwrap();
		let mixer_offer = mixer.offer().await.unwrap();
		let offers = vec![swap_offer, mixer_offer];
		let hops = vec![
			RouteHop {
				role: RouteRole::Swap,
				identity_public_key: swap_config.mwixnet_identity(),
				onion_address: swap_config.mwixnet_onion_address(),
				onion_public_key: swap_config.mwixnet_onion_pubkey(),
			},
			RouteHop {
				role: RouteRole::Mixer,
				identity_public_key: mixer_config.mwixnet_identity(),
				onion_address: mixer_config.mwixnet_onion_address(),
				onion_public_key: mixer_config.mwixnet_onion_pubkey(),
			},
		];
		let now = Utc::now().timestamp() as u64;
		let valid_until = offers.iter().map(MwixnetOffer::valid_until).min().unwrap();
		let route_id = route_id(20, &hops).unwrap();
		let mut proposal = RouteProposal {
			version: 1,
			msg_type: MwixnetType::RouteProposal,
			route_id,
			manifest_sequence: 1,
			valid_from: now,
			valid_until,
			fee_per_hop: 20,
			ordered_hops: hops,
			proposer_signature: Signature([0; 64]),
		};
		proposal.proposer_signature = swap_config.sign_mwixnet_hash(proposal.hash());
		let mixer_acceptance = mixer
			.propose(proposal.clone(), offers.clone())
			.await
			.unwrap();
		assert_eq!(
			mixer_acceptance,
			mixer
				.propose(proposal.clone(), offers.clone())
				.await
				.unwrap()
		);
		let mut swap_acceptance = RouteAcceptance {
			version: 1,
			msg_type: MwixnetType::RouteAcceptance,
			route_id,
			manifest_sequence: 1,
			proposal_hash: proposal.hash(),
			participant_identity: swap_config.mwixnet_identity(),
			accepted_until: valid_until,
			signature: Signature([0; 64]),
		};
		swap_acceptance.signature = swap_config.sign_mwixnet_hash(swap_acceptance.hash());
		let mut manifest = RouteManifest {
			version: 1,
			msg_type: MwixnetType::RouteManifest,
			route_id,
			manifest_sequence: 1,
			proposal_hash: proposal.hash(),
			valid_from: proposal.valid_from,
			valid_until,
			fee_per_hop: proposal.fee_per_hop,
			ordered_hops: proposal.ordered_hops,
			proposer_signature: proposal.proposer_signature,
			acceptances: vec![swap_acceptance, mixer_acceptance],
			swap_identity: swap_config.mwixnet_identity(),
			signature: Signature([0; 64]),
		};
		manifest.signature = swap_config.sign_mwixnet_hash(manifest.hash());
		mixer.activate(manifest.clone()).await.unwrap();
		mixer.activate(manifest.clone()).await.unwrap();
		assert_eq!(manifest, mixer.route(route_id).await.unwrap());
		let mut skipped = manifest.proposal();
		skipped.manifest_sequence = 3;
		skipped.proposer_signature = swap_config.sign_mwixnet_hash(skipped.hash());
		assert!(mixer.propose(skipped, offers).await.is_err());
		let mut route = mixer
			.store
			.lock()
			.await
			.route(route_id, manifest.manifest_sequence)
			.unwrap()
			.unwrap();
		route.state = RouteState::Draining;
		route.manifest.valid_until = now - 1;
		mixer.store.lock().await.save_route(&route).unwrap();
		let mut request = RouteMixReq {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::MixReq,
			route_id,
			manifest_sequence: manifest.manifest_sequence,
			batch_id: Hash([9; 32]),
			onions: vec![onion_test_util::rand_onion()],
			sig: grin_onion::crypto::dalek::sign(&swap_config.key, &[]).unwrap(),
		};
		request.sig = grin_onion::crypto::dalek::sign(&swap_config.key, &request.hash().0).unwrap();
		assert_eq!(
			mixer.begin_batch(&request).await.unwrap().0,
			swap_config.mwixnet_identity()
		);
		let revocation = mixer
			.create_revocation(route_id, manifest.manifest_sequence)
			.await
			.unwrap();
		assert_eq!(
			revocation,
			mixer
				.create_revocation(route_id, manifest.manifest_sequence)
				.await
				.unwrap()
		);
		let route = mixer
			.store
			.lock()
			.await
			.route(route_id, manifest.manifest_sequence)
			.unwrap()
			.unwrap();
		assert_eq!(route.state, RouteState::Revoked);
		assert_eq!(route.revocations, vec![revocation.clone()]);
		assert_eq!(
			route.pending_relay,
			vec![mwixnet_protocol::RouteRelayItem::Revocation(revocation)]
		);
		std::fs::remove_dir_all(root).unwrap();
	}

	#[tokio::test]
	async fn offer_sequence_changes_with_policy() {
		grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
		let config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		let root = format!(
			"./target/tmp/.route_offer_{}",
			Utc::now().timestamp_nanos_opt().unwrap()
		);
		let service = RouteService::new(
			config.clone(),
			RouteStore::new(&root).unwrap(),
			RouteRole::Swap,
			10,
		);
		let first = service.offer().await.unwrap();
		drop(service);

		let service =
			RouteService::new(config, RouteStore::new(&root).unwrap(), RouteRole::Swap, 20);
		let second = service.offer().await.unwrap();
		assert_eq!(offer_sequence(&second), offer_sequence(&first) + 1);
		assert_eq!(service.offer().await.unwrap(), second);
		std::fs::remove_dir_all(root).unwrap();
	}

	#[tokio::test]
	async fn creates_and_checks_two_hop_route() {
		grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
		let swap_config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		let mixer_config = crate::config::test_util::local_config(
			&secp::random_secret(false),
			&Some(swap_config.server_pubkey()),
			&None,
		)
		.unwrap();
		let root = format!(
			"./target/tmp/.route_health_{}",
			Utc::now().timestamp_nanos_opt().unwrap()
		);
		let swap = RouteService::new(
			swap_config,
			RouteStore::new(&format!("{}/swap", root)).unwrap(),
			RouteRole::Swap,
			10,
		);
		let client = Arc::new(DirectRouteClient {
			mixer: RouteService::new(
				mixer_config,
				RouteStore::new(&format!("{}/mixer", root)).unwrap(),
				RouteRole::Mixer,
				20,
			),
			next: None,
			reject_proposal: false,
		});
		let clients: Vec<Arc<dyn MixClient>> = vec![client.clone()];
		let manifest = swap.create_route(&clients).await.unwrap();
		let proof = swap.check_health(&manifest, client.as_ref()).await.unwrap();
		proof
			.validate(&manifest, Utc::now().timestamp() as u64)
			.unwrap();
		let relay = swap.relay_item(&manifest).await.unwrap().unwrap();
		relay.validate(Utc::now().timestamp() as u64).unwrap();
		assert_eq!(
			swap.pending_relay_items().await.unwrap(),
			vec![relay.clone()]
		);
		swap.relay_submitted(&relay).await.unwrap();
		assert!(swap.pending_relay_items().await.unwrap().is_empty());
		assert_eq!(
			proof,
			swap.health(manifest.route_id, manifest.manifest_sequence)
				.await
				.unwrap()
		);
		let invalid = InvalidHealthClient {
			inner: client.clone(),
		};
		assert!(swap.check_health(&manifest, &invalid).await.is_err());
		assert!(swap
			.store
			.lock()
			.await
			.pending_health(manifest.route_id, manifest.manifest_sequence)
			.unwrap()
			.unwrap()
			.response
			.is_none());
		assert!(swap
			.check_health(&manifest, &FailingHealthClient)
			.await
			.is_err());
		let route = swap
			.store
			.lock()
			.await
			.route(manifest.route_id, manifest.manifest_sequence)
			.unwrap()
			.unwrap();
		assert_eq!(route.failures, 1);
		assert_eq!(route.state, RouteState::Degraded);
		let mut terminal = route;
		terminal.state = RouteState::Revoked;
		swap.store.lock().await.save_route(&terminal).unwrap();
		let invalid = InvalidHealthClient {
			inner: client.clone(),
		};
		assert!(swap.check_health(&manifest, &invalid).await.is_err());
		swap.check_health(&manifest, client.as_ref()).await.unwrap();
		let terminal = swap
			.store
			.lock()
			.await
			.route(manifest.route_id, manifest.manifest_sequence)
			.unwrap()
			.unwrap();
		assert_eq!(terminal.state, RouteState::Revoked);
		assert_eq!(terminal.failures, 1);
		std::fs::remove_dir_all(root).unwrap();
	}

	#[tokio::test]
	async fn creates_and_checks_three_hop_route() {
		grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
		let swap_config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		let mut first_config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		first_config.mixer = true;
		let mut last_config =
			crate::config::test_util::local_config(&secp::random_secret(false), &None, &None)
				.unwrap();
		last_config.mixer = true;
		let root = format!(
			"./target/tmp/.route_health_three_{}",
			Utc::now().timestamp_nanos_opt().unwrap()
		);
		let swap = RouteService::new(
			swap_config.clone(),
			RouteStore::new(&format!("{}/swap", root)).unwrap(),
			RouteRole::Swap,
			10,
		);
		let last = Arc::new(DirectRouteClient {
			mixer: RouteService::new(
				last_config,
				RouteStore::new(&format!("{}/last", root)).unwrap(),
				RouteRole::Mixer,
				20,
			),
			next: None,
			reject_proposal: false,
		});
		let first = Arc::new(DirectRouteClient {
			mixer: RouteService::new(
				first_config,
				RouteStore::new(&format!("{}/first", root)).unwrap(),
				RouteRole::Mixer,
				20,
			),
			next: Some(last.clone()),
			reject_proposal: false,
		});
		let initial_clients: Vec<Arc<dyn MixClient>> = vec![first.clone()];
		let initial_manifest = swap.create_route(&initial_clients).await.unwrap();
		swap.check_health(&initial_manifest, first.as_ref())
			.await
			.unwrap();
		let rejecting_last = Arc::new(DirectRouteClient {
			mixer: last.mixer.clone(),
			next: None,
			reject_proposal: true,
		});
		let rejected_clients: Vec<Arc<dyn MixClient>> = vec![first.clone(), rejecting_last];
		assert!(swap.create_route(&rejected_clients).await.is_err());
		assert_eq!(
			swap.active_route().await.unwrap(),
			Some((
				initial_manifest.route_id,
				initial_manifest.manifest_sequence
			))
		);
		let clients: Vec<Arc<dyn MixClient>> = vec![first.clone(), last.clone()];
		let manifest = swap.create_route(&clients).await.unwrap();
		assert_eq!(manifest.ordered_hops.len(), 3);
		assert!(swap.check_health(&manifest, last.as_ref()).await.is_err());
		assert_eq!(
			swap.active_route().await.unwrap(),
			Some((
				initial_manifest.route_id,
				initial_manifest.manifest_sequence
			))
		);
		let proof = swap.check_health(&manifest, first.as_ref()).await.unwrap();
		proof
			.validate(&manifest, Utc::now().timestamp() as u64)
			.unwrap();
		assert_eq!(
			swap.active_route().await.unwrap(),
			Some((manifest.route_id, manifest.manifest_sequence))
		);
		let mut initial_route = swap
			.store
			.lock()
			.await
			.route(
				initial_manifest.route_id,
				initial_manifest.manifest_sequence,
			)
			.unwrap()
			.unwrap();
		initial_route.state = RouteState::Unavailable;
		swap.store.lock().await.save_route(&initial_route).unwrap();
		swap.drain(
			initial_manifest.route_id,
			initial_manifest.manifest_sequence,
		)
		.await
		.unwrap();
		drop(swap);
		let reopened = RouteService::new(
			swap_config,
			RouteStore::new(&format!("{}/swap", root)).unwrap(),
			RouteRole::Swap,
			10,
		);
		assert_eq!(
			reopened.active_route().await.unwrap(),
			Some((manifest.route_id, manifest.manifest_sequence))
		);
		assert_eq!(
			reopened
				.store
				.lock()
				.await
				.route(
					initial_manifest.route_id,
					initial_manifest.manifest_sequence
				)
				.unwrap()
				.unwrap()
				.state,
			RouteState::Draining
		);
		for client in [first, last] {
			assert_eq!(
				client
					.mixer
					.store
					.lock()
					.await
					.route(manifest.route_id, manifest.manifest_sequence)
					.unwrap()
					.unwrap()
					.state,
				RouteState::Healthy
			);
		}
		std::fs::remove_dir_all(root).unwrap();
	}
}
