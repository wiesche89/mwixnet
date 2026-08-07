use std::collections::{HashMap, HashSet};
use std::result::Result;
use std::sync::Arc;

use async_trait::async_trait;
use grin_core::core::{Committed, Input, Output, OutputFeatures, Transaction, TransactionBody};
use grin_util::ToHex;
use itertools::Itertools;
use secp256k1zkp::key::ZERO_KEY;
use thiserror::Error;

use grin_onion::crypto::comsig::ComSignature;
use grin_onion::crypto::secp::{Commitment, Secp256k1, SecretKey};
use grin_onion::onion::{Onion, OnionError};
use grin_wallet_libwallet::mwixnet::onion as grin_onion;

use crate::config::ServerConfig;
use crate::mix_client::MixClient;
use crate::node::{self, GrinNode};
use crate::servers::mix_rpc::RouteMixReq;
use crate::servers::swap_rpc::{
	CancelAck, CancelStatus, CancelSwapReq, RouteSwapReq, SwapSubmission, SwapSubmissionStatus,
};
use crate::store::{RouteSwapData, StoreError, SwapData, SwapStatus, SwapStore, SwapTx};
use crate::tx;
use crate::wallet::Wallet;

/// Swap error types
#[derive(Clone, Error, Debug, PartialEq)]
pub enum SwapError {
	#[error("{0}")]
	Protocol(mwixnet_protocol::ProtocolRpcError),
	#[error("Invalid number of payloads provided")]
	InvalidPayloadLength,
	#[error("Commitment Signature is invalid")]
	InvalidComSignature,
	#[error("Rangeproof is invalid")]
	InvalidRangeproof,
	#[error("Rangeproof is required but was not supplied")]
	MissingRangeproof,
	#[error("Output {commit:?} does not exist, or is already spent.")]
	CoinNotFound { commit: Commitment },
	#[error("Output {commit:?} is already in the swap list.")]
	AlreadySwapped { commit: Commitment },
	#[error("Failed to peel onion layer: {0:?}")]
	PeelOnionFailure(OnionError),
	#[error("Fee too low (expected >= {minimum_fee:?}, actual {actual_fee:?})")]
	FeeTooLow { minimum_fee: u64, actual_fee: u64 },
	#[error("Error saving swap to data store: {0}")]
	StoreError(StoreError),
	#[error("Error building transaction: {0}")]
	TxError(String),
	#[error("Node communication error: {0}")]
	NodeError(String),
	#[error("Client communication error: {0:?}")]
	ClientError(String),
	#[error("Swap transaction not found: {0:?}")]
	SwapTxNotFound(Commitment),
	#[error("{0}")]
	UnknownError(String),
}

impl SwapError {
	fn protocol(code: mwixnet_protocol::ProtocolErrorCode, message: &str) -> Self {
		Self::Protocol(mwixnet_protocol::ProtocolRpcError::new(code, message))
	}
}

impl From<StoreError> for SwapError {
	fn from(e: StoreError) -> SwapError {
		SwapError::StoreError(e)
	}
}

impl From<tx::TxError> for SwapError {
	fn from(e: tx::TxError) -> SwapError {
		SwapError::TxError(e.to_string())
	}
}

impl From<node::NodeError> for SwapError {
	fn from(e: node::NodeError) -> SwapError {
		SwapError::NodeError(e.to_string())
	}
}

/// A public MWixnet server - the "Swap Server"
#[async_trait]
pub trait SwapServer: Send + Sync {
	/// Submit a new output to be swapped.
	async fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError>;

	async fn route_swap(
		&self,
		_request: &RouteSwapReq,
		_expected_hops: usize,
	) -> Result<SwapSubmission, SwapError> {
		Err(SwapError::UnknownError(
			"route requests are not supported".into(),
		))
	}

	fn set_next_server(&mut self, _next_server: Option<Arc<dyn MixClient>>) {}

	async fn route_submission(
		&self,
		_request: &RouteSwapReq,
	) -> Result<Option<SwapSubmission>, SwapError> {
		Ok(None)
	}

	async fn cancel_route_swap(&self, _request: &CancelSwapReq) -> Result<CancelAck, SwapError> {
		Err(SwapError::UnknownError(
			"route cancellation is not supported".into(),
		))
	}

	async fn route_open_requests(
		&self,
	) -> Result<HashMap<(mwixnet_protocol::Hash, u64), u64>, SwapError> {
		Ok(HashMap::new())
	}

	async fn reject_route_requests(
		&self,
		_route_id: mwixnet_protocol::Hash,
		_manifest_sequence: u64,
	) -> Result<(), SwapError> {
		Ok(())
	}

	/// Iterate through all saved submissions, filter out any inputs that are no longer spendable,
	/// and assemble the coinswap transaction, posting the transaction to the configured node.
	async fn execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError>;

	/// Verify the previous swap transaction is in the active chain or mempool.
	/// If it's not, rebroacast the transaction if it's still valid.
	/// If the transaction is no longer valid, perform the swap again.
	async fn check_reorg(
		&self,
		tx: &Arc<Transaction>,
	) -> Result<Option<Arc<Transaction>>, SwapError>;
}

/// The standard MWixnet server implementation
#[derive(Clone)]
pub struct SwapServerImpl {
	server_config: ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	wallet: Option<Arc<dyn Wallet>>,
	node: Arc<dyn GrinNode>,
	store: Arc<tokio::sync::Mutex<SwapStore>>,
}

impl SwapServerImpl {
	/// Create a new MWixnet server
	pub fn new(
		server_config: ServerConfig,
		next_server: Option<Arc<dyn MixClient>>,
		wallet: Option<Arc<dyn Wallet>>,
		node: Arc<dyn GrinNode>,
		store: SwapStore,
	) -> Self {
		SwapServerImpl {
			server_config,
			next_server,
			wallet,
			node,
			store: Arc::new(tokio::sync::Mutex::new(store)),
		}
	}

	fn get_fee_base(&self) -> u64 {
		self.server_config.accept_fee_base
	}

	/// Minimum fee to perform a swap.
	/// Requires enough fee for the swap server's kernel, 1 input and its output to swap.
	pub(crate) fn get_minimum_swap_fee(&self) -> u64 {
		TransactionBody::weight_by_iok(1, 1, 1) * self.get_fee_base()
	}

	async fn prepare_swap(
		&self,
		onion: &Onion,
		comsig: &ComSignature,
		signed_message: Vec<u8>,
		route: Option<RouteSwapData>,
		expected_hops: Option<usize>,
	) -> Result<SwapData, SwapError> {
		let valid_payload_count = match expected_hops {
			Some(expected) => onion.enc_payloads.len() == expected,
			None => {
				self.server_config.next_server.is_some() && onion.enc_payloads.len() > 1
					|| self.server_config.next_server.is_none() && onion.enc_payloads.len() == 1
			}
		};
		if !valid_payload_count {
			return Err(SwapError::InvalidPayloadLength);
		}
		comsig
			.verify(&onion.commit, &signed_message)
			.map_err(|_| SwapError::InvalidComSignature)?;
		let input = node::async_build_input(&self.node, &onion.commit)
			.await
			.map_err(|e| SwapError::UnknownError(e.to_string()))?
			.ok_or(SwapError::CoinNotFound {
				commit: onion.commit,
			})?;
		let peeled = onion
			.peel_layer(&self.server_config.key)
			.map_err(SwapError::PeelOnionFailure)?;
		let fee: u64 = peeled.payload.fee.into();
		if fee < self.get_minimum_swap_fee() {
			return Err(SwapError::FeeTooLow {
				minimum_fee: self.get_minimum_swap_fee(),
				actual_fee: fee,
			});
		}
		if let Some(rangeproof) = peeled.payload.rangeproof {
			let secp = Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			secp.verify_bullet_proof(peeled.onion.commit, rangeproof, None)
				.map_err(|_| SwapError::InvalidRangeproof)?;
		} else if peeled.onion.enc_payloads.is_empty() {
			return Err(SwapError::MissingRangeproof);
		}
		Ok(SwapData {
			excess: peeled.payload.excess,
			output_commit: peeled.onion.commit,
			rangeproof: peeled.payload.rangeproof,
			input,
			fee,
			onion: peeled.onion,
			status: SwapStatus::Unprocessed,
			route,
		})
	}

	async fn async_is_spendable(&self, next_block_height: u64, swap: &SwapData) -> bool {
		if swap.status == SwapStatus::Batched {
			return true;
		}
		if swap.status == SwapStatus::Unprocessed {
			if node::async_is_spendable(&self.node, &swap.input.commit, next_block_height)
				.await
				.unwrap_or(false)
			{
				if !node::async_is_unspent(&self.node, &swap.output_commit)
					.await
					.unwrap_or(true)
				{
					return true;
				}
			}
		}

		false
	}

	async fn async_execute_round(
		&self,
		store: &SwapStore,
		mut swaps: Vec<SwapData>,
	) -> Result<Option<Arc<Transaction>>, SwapError> {
		swaps.sort_by(|a, b| a.output_commit.partial_cmp(&b.output_commit).unwrap());

		if swaps.len() == 0 {
			return Ok(None);
		}

		println!("Executing swap round with {} output(s)", swaps.len());

		let (mut filtered, mut failed, offset, outputs, kernels) =
			if let Some(client) = &self.next_server {
				let onions: Vec<Onion> = swaps.iter().map(|s| s.onion.clone()).collect();
				let route = swaps.first().and_then(|swap| swap.route.as_ref()).cloned();
				if route.is_some()
					&& swaps.iter().any(|swap| {
						swap.route
							.as_ref()
							.map(|route| (route.route_id, route.manifest_sequence))
							!= route
								.as_ref()
								.map(|route| (route.route_id, route.manifest_sequence))
					}) {
					return Err(SwapError::UnknownError(
						"route batch contains requests from different manifests".into(),
					));
				}
				let mixed = if let Some(route) = route {
					let batch_id = route
						.batch_id
						.unwrap_or_else(|| mwixnet_protocol::Hash(rand::random()));
					let request_hash = RouteMixReq::signing_hash(
						&route.route_id,
						route.manifest_sequence,
						&batch_id,
						&onions,
					);
					for (position, swap) in swaps.iter_mut().enumerate() {
						let metadata = swap.route.as_mut().unwrap();
						if metadata
							.mix_req_hash
							.map(|hash| hash != request_hash)
							.unwrap_or(false)
						{
							return Err(SwapError::protocol(
								mwixnet_protocol::ProtocolErrorCode::BatchConflict,
								"stored batch does not match the request",
							));
						}
						metadata.batch_id = Some(batch_id);
						metadata.batch_position = Some(position as u16);
						metadata.mix_req_hash = Some(request_hash);
						swap.status = SwapStatus::Batched;
					}
					store.save_swaps(&swaps)?;
					client
						.mix_route(route.route_id, route.manifest_sequence, batch_id, &onions)
						.await
						.map_err(|error| SwapError::ClientError(error.to_string()))?
				} else {
					client
						.mix_outputs(&onions)
						.await
						.map_err(|error| SwapError::ClientError(error.to_string()))?
				};
				if let Some(route) = swaps.first().and_then(|swap| swap.route.as_ref()) {
					if mixed.version != Some(mwixnet_protocol::MWIXNET_PROTOCOL_VERSION)
						|| mixed.msg_type != Some(mwixnet_protocol::MwixnetType::MixResp)
						|| mixed.batch_id != route.batch_id
						|| mixed.components.outputs.len() != mixed.indices.len()
						|| !valid_mix_indices(&mixed.indices, swaps.len())
						|| if mixed.indices.is_empty() {
							!mixed.components.kernels.is_empty()
						} else {
							mixed.components.kernels.len() != swaps[0].onion.enc_payloads.len()
						} {
						return Err(SwapError::protocol(
							mwixnet_protocol::ProtocolErrorCode::InvalidMwixnetMessage,
							"invalid route mix response",
						));
					}
				}

				// Filter out failed entries
				let kept_indices = HashSet::<_>::from_iter(mixed.indices.clone());
				let filtered = swaps
					.iter()
					.enumerate()
					.filter(|(i, _)| kept_indices.contains(i))
					.map(|(_, j)| j.clone())
					.collect();

				let failed = swaps
					.iter()
					.enumerate()
					.filter(|(i, _)| !kept_indices.contains(i))
					.map(|(_, j)| j.clone())
					.collect();

				(
					filtered,
					failed,
					mixed.components.offset,
					mixed.components.outputs,
					mixed.components.kernels,
				)
			} else {
				// Build plain outputs for each swap entry
				let outputs: Vec<Output> = swaps
					.iter()
					.map(|s| {
						Output::new(
							OutputFeatures::Plain,
							s.output_commit,
							s.rangeproof.unwrap(),
						)
					})
					.collect();

				(swaps, Vec::new(), ZERO_KEY, outputs, Vec::new())
			};
		if filtered.is_empty() {
			for swap in &mut failed {
				swap.status = SwapStatus::Failed;
			}
			store.save_swaps(&failed)?;
			return Ok(None);
		}

		let fees_paid: u64 = filtered.iter().map(|s| s.fee).sum();
		let inputs: Vec<Input> = filtered.iter().map(|s| s.input).collect();
		let output_excesses: Vec<SecretKey> = filtered.iter().map(|s| s.excess.clone()).collect();

		let tx = tx::async_assemble_tx(
			self.wallet.as_ref(),
			&inputs,
			&outputs,
			&kernels,
			self.get_fee_base(),
			fees_paid,
			&offset,
			&output_excesses,
		)
		.await?;

		let chain_tip = self.node.async_get_chain_tip().await?;

		let input_count = inputs.len();
		let output_count = outputs.len();
		let failed_count = failed.len();
		let swap_tx = SwapTx {
			tx: tx.clone(),
			chain_tip,
		};
		let kernel_commit = tx.kernels().first().unwrap().excess;
		for swap in &mut filtered {
			if swap.route.is_some() {
				swap.status = SwapStatus::Posting { kernel_commit };
			}
		}
		for swap in &mut failed {
			swap.status = SwapStatus::Failed;
		}
		let mut posting = filtered.clone();
		posting.extend(failed.clone());
		store.save_swap_tx_and_swaps(&swap_tx, &posting)?;
		self.node.async_post_tx(&tx).await?;

		// Update status to in process
		for swap in &mut filtered {
			swap.status = SwapStatus::InProcess { kernel_commit };
		}
		store.save_swaps(&filtered)?;

		println!(
			"Swap transaction posted: kernel {}, {} input(s), {} output(s), {} rejected, {} nanogrin fee",
			kernel_commit.to_hex(),
			input_count,
			output_count,
			failed_count,
			fees_paid
		);

		Ok(Some(Arc::new(tx)))
	}
}

fn valid_mix_indices(indices: &[usize], input_count: usize) -> bool {
	!indices.windows(2).any(|pair| pair[0] >= pair[1])
		&& indices.iter().all(|index| *index < input_count)
}

#[async_trait]
impl SwapServer for SwapServerImpl {
	async fn reject_route_requests(
		&self,
		route_id: mwixnet_protocol::Hash,
		manifest_sequence: u64,
	) -> Result<(), SwapError> {
		let store = self.store.lock().await;
		let mut swaps = store
			.swaps_iter()?
			.filter(|swap| {
				swap.status == SwapStatus::Unprocessed
					&& swap
						.route
						.as_ref()
						.map(|route| {
							route.route_id == route_id
								&& route.manifest_sequence == manifest_sequence
						})
						.unwrap_or(false)
			})
			.collect::<Vec<_>>();
		for swap in &mut swaps {
			swap.status = SwapStatus::Failed;
		}
		store.save_swaps(&swaps)?;
		Ok(())
	}

	async fn route_open_requests(
		&self,
	) -> Result<HashMap<(mwixnet_protocol::Hash, u64), u64>, SwapError> {
		let store = self.store.lock().await;
		let mut open = HashMap::new();
		for swap in store.swaps_iter()? {
			if !matches!(
				swap.status,
				SwapStatus::Unprocessed | SwapStatus::Batched | SwapStatus::Posting { .. }
			) {
				continue;
			}
			if let Some(route) = swap.route {
				open.entry((route.route_id, route.manifest_sequence))
					.and_modify(|height: &mut u64| *height = (*height).max(route.expires_at_height))
					.or_insert(route.expires_at_height);
			}
		}
		Ok(open)
	}

	async fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError> {
		let signed_message = onion
			.serialize()
			.map_err(|e| SwapError::UnknownError(e.to_string()))?;
		let swap = self
			.prepare_swap(onion, comsig, signed_message, None, None)
			.await?;
		let output_commit = swap.output_commit;
		let fee = swap.fee;
		let remaining_hops = swap.onion.enc_payloads.len();
		let locked = self.store.lock().await;
		locked.save_swap(&swap, false).map_err(|e| match e {
			StoreError::AlreadyExists(_) => SwapError::AlreadySwapped {
				commit: onion.commit.clone(),
			},
			_ => SwapError::StoreError(e),
		})?;
		println!(
			"Swap request accepted: input {}, output {}, fee {} nanogrin, {} remaining hop(s)",
			onion.commit.to_hex(),
			output_commit.to_hex(),
			fee,
			remaining_hops
		);
		Ok(())
	}

	async fn route_swap(
		&self,
		request: &RouteSwapReq,
		expected_hops: usize,
	) -> Result<SwapSubmission, SwapError> {
		if !request.validate() {
			return Err(SwapError::protocol(
				mwixnet_protocol::ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid route-bound swap request",
			));
		}
		if let Some(submission) = self.route_submission(request).await? {
			return Ok(submission);
		}
		let request_hash = request.hash();
		let tip = self.node.async_get_chain_tip().await?.0;
		if tip >= request.expires_at_height {
			return Err(SwapError::protocol(
				mwixnet_protocol::ProtocolErrorCode::RequestExpired,
				"request expiry height reached",
			));
		}
		let ttl = request.expires_at_height.saturating_sub(tip);
		if ttl < mwixnet_protocol::MIN_REQUEST_TTL_BLOCKS as u64
			|| ttl > mwixnet_protocol::MAX_REQUEST_TTL_BLOCKS as u64
		{
			return Err(SwapError::protocol(
				mwixnet_protocol::ProtocolErrorCode::LimitExceeded,
				"request TTL is outside the server limits",
			));
		}
		let swap = self
			.prepare_swap(
				&request.onion,
				&request.comsig,
				request_hash.0.to_vec(),
				Some(RouteSwapData {
					route_id: request.route_id,
					manifest_sequence: request.manifest_sequence,
					wallet_request_id: request.wallet_request_id,
					swap_req_hash: request_hash,
					expires_at_height: request.expires_at_height,
					batch_id: None,
					batch_position: None,
					mix_req_hash: None,
					cancelled_at: None,
					cancel_req_hash: None,
				}),
				Some(expected_hops),
			)
			.await?;
		let saved = self.store.lock().await.save_route_swap(&swap);
		match saved {
			Ok(()) => {}
			Err(StoreError::AlreadyExists(_)) => {
				if let Some(submission) = self.route_submission(request).await? {
					return Ok(submission);
				}
				return Err(SwapError::protocol(
					mwixnet_protocol::ProtocolErrorCode::InputAlreadyRegistered,
					"input is already registered",
				));
			}
			Err(error) => return Err(SwapError::StoreError(error)),
		}
		Ok(submission(&swap))
	}

	fn set_next_server(&mut self, next_server: Option<Arc<dyn MixClient>>) {
		self.next_server = next_server;
	}

	async fn route_submission(
		&self,
		request: &RouteSwapReq,
	) -> Result<Option<SwapSubmission>, SwapError> {
		let Some(existing) = self
			.store
			.lock()
			.await
			.get_route_swap(request.route_id, request.wallet_request_id)?
		else {
			return Ok(None);
		};
		let route = existing.route.as_ref().ok_or_else(|| {
			SwapError::UnknownError("route request index points to a legacy swap".into())
		})?;
		if route.swap_req_hash != request.hash() {
			return Err(SwapError::protocol(
				mwixnet_protocol::ProtocolErrorCode::RequestConflict,
				"wallet request ID is bound to a different request",
			));
		}
		Ok(Some(submission(&existing)))
	}

	async fn cancel_route_swap(&self, request: &CancelSwapReq) -> Result<CancelAck, SwapError> {
		let now = chrono::Utc::now().timestamp() as u64;
		if request.version != mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			|| request.msg_type != mwixnet_protocol::MwixnetType::CancelSwapReq
			|| request
				.comsig
				.verify(&request.input_commitment, &request.hash().0.to_vec())
				.is_err()
		{
			return Err(SwapError::protocol(
				mwixnet_protocol::ProtocolErrorCode::InvalidMwixnetMessage,
				"invalid cancellation request",
			));
		}
		let store = self.store.lock().await;
		let mut swap = store
			.get_route_swap(request.route_id, request.wallet_request_id)?
			.ok_or_else(|| {
				SwapError::protocol(
					mwixnet_protocol::ProtocolErrorCode::RouteUnknown,
					"request not found",
				)
			})?;
		let route = swap.route.as_mut().unwrap();
		if route.manifest_sequence != request.manifest_sequence
			|| route.swap_req_hash != request.swap_req_hash
			|| swap.input.commit != request.input_commitment
		{
			return Err(SwapError::protocol(
				mwixnet_protocol::ProtocolErrorCode::RequestConflict,
				"cancellation does not match the stored request",
			));
		}
		let tombstone_created_at = match swap.status {
			SwapStatus::Unprocessed => {
				if request.created_at > now.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
					|| now
						> request
							.created_at
							.saturating_add(mwixnet_protocol::MAX_CLOCK_SKEW)
				{
					return Err(SwapError::protocol(
						mwixnet_protocol::ProtocolErrorCode::InvalidMwixnetMessage,
						"cancellation timestamp is outside the allowed clock skew",
					));
				}
				route.cancelled_at = Some(now);
				route.cancel_req_hash = Some(request.hash());
				swap.status = SwapStatus::Cancelled;
				store.save_swap(&swap, true)?;
				now
			}
			SwapStatus::Cancelled => {
				if route.cancel_req_hash != Some(request.hash()) {
					return Err(SwapError::protocol(
						mwixnet_protocol::ProtocolErrorCode::RequestConflict,
						"request was cancelled by a different cancellation",
					));
				}
				route.cancelled_at.unwrap_or(now)
			}
			SwapStatus::Batched | SwapStatus::Posting { .. } => {
				return Err(SwapError::protocol(
					mwixnet_protocol::ProtocolErrorCode::RequestAlreadyProcessing,
					"request is already being processed",
				))
			}
			SwapStatus::InProcess { .. } | SwapStatus::Completed { .. } => {
				return Err(SwapError::protocol(
					mwixnet_protocol::ProtocolErrorCode::RequestPosted,
					"request transaction was posted",
				))
			}
			SwapStatus::Failed => {
				return Err(SwapError::protocol(
					mwixnet_protocol::ProtocolErrorCode::RequestRejected,
					"request was rejected",
				))
			}
			SwapStatus::Expired => {
				return Err(SwapError::protocol(
					mwixnet_protocol::ProtocolErrorCode::RequestExpired,
					"request expired",
				))
			}
		};
		let mut ack = CancelAck {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::CancelAck,
			route_id: request.route_id,
			manifest_sequence: request.manifest_sequence,
			wallet_request_id: request.wallet_request_id,
			cancel_swap_req_hash: request.hash(),
			input_commitment: request.input_commitment,
			status: CancelStatus::Cancelled,
			tombstone_created_at,
			swap_identity: self.server_config.mwixnet_identity(),
			swap_signature: mwixnet_protocol::Signature([0; 64]),
		};
		ack.swap_signature = self.server_config.sign_mwixnet_hash(ack.hash());
		Ok(ack)
	}

	async fn execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError> {
		let chain_tip = self.node.async_get_chain_tip().await?;
		let next_block_height = chain_tip.0 + 1;

		let locked_store = self.store.lock().await;
		let mut swaps: Vec<SwapData> = locked_store
			.swaps_iter()?
			.unique_by(|s| s.output_commit)
			.collect();
		let mut posting = HashSet::new();
		for swap in &mut swaps {
			if let SwapStatus::Posting { kernel_commit } = swap.status {
				if self
					.node
					.async_get_kernel(&kernel_commit, None, None)
					.await?
					.is_some()
				{
					swap.status = SwapStatus::InProcess { kernel_commit };
				} else {
					posting.insert(kernel_commit);
				}
			}
			if let SwapStatus::InProcess { kernel_commit }
			| SwapStatus::Completed { kernel_commit, .. } = swap.status
			{
				match self
					.node
					.async_get_kernel(&kernel_commit, None, None)
					.await?
				{
					Some(kernel) if chain_tip.0.saturating_sub(kernel.height) + 1 >= 10 => {
						swap.status = SwapStatus::Completed {
							kernel_commit,
							block_hash: chain_tip.1,
						};
					}
					Some(_) => swap.status = SwapStatus::InProcess { kernel_commit },
					None => {
						swap.status = SwapStatus::Posting { kernel_commit };
						posting.insert(kernel_commit);
					}
				}
			}
			if let Some(route) = &swap.route {
				if next_block_height >= route.expires_at_height {
					swap.status = match swap.status {
						SwapStatus::Unprocessed => SwapStatus::Expired,
						SwapStatus::Batched => SwapStatus::Failed,
						ref status => status.clone(),
					};
				}
			}
		}
		locked_store.save_swaps(&swaps)?;
		let mut last_tx = None;
		for kernel_commit in posting {
			let stored = locked_store.get_swap_tx(&kernel_commit)?;
			if let Err(error) = self.node.async_post_tx(&stored.tx).await {
				warn!(
					"Unable to repost MWixnet transaction {}: {}",
					kernel_commit.to_hex(),
					error
				);
				continue;
			}
			for swap in &mut swaps {
				if swap.status == (SwapStatus::Posting { kernel_commit }) {
					swap.status = SwapStatus::InProcess { kernel_commit };
				}
			}
			locked_store.save_swaps(&swaps)?;
			last_tx = Some(Arc::new(stored.tx));
		}
		let mut groups: Vec<(
			Option<(mwixnet_protocol::Hash, u64, Option<mwixnet_protocol::Hash>)>,
			Vec<SwapData>,
		)> = Vec::new();
		for swap in &swaps {
			if self.async_is_spendable(next_block_height, &swap).await {
				let key = swap
					.route
					.as_ref()
					.map(|route| (route.route_id, route.manifest_sequence, route.batch_id));
				if let Some((_, group)) = groups.iter_mut().find(|(candidate, _)| *candidate == key)
				{
					group.push(swap.clone());
				} else {
					groups.push((key, vec![swap.clone()]));
				}
			}
		}
		for (_, group) in groups {
			for chunk in group.chunks(mwixnet_protocol::MAX_MIX_BATCH_SIZE) {
				if let Some(tx) = self
					.async_execute_round(&locked_store, chunk.to_vec())
					.await?
				{
					last_tx = Some(tx);
				}
			}
		}
		Ok(last_tx)
	}

	async fn check_reorg(
		&self,
		tx: &Arc<Transaction>,
	) -> Result<Option<Arc<Transaction>>, SwapError> {
		let excess = tx.kernels().first().unwrap().excess;
		let locked_store = self.store.lock().await;
		if let Ok(swap_tx) = locked_store.get_swap_tx(&excess) {
			// If kernel is in active chain, return tx
			if self
				.node
				.async_get_kernel(&excess, Some(swap_tx.chain_tip.0), None)
				.await?
				.is_some()
			{
				return Ok(Some(tx.clone()));
			}

			// If transaction is still valid, rebroadcast and return tx
			if node::async_is_tx_valid(&self.node, &tx).await? {
				self.node.async_post_tx(&tx).await?;
				return Ok(Some(tx.clone()));
			}

			// Collect all swaps based on tx's inputs, and execute_round with those swaps
			let next_block_height = self.node.async_get_chain_tip().await?.0 + 1;
			let mut swaps = Vec::new();
			for input_commit in &tx.inputs_committed() {
				if let Ok(swap) = locked_store.get_swap(&input_commit) {
					if swap.route.is_some() {
						return Ok(None);
					}
					if self.async_is_spendable(next_block_height, &swap).await {
						swaps.push(swap);
					}
				}
			}

			self.async_execute_round(&locked_store, swaps).await
		} else {
			Err(SwapError::SwapTxNotFound(excess))
		}
	}
}

fn submission(swap: &SwapData) -> SwapSubmission {
	let route = swap.route.as_ref().unwrap();
	let (status, kernel_excess) = match swap.status {
		SwapStatus::Unprocessed => (SwapSubmissionStatus::Accepted, None),
		SwapStatus::Batched => (SwapSubmissionStatus::Batched, None),
		SwapStatus::Posting { kernel_commit } => {
			(SwapSubmissionStatus::Posting, Some(kernel_commit.to_hex()))
		}
		SwapStatus::InProcess { kernel_commit } => {
			(SwapSubmissionStatus::Posted, Some(kernel_commit.to_hex()))
		}
		SwapStatus::Completed { kernel_commit, .. } => (
			SwapSubmissionStatus::Confirmed,
			Some(kernel_commit.to_hex()),
		),
		SwapStatus::Failed => (SwapSubmissionStatus::Rejected, None),
		SwapStatus::Cancelled => (SwapSubmissionStatus::Cancelled, None),
		SwapStatus::Expired => (SwapSubmissionStatus::Expired, None),
	};
	SwapSubmission {
		route_id: route.route_id,
		wallet_request_id: route.wallet_request_id,
		swap_req_hash: route.swap_req_hash,
		status,
		kernel_excess,
	}
}

#[cfg(test)]
pub mod mock {
	use super::grin_onion;
	use std::collections::HashMap;
	use std::sync::Arc;

	use async_trait::async_trait;
	use grin_core::core::Transaction;

	use grin_onion::crypto::comsig::ComSignature;
	use grin_onion::onion::Onion;

	use super::{SwapError, SwapServer};

	pub struct MockSwapServer {
		errors: HashMap<Onion, SwapError>,
	}

	impl MockSwapServer {
		pub fn new() -> MockSwapServer {
			MockSwapServer {
				errors: HashMap::new(),
			}
		}

		pub fn set_response(&mut self, onion: &Onion, e: SwapError) {
			self.errors.insert(onion.clone(), e);
		}
	}

	#[async_trait]
	impl SwapServer for MockSwapServer {
		async fn swap(&self, onion: &Onion, _comsig: &ComSignature) -> Result<(), SwapError> {
			if let Some(e) = self.errors.get(&onion) {
				return Err(e.clone());
			}

			Ok(())
		}

		async fn execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError> {
			Ok(None)
		}

		async fn check_reorg(
			&self,
			tx: &Arc<Transaction>,
		) -> Result<Option<Arc<Transaction>>, SwapError> {
			Ok(Some(tx.clone()))
		}
	}
}

#[cfg(test)]
pub mod test_util {
	use super::grin_onion;
	use std::sync::Arc;

	use grin_onion::crypto::dalek::DalekPublicKey;
	use grin_onion::crypto::secp::SecretKey;

	use crate::config;
	use crate::mix_client::MixClient;
	use crate::node::GrinNode;
	use crate::servers::swap::SwapServerImpl;
	use crate::store::SwapStore;
	use crate::wallet::mock::MockWallet;

	pub fn new_swapper(
		test_dir: &str,
		server_key: &SecretKey,
		next_server: Option<(&DalekPublicKey, &Arc<dyn MixClient>)>,
		node: Arc<dyn GrinNode>,
	) -> (Arc<SwapServerImpl>, Arc<MockWallet>) {
		let config =
			config::test_util::local_config(&server_key, &None, &next_server.map(|n| n.0.clone()))
				.unwrap();

		let wallet = Arc::new(MockWallet::new());
		let store = SwapStore::new(test_dir).unwrap();
		let swap_server = Arc::new(SwapServerImpl::new(
			config,
			next_server.map(|n| n.1.clone()),
			Some(wallet.clone()),
			node,
			store,
		));

		(swap_server, wallet)
	}
}

#[cfg(test)]
mod tests {
	use super::grin_onion;
	use std::sync::Arc;

	use ::function_name::named;
	use grin_core::core::{
		Committed, Input, Inputs, Output, OutputFeatures, Transaction, Weighting,
	};
	use secp256k1zkp::key::ZERO_KEY;
	use x25519_dalek::PublicKey as xPublicKey;

	use grin_onion::crypto::comsig::ComSignature;
	use grin_onion::crypto::secp;
	use grin_onion::onion::Onion;
	use grin_onion::test_util as onion_test_util;
	use grin_onion::{create_onion, new_hop, Hop};

	use crate::mix_client::{self, MixClient};
	use crate::node::mock::MockGrinNode;
	use crate::servers::mix_rpc::MixResp;
	use crate::servers::swap::{SwapError, SwapServer};
	use crate::store::{RouteSwapData, SwapData, SwapStatus};
	use crate::tx;
	use crate::tx::TxComponents;

	macro_rules! assert_error_type {
		($result:expr, $error_type:pat) => {
			assert!($result.is_err());
			assert!(if let $error_type = $result.unwrap_err() {
				true
			} else {
				false
			});
		};
	}

	macro_rules! init_test {
		() => {{
			grin_core::global::set_local_chain_type(
				grin_core::global::ChainTypes::AutomatedTesting,
			);
			let test_dir = concat!("./target/tmp/.", function_name!());
			let _ = std::fs::remove_dir_all(test_dir);
			test_dir
		}};
	}

	#[test]
	fn route_mix_indices_are_ordered_unique_and_bounded() {
		assert!(super::valid_mix_indices(&[0, 2], 3));
		assert!(!super::valid_mix_indices(&[0, 0], 2));
		assert!(!super::valid_mix_indices(&[1, 0], 2));
		assert!(!super::valid_mix_indices(&[0, 2], 2));
	}

	/// Standalone swap server to demonstrate request validation and onion unwrapping.
	#[tokio::test]
	#[named]
	async fn swap_standalone() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (output_commit, proof) = onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop.clone()], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		server.swap(&onion, &comsig).await?;

		// Make sure entry is added to server.
		let expected = SwapData {
			excess: hop_excess.clone(),
			output_commit: output_commit.clone(),
			rangeproof: Some(proof),
			input: Input::new(OutputFeatures::Plain, input_commit.clone()),
			fee: fee as u64,
			onion: Onion {
				ephemeral_pubkey: xPublicKey::from([0u8; 32]),
				commit: output_commit.clone(),
				enc_payloads: vec![],
			},
			status: SwapStatus::Unprocessed,
			route: None,
		};

		{
			let store = server.store.lock().await;
			assert_eq!(1, store.swaps_iter().unwrap().count());
			assert!(store.swap_exists(&input_commit).unwrap());
			assert_eq!(expected, store.get_swap(&input_commit).unwrap());
		}

		let tx = server.execute_round().await?;
		assert!(tx.is_some());

		{
			// check that status was updated
			let store = server.store.lock().await;
			assert!(match store.get_swap(&input_commit)?.status {
				SwapStatus::InProcess { kernel_commit } =>
					kernel_commit == tx.unwrap().kernels().first().unwrap().excess,
				_ => false,
			});
		}

		// check that the transaction was posted
		let posted_txns = node.get_posted_txns();
		assert_eq!(posted_txns.len(), 1);
		let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
		assert!(posted_txn.inputs_committed().contains(&input_commit));
		assert!(posted_txn.outputs_committed().contains(&output_commit));
		// todo: check that outputs also contain the commitment generated by our wallet

		posted_txn.validate(Weighting::AsTransaction)?;

		Ok(())
	}

	/// Spent swaps are skipped when executing a round.
	#[tokio::test]
	#[named]
	async fn spent_swap_skipped() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;
		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (output_commit, proof) = onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));
		let onion = create_onion(&input_commit, &vec![hop], false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new());
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		server.store.lock().await.save_swap(
			&SwapData {
				excess: hop_excess,
				output_commit,
				rangeproof: Some(proof),
				input: Input::new(OutputFeatures::Plain, input_commit),
				fee: fee as u64,
				onion: onion.peel_layer(&server_key)?.onion,
				status: SwapStatus::Unprocessed,
				route: None,
			},
			false,
		)?;

		assert!(server.execute_round().await?.is_none());
		assert!(node.get_posted_txns().is_empty());

		Ok(())
	}

	/// Multi-server test to verify proper MixClient communication.
	#[tokio::test]
	#[named]
	async fn swap_multiserver() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let test_dir = init_test!();

		// Setup input
		let value: u64 = 200_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;
		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));

		// Swapper data
		let swap_fee: u32 = 50_000_000;
		let (swap_sk, _swap_pk) = onion_test_util::rand_keypair();
		let swap_hop_excess = secp::random_secret(false);
		let swap_hop = new_hop(&swap_sk, &swap_hop_excess, swap_fee, None);

		// Mixer data
		let mixer_fee: u32 = 30_000_000;
		let (mixer_sk, mixer_pk) = onion_test_util::rand_keypair();
		let mixer_hop_excess = secp::random_secret(false);
		let (output_commit, proof) = onion_test_util::proof(
			value,
			swap_fee + mixer_fee,
			&blind,
			&vec![&swap_hop_excess, &mixer_hop_excess],
		);
		let mixer_hop = new_hop(&mixer_sk, &mixer_hop_excess, mixer_fee, Some(proof));

		// Create onion
		let onion = create_onion(&input_commit, &vec![swap_hop, mixer_hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		// Mock mixer
		let mixer_onion = onion.peel_layer(&swap_sk)?.onion;
		let mut mock_mixer = mix_client::mock::MockMixClient::new();
		let mixer_response = TxComponents {
			offset: ZERO_KEY,
			outputs: vec![Output::new(
				OutputFeatures::Plain,
				output_commit.clone(),
				proof.clone(),
			)],
			kernels: vec![tx::build_kernel(&mixer_hop_excess, mixer_fee as u64)?],
		};
		mock_mixer.set_response(
			&vec![mixer_onion.clone()],
			MixResp {
				version: None,
				msg_type: None,
				batch_id: None,
				indices: vec![0 as usize],
				components: mixer_response,
			},
		);

		let mixer: Arc<dyn MixClient> = Arc::new(mock_mixer);
		let (swapper, _) = super::test_util::new_swapper(
			&test_dir,
			&swap_sk,
			Some((&mixer_pk, &mixer)),
			node.clone(),
		);
		swapper.swap(&onion, &comsig).await?;

		let tx = swapper.execute_round().await?;
		assert!(tx.is_some());

		// check that the transaction was posted
		let posted_txns = node.get_posted_txns();
		assert_eq!(posted_txns.len(), 1);
		let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
		assert!(posted_txn.inputs_committed().contains(&input_commit));
		assert!(posted_txn.outputs_committed().contains(&output_commit));
		// todo: check that outputs also contain the commitment generated by our wallet

		posted_txn.validate(Weighting::AsTransaction)?;

		Ok(())
	}

	/// Returns InvalidPayloadLength when too many payloads are provided.
	#[tokio::test]
	#[named]
	async fn swap_too_many_payloads() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let hops: Vec<Hop> = vec![hop.clone(), hop.clone()]; // Multiple payloads
		let onion = create_onion(&input_commit, &hops, false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(Err(SwapError::InvalidPayloadLength), result);

		// Make sure no entry is added to the store
		assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

		Ok(())
	}

	#[tokio::test]
	#[named]
	async fn route_payload_count_uses_manifest() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();
		let value = 200_000_000;
		let fee = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;
		let server_key = secp::random_secret(false);
		let server_excess = secp::random_secret(false);
		let mixer_key = secp::random_secret(false);
		let mixer_excess = secp::random_secret(false);
		let (_, proof) =
			onion_test_util::proof(value, fee * 2, &blind, &vec![&server_excess, &mixer_excess]);
		let hops = vec![
			new_hop(&server_key, &server_excess, fee, None),
			new_hop(&mixer_key, &mixer_excess, fee, Some(proof)),
		];
		let onion = create_onion(&input_commit, &hops, false)?;
		let signed_message = onion.serialize()?;
		let comsig = ComSignature::sign(value, &blind, &signed_message, false)?;
		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let route = RouteSwapData {
			route_id: mwixnet_protocol::Hash([1; 32]),
			manifest_sequence: 1,
			wallet_request_id: mwixnet_protocol::Hash([2; 32]),
			swap_req_hash: mwixnet_protocol::Hash([3; 32]),
			expires_at_height: 60,
			batch_id: None,
			batch_position: None,
			mix_req_hash: None,
			cancelled_at: None,
			cancel_req_hash: None,
		};

		assert!(server
			.prepare_swap(
				&onion,
				&comsig,
				signed_message,
				Some(route.clone()),
				Some(2)
			)
			.await
			.is_ok());
		assert_eq!(
			server
				.prepare_swap(&onion, &comsig, onion.serialize()?, Some(route), Some(3))
				.await,
			Err(SwapError::InvalidPayloadLength)
		);

		Ok(())
	}

	/// Returns InvalidComSignature when ComSignature fails to verify.
	#[tokio::test]
	#[named]
	async fn swap_invalid_com_signature() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop], false)?;

		let wrong_blind = secp::random_secret(false);
		let comsig = ComSignature::sign(value, &wrong_blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(Err(SwapError::InvalidComSignature), result);

		// Make sure no entry is added to the store
		assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

		Ok(())
	}

	/// Returns InvalidRangeProof when the rangeproof fails to verify for the commitment.
	#[tokio::test]
	#[named]
	async fn swap_invalid_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let wrong_value = value + 10_000_000;
		let (_output_commit, proof) =
			onion_test_util::proof(wrong_value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(Err(SwapError::InvalidRangeproof), result);

		// Make sure no entry is added to the store
		assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

		Ok(())
	}

	/// Returns MissingRangeproof when no rangeproof is provided.
	#[tokio::test]
	#[named]
	async fn swap_missing_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let hop = new_hop(&server_key, &hop_excess, fee, None);

		let onion = create_onion(&input_commit, &vec![hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(Err(SwapError::MissingRangeproof), result);

		// Make sure no entry is added to the store
		assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

		Ok(())
	}

	/// Returns CoinNotFound when there's no matching output in the UTXO set.
	#[tokio::test]
	#[named]
	async fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new());
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(
			Err(SwapError::CoinNotFound {
				commit: input_commit.clone()
			}),
			result
		);

		// Make sure no entry is added to the store
		assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

		Ok(())
	}

	/// Returns AlreadySwapped when trying to swap the same commitment multiple times.
	#[tokio::test]
	#[named]
	async fn swap_already_swapped() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		server.swap(&onion, &comsig).await?;

		// Call swap a second time
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(
			Err(SwapError::AlreadySwapped {
				commit: input_commit.clone()
			}),
			result
		);

		Ok(())
	}

	/// Returns SwapTxNotFound when trying to check_reorg with a transaction not found in the store.
	#[tokio::test]
	#[named]
	async fn swap_tx_not_found() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let server_key = secp::random_secret(false);
		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new());
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let kern = tx::build_kernel(&secp::random_secret(false), 1000u64)?;
		let tx: Arc<Transaction> =
			Arc::new(Transaction::new(Inputs::default(), &[], &[kern.clone()]));
		let result = server.check_reorg(&tx).await;
		assert_eq!(Err(SwapError::SwapTxNotFound(kern.excess())), result);

		Ok(())
	}

	/// Returns PeelOnionFailure when a failure occurs trying to decrypt the onion payload.
	#[tokio::test]
	#[named]
	async fn swap_peel_onion_failure() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);

		let wrong_server_key = secp::random_secret(false);
		let hop = new_hop(&wrong_server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;

		assert!(result.is_err());
		assert_error_type!(result, SwapError::PeelOnionFailure(_));

		Ok(())
	}

	/// Returns FeeTooLow when the minimum fee is not met.
	#[tokio::test]
	#[named]
	async fn swap_fee_too_low() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 1_000_000;
		let blind = secp::random_secret(false);
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret(false);
		let hop_excess = secp::random_secret(false);
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop], false)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?, false)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig).await;
		assert_eq!(
			Err(SwapError::FeeTooLow {
				minimum_fee: 12_500_000,
				actual_fee: fee as u64,
			}),
			result
		);

		Ok(())
	}
}
