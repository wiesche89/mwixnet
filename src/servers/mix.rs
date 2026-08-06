use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use grin_core::core::{Output, OutputFeatures, TransactionBody};
use grin_core::ser;
use grin_core::ser::ProtocolVersion;
use itertools::Itertools;
use thiserror::Error;

use grin_onion::crypto::dalek::{self, DalekSignature};
use grin_onion::onion::{Onion, OnionError, PeeledOnion};
use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use secp256k1zkp::key::ZERO_KEY;
use secp256k1zkp::Secp256k1;

use crate::config::ServerConfig;
use crate::mix_client::MixClient;
use crate::node::{self, GrinNode};
use crate::servers::mix_rpc::{MixResp, RouteMixReq};
use crate::tx::{self, TxComponents};
use crate::wallet::Wallet;

fn filter_by_indices<'a, T>(
	items: &'a [(usize, T)],
	kept_indices: &HashSet<usize>,
) -> Vec<&'a (usize, T)> {
	items
		.iter()
		.enumerate()
		.filter(|(i, _)| kept_indices.contains(i))
		.map(|(_, item)| item)
		.collect()
}

/// Mixer error types
#[derive(Error, Debug)]
pub enum MixError {
	#[error("{0}")]
	Protocol(mwixnet_protocol::ProtocolRpcError),
	#[error("Invalid number of payloads provided")]
	InvalidPayloadLength,
	#[error("Signature is invalid")]
	InvalidSignature,
	#[error("Rangeproof is invalid")]
	InvalidRangeproof,
	#[error("Rangeproof is required but was not supplied")]
	MissingRangeproof,
	#[error("Failed to peel onion layer: {0:?}")]
	PeelOnionFailure(OnionError),
	#[error("Fee too low (expected >= {minimum_fee:?}, actual {actual_fee:?})")]
	FeeTooLow { minimum_fee: u64, actual_fee: u64 },
	#[error("None of the outputs could be mixed")]
	NoValidOutputs,
	#[error("Dalek error: {0:?}")]
	Dalek(dalek::DalekError),
	#[error("Secp error: {0:?}")]
	Secp(grin_util::secp::Error),
	#[error("Error building transaction: {0:?}")]
	TxError(tx::TxError),
	#[error("Wallet error: {0:?}")]
	WalletError(crate::wallet::WalletError),
	#[error("Client comm error: {0:?}")]
	Client(crate::mix_client::MixClientError),
}

/// An internal MWixnet server - a "Mixer"
#[async_trait]
pub trait MixServer: Send + Sync {
	/// Swaps the outputs provided and returns the final swapped outputs and kernels.
	async fn mix_outputs(
		&self,
		onions: &Vec<Onion>,
		sig: &DalekSignature,
	) -> Result<MixResp, MixError>;

	async fn route_mix(
		&self,
		_request: &RouteMixReq,
		_predecessor: &grin_onion::crypto::dalek::DalekPublicKey,
		_next_server: Option<Arc<dyn MixClient>>,
	) -> Result<MixResp, MixError> {
		Err(MixError::InvalidSignature)
	}
}

/// The standard MWixnet "Mixer" implementation
#[derive(Clone)]
pub struct MixServerImpl {
	secp: Secp256k1,
	server_config: ServerConfig,
	mix_client: Option<Arc<dyn MixClient>>,
	wallet: Option<Arc<dyn Wallet>>,
	node: Arc<dyn GrinNode>,
}

impl MixServerImpl {
	/// Create a new 'Mix' server
	pub fn new(
		server_config: ServerConfig,
		mix_client: Option<Arc<dyn MixClient>>,
		wallet: Option<Arc<dyn Wallet>>,
		node: Arc<dyn GrinNode>,
	) -> Self {
		MixServerImpl {
			secp: Secp256k1::new(),
			server_config,
			mix_client,
			wallet,
			node,
		}
	}

	fn get_fee_base(&self) -> u64 {
		self.server_config.accept_fee_base
	}

	/// Minimum fee to perform a mix.
	/// Requires enough fee for the mixer's kernel.
	pub(crate) fn get_minimum_mix_fee(&self) -> u64 {
		TransactionBody::weight_by_iok(0, 0, 1) * self.get_fee_base()
	}

	fn peel_onion(&self, onion: &Onion, has_next: bool) -> Result<PeeledOnion, MixError> {
		// Verify that more than 1 payload exists when there's a next server,
		// or that exactly 1 payload exists when this is the final server
		if has_next && onion.enc_payloads.len() <= 1 || !has_next && onion.enc_payloads.len() != 1 {
			return Err(MixError::InvalidPayloadLength);
		}

		// Peel the top layer
		let peeled = onion
			.peel_layer(&self.server_config.key)
			.map_err(|e| MixError::PeelOnionFailure(e))?;

		// Verify the fee meets the minimum
		let fee: u64 = peeled.payload.fee.into();
		if fee < self.get_minimum_mix_fee() {
			return Err(MixError::FeeTooLow {
				minimum_fee: self.get_minimum_mix_fee(),
				actual_fee: fee,
			});
		}

		if let Some(r) = peeled.payload.rangeproof {
			// Verify the bullet proof
			self.secp
				.verify_bullet_proof(peeled.onion.commit, r, None)
				.map_err(|_| MixError::InvalidRangeproof)?;
		} else if peeled.onion.enc_payloads.is_empty() {
			// A rangeproof is required in the last payload
			return Err(MixError::MissingRangeproof);
		}

		Ok(peeled)
	}

	async fn async_build_final_outputs(
		&self,
		peeled: &Vec<(usize, PeeledOnion)>,
		route: Option<(mwixnet_protocol::Hash, u64, mwixnet_protocol::Hash)>,
	) -> Result<MixResp, MixError> {
		// Filter out commitments that already exist in the UTXO set
		let filtered: Vec<&(usize, PeeledOnion)> = stream::iter(peeled.iter())
			.filter(|(_, p)| async {
				!node::async_is_unspent(&self.node, &p.onion.commit)
					.await
					.unwrap_or(true)
			})
			.collect()
			.await;

		// Build plain outputs for each mix entry
		let outputs: Vec<Output> = filtered
			.iter()
			.map(|(_, p)| {
				Output::new(
					OutputFeatures::Plain,
					p.onion.commit,
					p.payload.rangeproof.unwrap(),
				)
			})
			.collect();

		let fees_paid = filtered.iter().map(|(_, p)| p.payload.fee.fee()).sum();
		let output_excesses = filtered
			.iter()
			.map(|(_, p)| p.payload.excess.clone())
			.collect();

		let components = tx::async_assemble_components(
			self.wallet.as_ref(),
			&TxComponents {
				offset: ZERO_KEY,
				kernels: Vec::new(),
				outputs,
			},
			&output_excesses,
			self.get_fee_base(),
			fees_paid,
		)
		.await
		.map_err(MixError::TxError)?;

		let indices = filtered.iter().map(|(i, _)| *i).collect();

		Ok(MixResp {
			version: route.map(|_| mwixnet_protocol::MWIXNET_PROTOCOL_VERSION),
			msg_type: route.map(|_| mwixnet_protocol::MwixnetType::MixResp),
			batch_id: route.map(|(_, _, batch_id)| batch_id),
			indices,
			components,
		})
	}

	async fn call_next_mixer(
		&self,
		peeled: &Vec<(usize, PeeledOnion)>,
		route: Option<(mwixnet_protocol::Hash, u64, mwixnet_protocol::Hash)>,
		next_server: &dyn MixClient,
	) -> Result<MixResp, MixError> {
		// Sort by commitment
		let mut onions_with_index = peeled.clone();
		onions_with_index
			.sort_by(|(_, a), (_, b)| a.onion.commit.partial_cmp(&b.onion.commit).unwrap());

		// Call next server
		let onions = onions_with_index
			.iter()
			.map(|(_, p)| p.onion.clone())
			.collect();
		let mixed = match route {
			Some((route_id, manifest_sequence, batch_id)) => next_server
				.mix_route(route_id, manifest_sequence, batch_id, &onions)
				.await
				.map_err(MixError::Client)?,
			None => next_server
				.mix_outputs(&onions)
				.await
				.map_err(MixError::Client)?,
		};
		if let Some((_, _, batch_id)) = route {
			if mixed.version != Some(mwixnet_protocol::MWIXNET_PROTOCOL_VERSION)
				|| mixed.msg_type != Some(mwixnet_protocol::MwixnetType::MixResp)
				|| mixed.batch_id != Some(batch_id)
				|| mixed.indices.windows(2).any(|pair| pair[0] >= pair[1])
				|| mixed.indices.iter().any(|index| *index >= onions.len())
				|| mixed.components.outputs.len() != mixed.indices.len()
				|| (mixed.indices.is_empty() && !mixed.components.kernels.is_empty())
			{
				return Err(MixError::Protocol(mwixnet_protocol::ProtocolRpcError::new(
					mwixnet_protocol::ProtocolErrorCode::InvalidMwixnetMessage,
					"invalid route mix response",
				)));
			}
		}

		// Remove filtered entries
		let kept_next_indices = HashSet::<_>::from_iter(mixed.indices.clone());
		let filtered_onions = filter_by_indices(&onions_with_index, &kept_next_indices);

		// Calculate excess of entries kept
		let excesses = filtered_onions
			.iter()
			.map(|(_, p)| p.payload.excess.clone())
			.collect();

		// Calculate total fee of entries kept
		let fees_paid = filtered_onions
			.iter()
			.fold(0, |f, (_, p)| f + p.payload.fee.fee());

		let indices = filtered_onions.iter().map(|(i, _)| *i).sorted().collect();

		let components = tx::async_assemble_components(
			self.wallet.as_ref(),
			&mixed.components,
			&excesses,
			self.get_fee_base(),
			fees_paid,
		)
		.await
		.map_err(MixError::TxError)?;

		Ok(MixResp {
			version: route.map(|_| mwixnet_protocol::MWIXNET_PROTOCOL_VERSION),
			msg_type: route.map(|_| mwixnet_protocol::MwixnetType::MixResp),
			batch_id: route.map(|(_, _, batch_id)| batch_id),
			indices,
			components,
		})
	}

	async fn process_onions(
		&self,
		onions: &Vec<Onion>,
		route: Option<(mwixnet_protocol::Hash, u64, mwixnet_protocol::Hash)>,
		next_server: Option<Arc<dyn MixClient>>,
	) -> Result<MixResp, MixError> {
		let has_next = next_server.is_some();
		let mut peeled: Vec<(usize, PeeledOnion)> = onions
			.iter()
			.enumerate()
			.filter_map(|(i, onion)| match self.peel_onion(onion, has_next) {
				Ok(peeled) => Some((i, peeled)),
				Err(error) => {
					println!("Error peeling onion: {:?}", error);
					None
				}
			})
			.collect();
		peeled.sort_by_key(|(_, onion)| onion.onion.commit);
		peeled.dedup_by_key(|(_, onion)| onion.onion.commit);
		peeled.sort_by_key(|(index, _)| *index);
		if peeled.is_empty() {
			return match route {
				Some((_, _, batch_id)) => Ok(MixResp {
					version: Some(mwixnet_protocol::MWIXNET_PROTOCOL_VERSION),
					msg_type: Some(mwixnet_protocol::MwixnetType::MixResp),
					batch_id: Some(batch_id),
					indices: Vec::new(),
					components: TxComponents {
						offset: ZERO_KEY,
						kernels: Vec::new(),
						outputs: Vec::new(),
					},
				}),
				None => Err(MixError::NoValidOutputs),
			};
		}
		if let Some(next_server) = next_server {
			self.call_next_mixer(&peeled, route, next_server.as_ref())
				.await
		} else {
			self.async_build_final_outputs(&peeled, route).await
		}
	}
}

#[async_trait]
impl MixServer for MixServerImpl {
	async fn mix_outputs(
		&self,
		onions: &Vec<Onion>,
		sig: &DalekSignature,
	) -> Result<MixResp, MixError> {
		// Verify Signature
		let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
		sig.verify(
			self.server_config.prev_server.as_ref().unwrap(),
			serialized.as_slice(),
		)
		.map_err(|_| MixError::InvalidSignature)?;

		self.process_onions(onions, None, self.mix_client.clone())
			.await
	}

	async fn route_mix(
		&self,
		request: &RouteMixReq,
		predecessor: &grin_onion::crypto::dalek::DalekPublicKey,
		next_server: Option<Arc<dyn MixClient>>,
	) -> Result<MixResp, MixError> {
		request
			.sig
			.verify(predecessor, &request.hash().0)
			.map_err(|_| MixError::InvalidSignature)?;
		self.process_onions(
			&request.onions,
			Some((
				request.route_id,
				request.manifest_sequence,
				request.batch_id,
			)),
			next_server,
		)
		.await
	}
}

#[cfg(test)]
mod test_util {
	use super::grin_onion;
	use std::sync::Arc;

	use grin_onion::crypto::dalek::DalekPublicKey;
	use secp256k1zkp::SecretKey;

	use crate::config;
	use crate::mix_client::test_util::DirectMixClient;
	use crate::mix_client::MixClient;
	use crate::node::mock::MockGrinNode;
	use crate::servers::mix::MixServerImpl;
	use crate::wallet::mock::MockWallet;

	pub fn new_mixer(
		server_key: &SecretKey,
		prev_server: (&SecretKey, &DalekPublicKey),
		next_server: &Option<(DalekPublicKey, Arc<dyn MixClient>)>,
		node: &Arc<MockGrinNode>,
	) -> (Arc<DirectMixClient>, Arc<MockWallet>) {
		let config = config::test_util::local_config(
			&server_key,
			&Some(prev_server.1.clone()),
			&next_server.as_ref().map(|(k, _)| k.clone()),
		)
		.unwrap();

		let wallet = Arc::new(MockWallet::new());
		let mix_server = Arc::new(MixServerImpl::new(
			config,
			next_server.as_ref().map(|(_, c)| c.clone()),
			Some(wallet.clone()),
			node.clone(),
		));
		let client = Arc::new(DirectMixClient {
			key: prev_server.0.clone(),
			mix_server: mix_server.clone(),
		});

		(client, wallet)
	}
}

#[cfg(test)]
mod tests {
	use super::grin_onion;
	use std::collections::HashSet;
	use std::sync::Arc;

	use ::function_name::named;

	use grin_onion::crypto::dalek::DalekPublicKey;
	use grin_onion::crypto::secp::{self, Commitment};
	use grin_onion::test_util as onion_test_util;
	use grin_onion::{create_onion, new_hop, Hop};
	use secp256k1zkp::pedersen::RangeProof;
	use secp256k1zkp::SecretKey;

	use crate::mix_client::MixClient;
	use crate::node::mock::MockGrinNode;

	macro_rules! init_test {
		() => {{
			grin_core::global::set_local_chain_type(
				grin_core::global::ChainTypes::AutomatedTesting,
			);
			let db_root = concat!("./target/tmp/.", function_name!());
			let _ = std::fs::remove_dir_all(db_root);
			()
		}};
	}

	struct ServerVars {
		fee: u32,
		sk: SecretKey,
		pk: DalekPublicKey,
		excess: SecretKey,
	}

	impl ServerVars {
		fn new(fee: u32) -> Self {
			let (sk, pk) = onion_test_util::rand_keypair();
			let excess = secp::random_secret(false);
			ServerVars {
				fee,
				sk,
				pk,
				excess,
			}
		}

		fn build_hop(&self, proof: Option<RangeProof>) -> Hop {
			new_hop(&self.sk, &self.excess, self.fee, proof)
		}
	}

	#[test]
	fn filters_mixed_indices() {
		let items = vec![(1, "first"), (0, "second")];
		let kept = HashSet::from([0]);
		assert_eq!(super::filter_by_indices(&items, &kept), vec![&items[0]]);

		let kept = HashSet::from([1]);
		assert_eq!(super::filter_by_indices(&items, &kept), vec![&items[1]]);
	}

	/// Tests the happy path for a 3 server setup.
	///
	/// Servers:
	/// * Swap Server - Simulated by test
	/// * Mixer 1 - Internal MixServerImpl directly called by test
	/// * Mixer 2 - Final MixServerImpl called by Mixer 1
	#[tokio::test]
	#[named]
	async fn mix_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
		init_test!();

		// Setup Input(s)
		let input1_value: u64 = 200_000_000;
		let input1_blind = secp::random_secret(false);
		let input1_commit = secp::commit(input1_value, &input1_blind)?;
		let input_commits = vec![&input1_commit];

		// Setup Servers
		let (swap_vars, mix1_vars, mix2_vars) = (
			ServerVars::new(50_000_000),
			ServerVars::new(50_000_000),
			ServerVars::new(50_000_000),
		);

		let node = Arc::new(MockGrinNode::new_with_utxos(&input_commits));
		let (mixer2_client, mixer2_wallet) = super::test_util::new_mixer(
			&mix2_vars.sk,
			(&mix1_vars.sk, &mix1_vars.pk),
			&None,
			&node,
		);

		let (mixer1_client, mixer1_wallet) = super::test_util::new_mixer(
			&mix1_vars.sk,
			(&swap_vars.sk, &swap_vars.pk),
			&Some((mix2_vars.pk.clone(), mixer2_client.clone())),
			&node,
		);

		// Build rangeproof
		let (output_commit, proof) = onion_test_util::proof(
			input1_value,
			swap_vars.fee + mix1_vars.fee + mix2_vars.fee,
			&input1_blind,
			&vec![&swap_vars.excess, &mix1_vars.excess, &mix2_vars.excess],
		);

		// Create Onion
		let onion = create_onion(
			&input1_commit,
			&vec![
				swap_vars.build_hop(None),
				mix1_vars.build_hop(None),
				mix2_vars.build_hop(Some(proof)),
			],
			false,
		)?;

		// Simulate the swap server peeling the onion and then calling mix1
		let mix1_onion = onion.peel_layer(&swap_vars.sk)?;
		let mixed = mixer1_client
			.mix_outputs(&vec![mix1_onion.onion.clone()])
			.await?;

		// Verify 3 outputs are returned: mixed output, mixer1's output, and mixer2's output
		assert_eq!(mixed.indices, vec![0 as usize]);
		assert_eq!(mixed.components.outputs.len(), 3);
		let output_commits: HashSet<Commitment> = mixed
			.components
			.outputs
			.iter()
			.map(|o| o.identifier.commit.clone())
			.collect();
		assert!(output_commits.contains(&output_commit));

		assert_eq!(mixer1_wallet.built_outputs().len(), 1);
		assert!(output_commits.contains(mixer1_wallet.built_outputs().get(0).unwrap()));

		assert_eq!(mixer2_wallet.built_outputs().len(), 1);
		assert!(output_commits.contains(mixer2_wallet.built_outputs().get(0).unwrap()));

		Ok(())
	}
}
