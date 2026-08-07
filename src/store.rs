use grin_core::core::hash::Hash;
use grin_core::core::{Input, Transaction};
use grin_core::ser::{
	self, DeserializationMode, ProtocolVersion, Readable, Reader, Writeable, Writer,
};
use grin_store::{self as store, Store};
use grin_util::ToHex;
use thiserror::Error;

use crate::servers::mix_rpc::{MixResp, RouteMixReq};
use grin_onion::crypto::secp::{self, Commitment, RangeProof, SecretKey};
use grin_onion::onion::Onion;
use grin_onion::util::{read_optional, write_optional};
use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use mwixnet_protocol::{
	Hash as MwixnetHash, HealthChallenge, HealthRequest, HealthResponse, MwixnetOffer,
	RouteAcceptance, RouteHealthProof, RouteManifest, RouteProposal, RouteState,
};
use serde::{Deserialize, Serialize};

const DB_NAME: &str = "swap";
const STORE_SUBPATH: &str = "swaps";

const CURRENT_SWAP_VERSION: u8 = 1;
const SWAP_PREFIX: u8 = b'S';
const REQUEST_PREFIX: u8 = b'Q';

const CURRENT_TX_VERSION: u8 = 0;
const TX_PREFIX: u8 = b'T';

const OFFER_PREFIX: u8 = b'O';
const PROPOSAL_PREFIX: u8 = b'P';
const ROUTE_PREFIX: u8 = b'R';
const HEALTH_PREFIX: u8 = b'H';
const BATCH_PREFIX: u8 = b'B';

/// Swap statuses
#[derive(Clone, Debug, PartialEq)]
pub enum SwapStatus {
	Unprocessed,
	Batched,
	Posting {
		kernel_commit: Commitment,
	},
	InProcess {
		kernel_commit: Commitment,
	},
	Completed {
		kernel_commit: Commitment,
		block_hash: Hash,
	},
	Failed,
	Cancelled,
	Expired,
}

impl Writeable for SwapStatus {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			SwapStatus::Unprocessed => {
				writer.write_u8(0)?;
			}
			SwapStatus::InProcess { kernel_commit } => {
				writer.write_u8(1)?;
				kernel_commit.write(writer)?;
			}
			SwapStatus::Completed {
				kernel_commit,
				block_hash,
			} => {
				writer.write_u8(2)?;
				kernel_commit.write(writer)?;
				block_hash.write(writer)?;
			}
			SwapStatus::Failed => {
				writer.write_u8(3)?;
			}
			SwapStatus::Batched => writer.write_u8(4)?,
			SwapStatus::Posting { kernel_commit } => {
				writer.write_u8(5)?;
				kernel_commit.write(writer)?;
			}
			SwapStatus::Cancelled => writer.write_u8(6)?,
			SwapStatus::Expired => writer.write_u8(7)?,
		};

		Ok(())
	}
}

impl Readable for SwapStatus {
	fn read<R: Reader>(reader: &mut R) -> Result<SwapStatus, ser::Error> {
		let status = match reader.read_u8()? {
			0 => SwapStatus::Unprocessed,
			1 => {
				let kernel_commit = Commitment::read(reader)?;
				SwapStatus::InProcess { kernel_commit }
			}
			2 => {
				let kernel_commit = Commitment::read(reader)?;
				let block_hash = Hash::read(reader)?;
				SwapStatus::Completed {
					kernel_commit,
					block_hash,
				}
			}
			3 => SwapStatus::Failed,
			4 => SwapStatus::Batched,
			5 => SwapStatus::Posting {
				kernel_commit: Commitment::read(reader)?,
			},
			6 => SwapStatus::Cancelled,
			7 => SwapStatus::Expired,
			_ => {
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(status)
	}
}

/// Data needed to swap a single output.
#[derive(Clone, Debug, PartialEq)]
pub struct SwapData {
	/// The total excess for the output commitment
	pub excess: SecretKey,
	/// The derived output commitment after applying excess and fee
	pub output_commit: Commitment,
	/// The rangeproof, included only for the final hop (node N)
	pub rangeproof: Option<RangeProof>,
	/// Transaction input being spent
	pub input: Input,
	/// Transaction fee
	pub fee: u64,
	/// The remaining onion after peeling off our layer
	pub onion: Onion,
	/// The status of the swap
	pub status: SwapStatus,
	/// Route request metadata, absent for legacy submissions.
	pub route: Option<RouteSwapData>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RouteSwapData {
	pub route_id: MwixnetHash,
	pub manifest_sequence: u64,
	pub wallet_request_id: MwixnetHash,
	pub swap_req_hash: MwixnetHash,
	pub expires_at_height: u64,
	pub batch_id: Option<MwixnetHash>,
	pub batch_position: Option<u16>,
	pub mix_req_hash: Option<MwixnetHash>,
	pub cancelled_at: Option<u64>,
	pub cancel_req_hash: Option<MwixnetHash>,
}

fn write_mwixnet_hash<W: Writer>(
	writer: &mut W,
	value: Option<MwixnetHash>,
) -> Result<(), ser::Error> {
	match value {
		Some(value) => {
			writer.write_u8(1)?;
			value.write(writer)
		}
		None => writer.write_u8(0),
	}
}

fn read_mwixnet_hash<R: Reader>(reader: &mut R) -> Result<Option<MwixnetHash>, ser::Error> {
	match reader.read_u8()? {
		0 => Ok(None),
		1 => Ok(Some(MwixnetHash::read(reader)?)),
		_ => Err(ser::Error::CorruptedData),
	}
}

impl Writeable for SwapData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(CURRENT_SWAP_VERSION)?;
		writer.write_fixed_bytes(&self.excess)?;
		writer.write_fixed_bytes(&self.output_commit)?;
		write_optional(writer, &self.rangeproof)?;
		self.input.write(writer)?;
		writer.write_u64(self.fee.into())?;
		self.onion.write(writer)?;
		self.status.write(writer)?;
		match &self.route {
			Some(route) => {
				writer.write_u8(1)?;
				route.route_id.write(writer)?;
				writer.write_u64(route.manifest_sequence)?;
				route.wallet_request_id.write(writer)?;
				route.swap_req_hash.write(writer)?;
				writer.write_u64(route.expires_at_height)?;
				write_mwixnet_hash(writer, route.batch_id)?;
				match route.batch_position {
					Some(position) => {
						writer.write_u8(1)?;
						writer.write_u16(position)?;
					}
					None => writer.write_u8(0)?,
				}
				write_mwixnet_hash(writer, route.mix_req_hash)?;
				match route.cancelled_at {
					Some(value) => {
						writer.write_u8(1)?;
						writer.write_u64(value)?;
					}
					None => writer.write_u8(0)?,
				}
				write_mwixnet_hash(writer, route.cancel_req_hash)?;
			}
			None => writer.write_u8(0)?,
		}

		Ok(())
	}
}

impl Readable for SwapData {
	fn read<R: Reader>(reader: &mut R) -> Result<SwapData, ser::Error> {
		let version = reader.read_u8()?;
		if version > CURRENT_SWAP_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}

		let excess = secp::read_secret_key(reader)?;
		let output_commit = Commitment::read(reader)?;
		let rangeproof = read_optional(reader)?;
		let input = Input::read(reader)?;
		let fee = reader.read_u64()?;
		let onion = Onion::read(reader)?;
		let status = SwapStatus::read(reader)?;
		let route = if version == 0 {
			None
		} else {
			match reader.read_u8()? {
				0 => None,
				1 => Some(RouteSwapData {
					route_id: MwixnetHash::read(reader)?,
					manifest_sequence: reader.read_u64()?,
					wallet_request_id: MwixnetHash::read(reader)?,
					swap_req_hash: MwixnetHash::read(reader)?,
					expires_at_height: reader.read_u64()?,
					batch_id: read_mwixnet_hash(reader)?,
					batch_position: match reader.read_u8()? {
						0 => None,
						1 => Some(reader.read_u16()?),
						_ => return Err(ser::Error::CorruptedData),
					},
					mix_req_hash: read_mwixnet_hash(reader)?,
					cancelled_at: match reader.read_u8()? {
						0 => None,
						1 => Some(reader.read_u64()?),
						_ => return Err(ser::Error::CorruptedData),
					},
					cancel_req_hash: read_mwixnet_hash(reader)?,
				}),
				_ => return Err(ser::Error::CorruptedData),
			}
		};
		Ok(SwapData {
			excess,
			output_commit,
			rangeproof,
			input,
			fee,
			onion,
			status,
			route,
		})
	}
}

/// A transaction created as part of a swap round.
#[derive(Clone, Debug, PartialEq)]
pub struct SwapTx {
	pub tx: Transaction,
	pub chain_tip: (u64, Hash),
	// TODO: Include status
}

impl Writeable for SwapTx {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(CURRENT_TX_VERSION)?;
		self.tx.write(writer)?;
		writer.write_u64(self.chain_tip.0)?;
		self.chain_tip.1.write(writer)?;
		Ok(())
	}
}

impl Readable for SwapTx {
	fn read<R: Reader>(reader: &mut R) -> Result<SwapTx, ser::Error> {
		let version = reader.read_u8()?;
		if version != CURRENT_TX_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}

		let tx = Transaction::read(reader)?;
		let height = reader.read_u64()?;
		let block_hash = Hash::read(reader)?;
		Ok(SwapTx {
			tx,
			chain_tip: (height, block_hash),
		})
	}
}

/// Storage facility for swap data.
pub struct SwapStore {
	db: Store,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProposalBinding {
	pub proposal_hash: MwixnetHash,
	pub proposal: RouteProposal,
	pub acceptance: RouteAcceptance,
}

impl Writeable for ProposalBinding {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.proposal_hash.write(writer)?;
		self.proposal.write(writer)?;
		self.acceptance.write(writer)
	}
}

impl Readable for ProposalBinding {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(Self {
			proposal_hash: MwixnetHash::read(reader)?,
			proposal: RouteProposal::read(reader)?,
			acceptance: RouteAcceptance::read(reader)?,
		})
	}
}

#[derive(Clone, Debug, PartialEq)]
pub struct RouteRecord {
	pub manifest: RouteManifest,
	pub state: RouteState,
	pub failures: u8,
	pub health_proof: Option<RouteHealthProof>,
	pub relay_sequence: u64,
	pub pending_relay: Vec<mwixnet_protocol::RouteRelayItem>,
	pub revocations: Vec<mwixnet_protocol::RouteRevocation>,
	pub drain_until_height: Option<u64>,
}

impl Writeable for RouteRecord {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.manifest.write(writer)?;
		self.state.write(writer)?;
		writer.write_u8(self.failures)?;
		match &self.health_proof {
			Some(proof) => {
				writer.write_u8(1)?;
				proof.write(writer)
			}
			None => writer.write_u8(0),
		}?;
		writer.write_u64(self.relay_sequence)?;
		if self.pending_relay.len() > mwixnet_protocol::MAX_ROUTE_HOPS + 1 {
			return Err(ser::Error::CountError);
		}
		writer.write_u16(self.pending_relay.len() as u16)?;
		for item in &self.pending_relay {
			item.write(writer)?;
		}
		if self.revocations.len() > mwixnet_protocol::MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		writer.write_u16(self.revocations.len() as u16)?;
		for revocation in &self.revocations {
			revocation.write(writer)?;
		}
		match self.drain_until_height {
			Some(height) => {
				writer.write_u8(1)?;
				writer.write_u64(height)?;
			}
			None => writer.write_u8(0)?,
		}
		Ok(())
	}
}

impl Readable for RouteRecord {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(Self {
			manifest: RouteManifest::read(reader)?,
			state: RouteState::read(reader)?,
			failures: reader.read_u8()?,
			health_proof: match reader.read_u8()? {
				0 => None,
				1 => Some(RouteHealthProof::read(reader)?),
				_ => return Err(ser::Error::CorruptedData),
			},
			relay_sequence: reader.read_u64()?,
			pending_relay: {
				let count = reader.read_u16()? as usize;
				if count > mwixnet_protocol::MAX_ROUTE_HOPS + 1 {
					return Err(ser::Error::CountError);
				}
				(0..count)
					.map(|_| mwixnet_protocol::RouteRelayItem::read(reader))
					.collect::<Result<Vec<_>, _>>()?
			},
			revocations: {
				let count = reader.read_u16()? as usize;
				if count > mwixnet_protocol::MAX_ROUTE_HOPS {
					return Err(ser::Error::CountError);
				}
				(0..count)
					.map(|_| mwixnet_protocol::RouteRevocation::read(reader))
					.collect::<Result<Vec<_>, _>>()?
			},
			drain_until_height: match reader.read_u8()? {
				0 => None,
				1 => Some(reader.read_u64()?),
				_ => return Err(ser::Error::CorruptedData),
			},
		})
	}
}

pub struct RouteStore {
	db: Store,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HealthBinding {
	pub stored_at: u64,
	pub request_hash: MwixnetHash,
	pub request: HealthRequest,
	pub challenge: Option<HealthChallenge>,
	pub hop_nonces: Vec<MwixnetHash>,
	pub response: Option<HealthResponse>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BatchBinding {
	pub request_hash: MwixnetHash,
	pub request: RouteMixReq,
	pub response: Option<MixResp>,
}

impl Writeable for BatchBinding {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl Readable for BatchBinding {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&bytes).map_err(|_| ser::Error::CorruptedData)
	}
}

impl Writeable for HealthBinding {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.stored_at)?;
		self.request_hash.write(writer)?;
		self.request.write(writer)?;
		match &self.challenge {
			Some(challenge) => {
				writer.write_u8(1)?;
				challenge.write(writer)?;
			}
			None => writer.write_u8(0)?,
		}
		if self.hop_nonces.len() >= mwixnet_protocol::MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		writer.write_u16(self.hop_nonces.len() as u16)?;
		for nonce in &self.hop_nonces {
			nonce.write(writer)?;
		}
		match &self.response {
			Some(response) => {
				writer.write_u8(1)?;
				response.write(writer)
			}
			None => writer.write_u8(0),
		}
	}
}

impl Readable for HealthBinding {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(Self {
			stored_at: reader.read_u64()?,
			request_hash: MwixnetHash::read(reader)?,
			request: HealthRequest::read(reader)?,
			challenge: match reader.read_u8()? {
				0 => None,
				1 => Some(HealthChallenge::read(reader)?),
				_ => return Err(ser::Error::CorruptedData),
			},
			hop_nonces: {
				let count = reader.read_u16()? as usize;
				if count >= mwixnet_protocol::MAX_ROUTE_HOPS {
					return Err(ser::Error::CountError);
				}
				(0..count)
					.map(|_| MwixnetHash::read(reader))
					.collect::<Result<_, _>>()?
			},
			response: match reader.read_u8()? {
				0 => None,
				1 => Some(HealthResponse::read(reader)?),
				_ => return Err(ser::Error::CorruptedData),
			},
		})
	}
}

/// Store error types
#[derive(Clone, Error, Debug, PartialEq)]
pub enum StoreError {
	#[error("Swap entry already exists for '{0:?}'")]
	AlreadyExists(Commitment),
	#[error("Entry does not exist for '{0:?}'")]
	NotFound(Commitment),
	#[error("Error occurred while attempting to open db: {0}")]
	OpenError(store::lmdb::Error),
	#[error("Serialization error occurred: {0}")]
	SerializationError(ser::Error),
	#[error("Error occurred while attempting to read from db: {0}")]
	ReadError(store::lmdb::Error),
	#[error("Error occurred while attempting to write to db: {0}")]
	WriteError(store::lmdb::Error),
}

impl From<ser::Error> for StoreError {
	fn from(e: ser::Error) -> StoreError {
		StoreError::SerializationError(e)
	}
}

impl SwapStore {
	/// Create new chain store
	pub fn new(db_root: &str) -> Result<SwapStore, StoreError> {
		let db = Store::new(
			db_root,
			Some(DB_NAME),
			Some(STORE_SUBPATH),
			vec![SWAP_PREFIX, TX_PREFIX, REQUEST_PREFIX],
			None,
			None,
		)
		.map_err(StoreError::OpenError)?;
		Ok(SwapStore { db })
	}

	/// Writes a single key-value pair to the database
	fn write<K: AsRef<[u8]>>(
		&self,
		prefix: u8,
		k: K,
		value: &Vec<u8>,
		overwrite: bool,
	) -> Result<bool, store::lmdb::Error> {
		let mut batch = self.db.batch()?;
		if !overwrite && batch.exists(Some(prefix), k.as_ref())? {
			Ok(false)
		} else {
			batch.put(Some(prefix), k.as_ref(), &value[..])?;
			batch.commit()?;
			Ok(true)
		}
	}

	/// Reads a single value by key
	fn read<K: AsRef<[u8]> + Copy, V: Readable>(&self, prefix: u8, k: K) -> Result<V, StoreError> {
		store::option_to_not_found(self.db.get_ser(Some(prefix), k.as_ref(), None), || {
			format!("{}:{}", prefix, k.to_hex())
		})
		.map_err(StoreError::ReadError)
	}

	/// Saves a swap to the database
	pub fn save_swap(&self, s: &SwapData, overwrite: bool) -> Result<(), StoreError> {
		let data = ser::ser_vec(&s, ProtocolVersion::local())?;
		let saved = self
			.write(SWAP_PREFIX, &s.input.commit, &data, overwrite)
			.map_err(StoreError::WriteError)?;
		if !saved {
			Err(StoreError::AlreadyExists(s.input.commit.clone()))
		} else {
			Ok(())
		}
	}

	pub fn save_swaps(&self, swaps: &[SwapData]) -> Result<(), StoreError> {
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		for swap in swaps {
			let data = ser::ser_vec(swap, ProtocolVersion::local())?;
			batch
				.put(Some(SWAP_PREFIX), swap.input.commit.as_ref(), &data)
				.map_err(StoreError::WriteError)?;
		}
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn save_swap_tx_and_swaps(
		&self,
		tx: &SwapTx,
		swaps: &[SwapData],
	) -> Result<(), StoreError> {
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		let tx_data = ser::ser_vec(tx, ProtocolVersion::local())?;
		batch
			.put(
				Some(TX_PREFIX),
				tx.tx.kernels().first().unwrap().excess.as_ref(),
				&tx_data,
			)
			.map_err(StoreError::WriteError)?;
		for swap in swaps {
			let data = ser::ser_vec(swap, ProtocolVersion::local())?;
			batch
				.put(Some(SWAP_PREFIX), swap.input.commit.as_ref(), &data)
				.map_err(StoreError::WriteError)?;
		}
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn save_route_swap(&self, swap: &SwapData) -> Result<(), StoreError> {
		let route = swap
			.route
			.as_ref()
			.ok_or(StoreError::SerializationError(ser::Error::CorruptedData))?;
		let data = ser::ser_vec(swap, ProtocolVersion::local())?;
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		if batch
			.exists(Some(SWAP_PREFIX), swap.input.commit.as_ref())
			.map_err(StoreError::ReadError)?
			|| batch
				.exists(
					Some(REQUEST_PREFIX),
					&route_request_key(route.route_id, route.wallet_request_id),
				)
				.map_err(StoreError::ReadError)?
		{
			return Err(StoreError::AlreadyExists(swap.input.commit));
		}
		batch
			.put(Some(SWAP_PREFIX), swap.input.commit.as_ref(), &data)
			.map_err(StoreError::WriteError)?;
		batch
			.put_ser(
				Some(REQUEST_PREFIX),
				&route_request_key(route.route_id, route.wallet_request_id),
				&swap.input.commit,
			)
			.map_err(StoreError::WriteError)?;
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn get_route_swap(
		&self,
		route_id: MwixnetHash,
		wallet_request_id: MwixnetHash,
	) -> Result<Option<SwapData>, StoreError> {
		let commitment: Option<Commitment> = self
			.db
			.get_ser(
				Some(REQUEST_PREFIX),
				&route_request_key(route_id, wallet_request_id),
				None,
			)
			.map_err(StoreError::ReadError)?;
		commitment
			.map(|commitment| self.get_swap(&commitment))
			.transpose()
	}

	/// Iterator over all swaps.
	pub fn swaps_iter(&self) -> Result<impl Iterator<Item = SwapData>, StoreError> {
		let protocol_version = self.db.protocol_version();
		let swaps =
			self.db
				.iter(Some(SWAP_PREFIX), move |key, mut v| {
					ser::deserialize(&mut v, protocol_version, DeserializationMode::default())
						.map_err(|e| {
							error!("Failed to deserialize swap '{}': {:?}", key.to_hex(), e);
							e.into()
						})
				})
				.map_err(StoreError::ReadError)?
				.collect::<Result<Vec<_>, _>>()
				.map_err(StoreError::ReadError)?;
		Ok(swaps.into_iter())
	}

	/// Checks if a matching swap exists in the database
	#[allow(dead_code)]
	pub fn swap_exists(&self, input_commit: &Commitment) -> Result<bool, StoreError> {
		self.db
			.batch()
			.map_err(StoreError::ReadError)?
			.exists(Some(SWAP_PREFIX), input_commit.as_ref())
			.map_err(StoreError::ReadError)
	}

	/// Reads a swap from the database
	pub fn get_swap(&self, input_commit: &Commitment) -> Result<SwapData, StoreError> {
		self.read(SWAP_PREFIX, input_commit)
	}

	/// Saves a swap transaction to the database
	pub fn save_swap_tx(&self, s: &SwapTx) -> Result<(), StoreError> {
		let data = ser::ser_vec(&s, ProtocolVersion::local())?;
		self.write(
			TX_PREFIX,
			&s.tx.kernels().first().unwrap().excess,
			&data,
			true,
		)
		.map_err(StoreError::WriteError)?;

		Ok(())
	}

	/// Reads a swap tx from the database
	pub fn get_swap_tx(&self, kernel_excess: &Commitment) -> Result<SwapTx, StoreError> {
		self.read(TX_PREFIX, kernel_excess)
	}
}

fn route_request_key(route_id: MwixnetHash, wallet_request_id: MwixnetHash) -> Vec<u8> {
	let mut key = Vec::with_capacity(64);
	key.extend_from_slice(&route_id.0);
	key.extend_from_slice(&wallet_request_id.0);
	key
}

fn route_key(route_id: MwixnetHash, manifest_sequence: u64) -> Vec<u8> {
	let mut key = Vec::with_capacity(40);
	key.extend_from_slice(&route_id.0);
	key.extend_from_slice(&manifest_sequence.to_be_bytes());
	key
}

fn remote_offer_key(offer: &MwixnetOffer) -> Vec<u8> {
	let (identity, msg_type) = match offer {
		MwixnetOffer::Mixer(offer) => (offer.identity_public_key, offer.msg_type),
		MwixnetOffer::Swap(offer) => (offer.identity_public_key, offer.msg_type),
	};
	let mut key = Vec::with_capacity(39);
	key.extend_from_slice(b"remote");
	key.extend_from_slice(&identity.0);
	key.push(msg_type as u8);
	key
}

fn stored_offer_sequence(offer: &MwixnetOffer) -> u64 {
	match offer {
		MwixnetOffer::Mixer(offer) => offer.sequence,
		MwixnetOffer::Swap(offer) => offer.sequence,
	}
}

impl RouteStore {
	pub fn new(db_root: &str) -> Result<Self, StoreError> {
		let db = Store::new(
			db_root,
			Some("mwixnet_route"),
			Some("routes"),
			vec![
				OFFER_PREFIX,
				PROPOSAL_PREFIX,
				ROUTE_PREFIX,
				HEALTH_PREFIX,
				BATCH_PREFIX,
			],
			None,
			None,
		)
		.map_err(StoreError::OpenError)?;
		Ok(Self { db })
	}

	pub fn offer(&self) -> Result<Option<MwixnetOffer>, StoreError> {
		self.db
			.get_ser(Some(OFFER_PREFIX), b"current", None)
			.map_err(StoreError::ReadError)
	}

	pub fn save_offer(&self, offer: &MwixnetOffer) -> Result<(), StoreError> {
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		batch
			.put_ser(Some(OFFER_PREFIX), b"current", offer)
			.map_err(StoreError::WriteError)?;
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn save_remote_offers(&self, offers: &[MwixnetOffer]) -> Result<bool, StoreError> {
		for offer in offers {
			if let Some(previous) = self
				.db
				.get_ser::<MwixnetOffer>(Some(OFFER_PREFIX), &remote_offer_key(offer), None)
				.map_err(StoreError::ReadError)?
			{
				if stored_offer_sequence(offer) < stored_offer_sequence(&previous)
					|| (stored_offer_sequence(offer) == stored_offer_sequence(&previous)
						&& offer != &previous)
				{
					return Ok(false);
				}
			}
		}
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		for offer in offers {
			batch
				.put_ser(Some(OFFER_PREFIX), &remote_offer_key(offer), offer)
				.map_err(StoreError::WriteError)?;
		}
		batch.commit().map_err(StoreError::WriteError)?;
		Ok(true)
	}

	pub fn proposal(
		&self,
		route_id: MwixnetHash,
		manifest_sequence: u64,
	) -> Result<Option<ProposalBinding>, StoreError> {
		self.db
			.get_ser(
				Some(PROPOSAL_PREFIX),
				&route_key(route_id, manifest_sequence),
				None,
			)
			.map_err(StoreError::ReadError)
	}

	pub fn save_proposal(
		&self,
		route_id: MwixnetHash,
		manifest_sequence: u64,
		binding: &ProposalBinding,
	) -> Result<(), StoreError> {
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		batch
			.put_ser(
				Some(PROPOSAL_PREFIX),
				&route_key(route_id, manifest_sequence),
				binding,
			)
			.map_err(StoreError::WriteError)?;
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn route(
		&self,
		route_id: MwixnetHash,
		manifest_sequence: u64,
	) -> Result<Option<RouteRecord>, StoreError> {
		self.db
			.get_ser(
				Some(ROUTE_PREFIX),
				&route_key(route_id, manifest_sequence),
				None,
			)
			.map_err(StoreError::ReadError)
	}

	pub fn save_route(&self, route: &RouteRecord) -> Result<(), StoreError> {
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		batch
			.put_ser(
				Some(ROUTE_PREFIX),
				&route_key(route.manifest.route_id, route.manifest.manifest_sequence),
				route,
			)
			.map_err(StoreError::WriteError)?;
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn latest_route(&self, route_id: MwixnetHash) -> Result<Option<RouteRecord>, StoreError> {
		let protocol_version = self.db.protocol_version();
		let routes = self
			.db
			.iter(Some(ROUTE_PREFIX), move |key, mut value| {
				if !key.starts_with(&route_id.0) {
					return Ok(None);
				}
				ser::deserialize(&mut value, protocol_version, DeserializationMode::default())
					.map(Some)
					.map_err(Into::into)
			})
			.map_err(StoreError::ReadError)?
			.collect::<Result<Vec<_>, _>>()
			.map_err(StoreError::ReadError)?;
		Ok(routes
			.into_iter()
			.flatten()
			.max_by_key(|route: &RouteRecord| route.manifest.manifest_sequence))
	}

	pub fn routes(&self) -> Result<Vec<RouteRecord>, StoreError> {
		let protocol_version = self.db.protocol_version();
		self.db
			.iter(Some(ROUTE_PREFIX), move |_, mut value| {
				ser::deserialize(&mut value, protocol_version, DeserializationMode::default())
					.map_err(Into::into)
			})
			.map_err(StoreError::ReadError)?
			.collect::<Result<Vec<_>, _>>()
			.map_err(StoreError::ReadError)
	}

	pub fn health(
		&self,
		route_id: MwixnetHash,
		manifest_sequence: u64,
		challenge_hash: MwixnetHash,
	) -> Result<Option<HealthBinding>, StoreError> {
		self.db
			.get_ser(
				Some(HEALTH_PREFIX),
				&health_key(route_id, manifest_sequence, challenge_hash),
				None,
			)
			.map_err(StoreError::ReadError)
	}

	pub fn pending_health(
		&self,
		route_id: MwixnetHash,
		manifest_sequence: u64,
	) -> Result<Option<HealthBinding>, StoreError> {
		let protocol_version = self.db.protocol_version();
		let bindings = self
			.db
			.iter(Some(HEALTH_PREFIX), move |_, mut value| {
				ser::deserialize(&mut value, protocol_version, DeserializationMode::default())
					.map_err(Into::into)
			})
			.map_err(StoreError::ReadError)?
			.collect::<Result<Vec<HealthBinding>, _>>()
			.map_err(StoreError::ReadError)?;
		Ok(bindings
			.into_iter()
			.filter(|binding| {
				binding.request.route_id == route_id
					&& binding.request.manifest_sequence == manifest_sequence
					&& binding.challenge.is_some()
					&& binding.response.is_none()
			})
			.max_by_key(|binding| {
				binding
					.challenge
					.as_ref()
					.map(|challenge| challenge.created_at)
					.unwrap_or(0)
			}))
	}

	pub fn save_health(
		&self,
		route_id: MwixnetHash,
		manifest_sequence: u64,
		challenge_hash: MwixnetHash,
		binding: &HealthBinding,
	) -> Result<(), StoreError> {
		let protocol_version = self.db.protocol_version();
		let now = chrono::Utc::now().timestamp() as u64;
		let retention =
			mwixnet_protocol::MAX_HEALTH_CERTIFICATE_AGE + mwixnet_protocol::MAX_CLOCK_SKEW;
		let expired = self
			.db
			.iter(Some(HEALTH_PREFIX), move |key, mut value| {
				let binding: HealthBinding =
					ser::deserialize(&mut value, protocol_version, DeserializationMode::default())?;
				Ok((key.to_vec(), binding.stored_at))
			})
			.map_err(StoreError::ReadError)?
			.collect::<Result<Vec<_>, _>>()
			.map_err(StoreError::ReadError)?;
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		for (key, stored_at) in expired {
			if stored_at.saturating_add(retention) < now {
				batch
					.delete(Some(HEALTH_PREFIX), &key)
					.map_err(StoreError::WriteError)?;
			}
		}
		batch
			.put_ser(
				Some(HEALTH_PREFIX),
				&health_key(route_id, manifest_sequence, challenge_hash),
				binding,
			)
			.map_err(StoreError::WriteError)?;
		batch.commit().map_err(StoreError::WriteError)
	}

	pub fn batch(
		&self,
		route_id: MwixnetHash,
		batch_id: MwixnetHash,
	) -> Result<Option<BatchBinding>, StoreError> {
		self.db
			.get_ser(Some(BATCH_PREFIX), &batch_key(route_id, batch_id), None)
			.map_err(StoreError::ReadError)
	}

	pub fn save_batch(
		&self,
		route_id: MwixnetHash,
		batch_id: MwixnetHash,
		binding: &BatchBinding,
	) -> Result<(), StoreError> {
		let mut batch = self.db.batch().map_err(StoreError::WriteError)?;
		batch
			.put_ser(Some(BATCH_PREFIX), &batch_key(route_id, batch_id), binding)
			.map_err(StoreError::WriteError)?;
		batch.commit().map_err(StoreError::WriteError)
	}
}

fn batch_key(route_id: MwixnetHash, batch_id: MwixnetHash) -> Vec<u8> {
	let mut key = Vec::with_capacity(64);
	key.extend_from_slice(&route_id.0);
	key.extend_from_slice(&batch_id.0);
	key
}

fn health_key(
	route_id: MwixnetHash,
	manifest_sequence: u64,
	challenge_hash: MwixnetHash,
) -> Vec<u8> {
	let mut key = route_key(route_id, manifest_sequence);
	key.extend_from_slice(&challenge_hash.0);
	key
}

#[cfg(test)]
mod tests {
	use super::grin_onion;
	use std::cmp::Ordering;

	use grin_core::core::{Input, OutputFeatures};
	use grin_core::global::{self, ChainTypes};
	use grin_core::ser::{self, ProtocolVersion};
	use rand::RngCore;

	use grin_onion::crypto::{dalek, secp};
	use grin_onion::test_util as onion_test_util;

	use crate::servers::mix_rpc::RouteMixReq;
	use crate::store::{
		BatchBinding, RouteStore, RouteSwapData, StoreError, SwapData, SwapStatus, SwapStore,
		SWAP_PREFIX,
	};
	use mwixnet_protocol::{Hash as MwixnetHash, MwixnetOffer};

	fn new_store(test_name: &str) -> SwapStore {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let db_root = format!("./target/tmp/.{}", test_name);
		let _ = std::fs::remove_dir_all(db_root.as_str());
		SwapStore::new(db_root.as_str()).unwrap()
	}

	fn rand_swap_with_status(status: SwapStatus) -> SwapData {
		SwapData {
			excess: secp::random_secret(false),
			output_commit: onion_test_util::rand_commit(),
			rangeproof: Some(onion_test_util::rand_proof()),
			input: Input::new(OutputFeatures::Plain, onion_test_util::rand_commit()),
			fee: rand::thread_rng().next_u64(),
			onion: onion_test_util::rand_onion(),
			status,
			route: None,
		}
	}

	fn rand_swap() -> SwapData {
		let s = rand::thread_rng().next_u64() % 3;
		let status = if s == 0 {
			SwapStatus::Unprocessed
		} else if s == 1 {
			SwapStatus::InProcess {
				kernel_commit: onion_test_util::rand_commit(),
			}
		} else {
			SwapStatus::Completed {
				kernel_commit: onion_test_util::rand_commit(),
				block_hash: onion_test_util::rand_hash(),
			}
		};
		rand_swap_with_status(status)
	}

	#[test]
	fn read_migrated_swap() -> Result<(), Box<dyn std::error::Error>> {
		let store = new_store("read_migrated_swap");
		let swap = rand_swap();
		let data = ser::ser_vec(&swap, ProtocolVersion::local())?;

		// Migration stores raw keys in the prefix database.
		let mut batch = store.db.batch()?;
		batch.put(Some(SWAP_PREFIX), swap.input.commit.as_ref(), &data)?;
		batch.commit()?;

		assert_eq!(store.get_swap(&swap.input.commit)?, swap);
		assert!(store.swap_exists(&swap.input.commit)?);
		assert_eq!(
			store.save_swap(&swap, false),
			Err(StoreError::AlreadyExists(swap.input.commit))
		);
		Ok(())
	}

	#[test]
	fn invalid_swap_iter() -> Result<(), Box<dyn std::error::Error>> {
		let store = new_store("invalid_swap_iter");
		let swap = rand_swap();
		let mut batch = store.db.batch()?;
		batch.put(Some(SWAP_PREFIX), swap.input.commit.as_ref(), b"invalid")?;
		batch.commit()?;

		assert!(store.swaps_iter().is_err());
		Ok(())
	}

	#[test]
	fn swap_iter() -> Result<(), Box<dyn std::error::Error>> {
		let store = new_store("swap_iter");
		let mut swaps: Vec<SwapData> = Vec::new();
		for _ in 0..5 {
			let swap = rand_swap();
			store.save_swap(&swap, false)?;
			swaps.push(swap);
		}

		swaps.sort_by(|a, b| {
			if a.input.commit < b.input.commit {
				Ordering::Less
			} else if a.input.commit == b.input.commit {
				Ordering::Equal
			} else {
				Ordering::Greater
			}
		});

		let mut i: usize = 0;
		for swap in store.swaps_iter()? {
			assert_eq!(swap, *swaps.get(i).unwrap());
			i += 1;
		}

		Ok(())
	}

	#[test]
	fn save_swap() -> Result<(), Box<dyn std::error::Error>> {
		let store = new_store("save_swap");

		let mut swap = rand_swap_with_status(SwapStatus::Unprocessed);
		assert!(!store.swap_exists(&swap.input.commit)?);

		store.save_swap(&swap, false)?;
		assert_eq!(swap, store.get_swap(&swap.input.commit)?);
		assert!(store.swap_exists(&swap.input.commit)?);

		swap.status = SwapStatus::InProcess {
			kernel_commit: onion_test_util::rand_commit(),
		};
		let result = store.save_swap(&swap, false);
		assert_eq!(
			Err(StoreError::AlreadyExists(swap.input.commit.clone())),
			result
		);

		store.save_swap(&swap, true)?;
		assert_eq!(swap, store.get_swap(&swap.input.commit)?);

		Ok(())
	}

	#[test]
	fn route_request_id_cannot_be_overwritten() -> Result<(), Box<dyn std::error::Error>> {
		let store = new_store("route_request_id_cannot_be_overwritten");
		let route = RouteSwapData {
			route_id: MwixnetHash([1; 32]),
			manifest_sequence: 1,
			wallet_request_id: MwixnetHash([2; 32]),
			swap_req_hash: MwixnetHash([3; 32]),
			expires_at_height: 100,
			batch_id: None,
			batch_position: None,
			mix_req_hash: None,
			cancelled_at: None,
			cancel_req_hash: None,
		};
		let mut first = rand_swap_with_status(SwapStatus::Unprocessed);
		first.route = Some(route.clone());
		store.save_route_swap(&first)?;

		let mut second = rand_swap_with_status(SwapStatus::Unprocessed);
		second.route = Some(route);
		assert!(matches!(
			store.save_route_swap(&second),
			Err(StoreError::AlreadyExists(_))
		));
		assert_eq!(
			store
				.get_route_swap(MwixnetHash([1; 32]), MwixnetHash([2; 32]))?
				.unwrap()
				.input,
			first.input
		);
		Ok(())
	}

	#[test]
	fn remote_offer_sequence_cannot_roll_back() -> Result<(), Box<dyn std::error::Error>> {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let store = RouteStore::new(&format!(
			"./target/tmp/.store_remote_offer_sequence_{}",
			chrono::Utc::now().timestamp_nanos_opt().unwrap()
		))?;
		let mut offer = mwixnet_protocol::MixerOffer {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::MixerOffer,
			identity_public_key: mwixnet_protocol::PublicKey([1; 32]),
			onion_address: mwixnet_protocol::OnionAddress([1; 32]),
			onion_public_key: mwixnet_protocol::OnionPublicKey([2; 32]),
			minimum_fee: 1,
			capacity: 1,
			valid_until: 1,
			sequence: 2,
			signature: mwixnet_protocol::Signature([0; 64]),
		};
		assert!(store.save_remote_offers(&[MwixnetOffer::Mixer(offer.clone())])?);
		assert!(store.save_remote_offers(&[MwixnetOffer::Mixer(offer.clone())])?);
		offer.minimum_fee = 2;
		assert!(!store.save_remote_offers(&[MwixnetOffer::Mixer(offer.clone())])?);
		offer.sequence = 1;
		assert!(!store.save_remote_offers(&[MwixnetOffer::Mixer(offer)])?);
		Ok(())
	}

	#[test]
	fn route_batch_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let root = format!(
			"./target/tmp/.store_route_batch_reopen_{}",
			chrono::Utc::now().timestamp_nanos_opt().unwrap()
		);
		let key = secp::random_secret(false);
		let route_id = MwixnetHash([1; 32]);
		let batch_id = MwixnetHash([2; 32]);
		let onions = vec![onion_test_util::rand_onion()];
		let request_hash = RouteMixReq::signing_hash(&route_id, 1, &batch_id, &onions);
		let request = RouteMixReq {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::MixReq,
			route_id,
			manifest_sequence: 1,
			batch_id,
			onions,
			sig: dalek::sign(&key, request_hash.as_bytes())?,
		};
		{
			let store = RouteStore::new(&root)?;
			store.save_batch(
				request.route_id,
				request.batch_id,
				&BatchBinding {
					request_hash,
					request: request.clone(),
					response: None,
				},
			)?;
		}
		let stored = RouteStore::new(&root)?
			.batch(request.route_id, request.batch_id)?
			.unwrap();
		assert_eq!(stored.request_hash, request_hash);
		assert_eq!(stored.request.route_id, request.route_id);
		assert_eq!(stored.request.batch_id, request.batch_id);
		assert!(stored.response.is_none());
		std::fs::remove_dir_all(root)?;
		Ok(())
	}

	#[test]
	fn batched_swap_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let root = format!(
			"./target/tmp/.store_batched_swap_reopen_{}",
			chrono::Utc::now().timestamp_nanos_opt().unwrap()
		);
		let mut swap = rand_swap_with_status(SwapStatus::Batched);
		swap.route = Some(RouteSwapData {
			route_id: MwixnetHash([1; 32]),
			manifest_sequence: 2,
			wallet_request_id: MwixnetHash([3; 32]),
			swap_req_hash: MwixnetHash([4; 32]),
			expires_at_height: 100,
			batch_id: Some(MwixnetHash([5; 32])),
			batch_position: Some(6),
			mix_req_hash: Some(MwixnetHash([7; 32])),
			cancelled_at: None,
			cancel_req_hash: None,
		});
		{
			let store = SwapStore::new(&root)?;
			store.save_swap(&swap, false)?;
		}

		let store = SwapStore::new(&root)?;
		assert_eq!(store.get_swap(&swap.input.commit)?, swap);
		assert_eq!(store.swaps_iter()?.collect::<Vec<_>>(), vec![swap]);
		drop(store);
		std::fs::remove_dir_all(root)?;
		Ok(())
	}
}
