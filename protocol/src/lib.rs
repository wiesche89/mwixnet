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

//! Shared MWixnet discovery protocol types.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use grin_core::core::hash::{DefaultHashable, Hash as GrinHash, Hashed};
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use grin_util::{from_hex, ToHex};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt;

mod health;
mod route;

pub use health::*;
pub use route::*;

pub const MWIXNET_PROTOCOL_VERSION: u32 = 1;
pub const MIN_ROUTE_HOPS: usize = 2;
pub const MAX_ROUTE_HOPS: usize = 8;
pub const MAX_MANIFEST_VALIDITY: u64 = 30 * 24 * 60 * 60;
pub const MAX_CLOCK_SKEW: u64 = 2 * 60;
pub const MAX_HEALTH_CERTIFICATE_AGE: u64 = 15 * 60;
pub const UNAVAILABLE_AFTER_FAILURES: u8 = 3;
pub const MAX_ROUTE_ANNOUNCEMENT_VALIDITY: u64 = 15 * 60;
pub const MAX_OFFER_ANNOUNCEMENT_VALIDITY: u64 = 24 * 60 * 60;
pub const OFFER_POW_DIFFICULTY_BITS: usize = 16;
pub const MIN_REQUEST_TTL_BLOCKS: u16 = 10;
pub const MAX_REQUEST_TTL_BLOCKS: u16 = 1_440;
pub const P2P_GET_ROUTES_MAX_BYTES: u64 = 64;
pub const P2P_BATCH_MAX_ROUTES: usize = 128;
pub const P2P_BATCH_MAX_BYTES: u64 = 128 * 1024;
pub const P2P_ANNOUNCEMENT_MAX_BYTES: u64 = 1024;
pub const P2P_STATUS_MAX_BYTES: u64 = 512;
pub const P2P_REVOCATION_MAX_BYTES: u64 = 512;
pub const P2P_GET_OFFERS_MAX_BYTES: u64 = 64;
pub const P2P_OFFER_BATCH_MAX_ITEMS: usize = 128;
pub const P2P_OFFER_BATCH_MAX_BYTES: u64 = 128 * 1024;
pub const P2P_OFFER_ANNOUNCEMENT_MAX_BYTES: u64 = 1024;
pub const MAX_MIX_BATCH_SIZE: usize = 128;
pub const MAX_HEALTH_CHALLENGE_LIFETIME: u64 = 5 * 60;
pub const HEALTH_REQUEST_MAX_BYTES: usize = 64 * 1024;
pub const MWIXNET_RPC_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Type tag used by signed protocol messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MwixnetType {
	MixerOffer = 0,
	SwapOffer = 1,
	RouteProposal = 2,
	RouteAcceptance = 3,
	RouteManifest = 4,
	SwapReq = 5,
	MixReq = 6,
	MixResp = 7,
	HealthChallenge = 8,
	HealthRequest = 9,
	HealthAttestation = 10,
	RouteHealthCertificate = 11,
	CancelSwapReq = 12,
	CancelAck = 13,
	RouteAnnouncement = 14,
	RouteStatus = 15,
	RouteRevocation = 16,
	RouteId = 17,
	HealthHopNonce = 18,
	SwapReqOnion = 19,
	HealthOnionLayer = 20,
	HealthResponse = 21,
	RouteHealthProof = 22,
	OfferAnnouncement = 23,
}

impl TryFrom<u8> for MwixnetType {
	type Error = ser::Error;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(Self::MixerOffer),
			1 => Ok(Self::SwapOffer),
			2 => Ok(Self::RouteProposal),
			3 => Ok(Self::RouteAcceptance),
			4 => Ok(Self::RouteManifest),
			5 => Ok(Self::SwapReq),
			6 => Ok(Self::MixReq),
			7 => Ok(Self::MixResp),
			8 => Ok(Self::HealthChallenge),
			9 => Ok(Self::HealthRequest),
			10 => Ok(Self::HealthAttestation),
			11 => Ok(Self::RouteHealthCertificate),
			12 => Ok(Self::CancelSwapReq),
			13 => Ok(Self::CancelAck),
			14 => Ok(Self::RouteAnnouncement),
			15 => Ok(Self::RouteStatus),
			16 => Ok(Self::RouteRevocation),
			17 => Ok(Self::RouteId),
			18 => Ok(Self::HealthHopNonce),
			19 => Ok(Self::SwapReqOnion),
			20 => Ok(Self::HealthOnionLayer),
			21 => Ok(Self::HealthResponse),
			22 => Ok(Self::RouteHealthProof),
			23 => Ok(Self::OfferAnnouncement),
			_ => Err(ser::Error::CorruptedData),
		}
	}
}

/// Published state of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RouteState {
	Proposed = 0,
	Healthy = 1,
	Degraded = 2,
	Unavailable = 3,
	Draining = 4,
	Expired = 5,
	Revoked = 6,
}

impl TryFrom<u8> for RouteState {
	type Error = ser::Error;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(Self::Proposed),
			1 => Ok(Self::Healthy),
			2 => Ok(Self::Degraded),
			3 => Ok(Self::Unavailable),
			4 => Ok(Self::Draining),
			5 => Ok(Self::Expired),
			6 => Ok(Self::Revoked),
			_ => Err(ser::Error::CorruptedData),
		}
	}
}

impl Writeable for RouteState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(*self as u8)
	}
}

impl Readable for RouteState {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Self::try_from(reader.read_u8()?)
	}
}

/// Role of a server in a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RouteRole {
	Swap = 0,
	Mixer = 1,
}

impl TryFrom<u8> for RouteRole {
	type Error = ser::Error;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(Self::Swap),
			1 => Ok(Self::Mixer),
			_ => Err(ser::Error::CorruptedData),
		}
	}
}

/// Ed25519 identity key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

/// X25519 onion key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OnionPublicKey(pub [u8; 32]);

/// Canonical protocol hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

/// Tor v3 onion address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OnionAddress(pub [u8; 32]);

/// Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Hash {
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl fmt::Debug for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl Serialize for Hash {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.0.to_hex())
	}
}

impl<'de> Deserialize<'de> for Hash {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = from_hex(&value).map_err(D::Error::custom)?;
		Ok(Self(
			<[u8; 32]>::try_from(bytes.as_slice())
				.map_err(|_| D::Error::custom("invalid hash length"))?,
		))
	}
}

impl Writeable for Hash {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0)
	}
}

impl Readable for Hash {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_fixed_bytes(32)?;
		Ok(Self(<[u8; 32]>::try_from(bytes.as_slice()).unwrap()))
	}
}

impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl Serialize for PublicKey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.0.to_hex())
	}
}

impl<'de> Deserialize<'de> for PublicKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = from_hex(&value).map_err(D::Error::custom)?;
		Ok(Self(<[u8; 32]>::try_from(bytes.as_slice()).map_err(
			|_| D::Error::custom("invalid public key length"),
		)?))
	}
}

impl Writeable for PublicKey {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0)
	}
}

impl Readable for PublicKey {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_fixed_bytes(32)?;
		Ok(Self(<[u8; 32]>::try_from(bytes.as_slice()).unwrap()))
	}
}

impl fmt::Debug for OnionPublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl Serialize for OnionPublicKey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.0.to_hex())
	}
}

impl<'de> Deserialize<'de> for OnionPublicKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = from_hex(&value).map_err(D::Error::custom)?;
		Ok(Self(<[u8; 32]>::try_from(bytes.as_slice()).map_err(
			|_| D::Error::custom("invalid onion public key length"),
		)?))
	}
}

impl Writeable for OnionPublicKey {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0)
	}
}

impl Readable for OnionPublicKey {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_fixed_bytes(32)?;
		Ok(Self(<[u8; 32]>::try_from(bytes.as_slice()).unwrap()))
	}
}

impl fmt::Debug for OnionAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl fmt::Display for OnionAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut address = Vec::with_capacity(35);
		address.extend_from_slice(&self.0);
		let mut hasher = Sha3_256::new();
		hasher.update(b".onion checksum");
		hasher.update(self.0);
		hasher.update([3]);
		address.extend_from_slice(&hasher.finalize()[..2]);
		address.push(3);
		write!(f, "{}.onion", BASE32_NOPAD.encode(&address).to_lowercase())
	}
}

impl Serialize for OnionAddress {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_string())
	}
}

impl<'de> Deserialize<'de> for OnionAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let encoded = value
			.strip_suffix(".onion")
			.ok_or_else(|| D::Error::custom("invalid onion address"))?;
		if encoded.len() != 56
			|| !encoded
				.bytes()
				.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
		{
			return Err(D::Error::custom("invalid onion address"));
		}
		let bytes = BASE32_NOPAD
			.decode(encoded.to_ascii_uppercase().as_bytes())
			.map_err(D::Error::custom)?;
		if bytes.len() != 35 || bytes[34] != 3 {
			return Err(D::Error::custom("invalid onion address"));
		}
		let address = Self(<[u8; 32]>::try_from(&bytes[..32]).unwrap());
		if address.to_string() != value {
			return Err(D::Error::custom("invalid onion address checksum"));
		}
		Ok(address)
	}
}

impl Writeable for OnionAddress {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0)
	}
}

impl Readable for OnionAddress {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_fixed_bytes(32)?;
		Ok(Self(<[u8; 32]>::try_from(bytes.as_slice()).unwrap()))
	}
}

impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl Serialize for Signature {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.0.to_hex())
	}
}

impl<'de> Deserialize<'de> for Signature {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = from_hex(&value).map_err(D::Error::custom)?;
		Ok(Self(<[u8; 64]>::try_from(bytes.as_slice()).map_err(
			|_| D::Error::custom("invalid signature length"),
		)?))
	}
}

impl Writeable for Signature {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0)
	}
}

impl Readable for Signature {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_fixed_bytes(64)?;
		Ok(Self(<[u8; 64]>::try_from(bytes.as_slice()).unwrap()))
	}
}

/// Signed route announcement relayed by Grin nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAnnouncement {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub entry_onion: OnionAddress,
	pub swap_identity: PublicKey,
	pub hop_count: u8,
	pub participant_identities: Vec<PublicKey>,
	#[serde(with = "u64_serde")]
	pub fee_per_hop: u64,
	pub manifest_hash: Hash,
	pub health_hash: Hash,
	pub status: RouteState,
	#[serde(with = "u64_serde")]
	pub last_verified: u64,
	#[serde(with = "u64_serde")]
	pub valid_until: u64,
	#[serde(with = "u64_serde")]
	pub sequence: u64,
	pub signature: Signature,
}

/// Signed route state update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteStatus {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub manifest_hash: Hash,
	pub status: RouteState,
	#[serde(with = "u64_serde")]
	pub last_verified: u64,
	#[serde(with = "u64_serde")]
	pub valid_until: u64,
	#[serde(with = "u64_serde")]
	pub sequence: u64,
	pub swap_identity: PublicKey,
	pub signature: Signature,
}

/// Signed route revocation by a participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRevocation {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub manifest_hash: Hash,
	pub participant_identity: PublicKey,
	#[serde(with = "u64_serde")]
	pub revoked_at: u64,
	#[serde(with = "u64_serde")]
	pub sequence: u64,
	pub signature: Signature,
}

/// Item stored in the route relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RouteRelayItem {
	Announcement(RouteAnnouncement),
	Status(RouteStatus),
	Revocation(RouteRevocation),
}

impl RouteRelayItem {
	pub fn route_id(&self) -> Hash {
		match self {
			Self::Announcement(item) => item.route_id,
			Self::Status(item) => item.route_id,
			Self::Revocation(item) => item.route_id,
		}
	}

	pub fn manifest_sequence(&self) -> u64 {
		match self {
			Self::Announcement(item) => item.manifest_sequence,
			Self::Status(item) => item.manifest_sequence,
			Self::Revocation(item) => item.manifest_sequence,
		}
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		match self {
			Self::Announcement(item) => item.validate(now),
			Self::Status(item) => item.validate(now),
			Self::Revocation(item) => item.validate(now),
		}
	}
}

/// Paginated route request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetMwixnetRoutes {
	pub version: u32,
	#[serde(with = "u64_serde")]
	pub request_id: u64,
	pub cursor: Option<Hash>,
	pub limit: u16,
}

/// Paginated route response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MwixnetRoutes {
	pub version: u32,
	#[serde(with = "u64_serde")]
	pub request_id: u64,
	pub next_cursor: Option<Hash>,
	pub items: Vec<RouteRelayItem>,
}

/// Route page returned by the node API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRoutePage {
	pub next_cursor: Option<Hash>,
	pub items: Vec<RouteRelayItem>,
}

/// Proof-of-work envelope for a server offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferAnnouncement {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub offer: MwixnetOffer,
	#[serde(with = "u64_serde")]
	pub pow_nonce: u64,
}

/// Paginated offer request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetMwixnetOffers {
	pub version: u32,
	#[serde(with = "u64_serde")]
	pub request_id: u64,
	pub cursor: Option<Hash>,
	pub limit: u16,
}

/// Paginated offer response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MwixnetOffers {
	pub version: u32,
	#[serde(with = "u64_serde")]
	pub request_id: u64,
	pub next_cursor: Option<Hash>,
	pub items: Vec<OfferAnnouncement>,
}

/// Offer page returned by the node API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeOfferPage {
	pub next_cursor: Option<Hash>,
	pub items: Vec<OfferAnnouncement>,
}

/// Protocol validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	InvalidMessage(&'static str),
	InvalidSignature,
	HealthLayerAuthenticationFailed,
}

/// Stable error code returned by MWixnet RPC methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
	UnsupportedMwixnetVersion,
	InvalidMwixnetMessage,
	LimitExceeded,
	OfferStale,
	ProposalConflict,
	ManifestConflict,
	RouteUnknown,
	RouteUnhealthy,
	RouteNotAcceptingRequests,
	ManifestExpired,
	UnauthorizedPredecessor,
	HealthChallengeReplayed,
	HealthLayerAuthenticationFailed,
	RequestExpired,
	RequestAlreadyProcessing,
	RequestPosted,
	RequestRejected,
	RequestConflict,
	InputAlreadyRegistered,
	BatchConflict,
	ServerBusy,
}

impl ProtocolErrorCode {
	pub fn retryable(self) -> bool {
		matches!(
			self,
			Self::ServerBusy | Self::RouteUnknown | Self::RouteUnhealthy
		)
	}
}

/// Structured MWixnet RPC error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRpcError {
	pub code: ProtocolErrorCode,
	pub retryable: bool,
	pub message: String,
}

impl ProtocolRpcError {
	pub fn new(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
		Self {
			code,
			retryable: code.retryable(),
			message: message.into(),
		}
	}
}

impl fmt::Display for ProtocolRpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?}: {}", self.code, self.message)
	}
}

mod u64_serde {
	use serde::{Deserialize, Deserializer, Serializer};

	#[derive(Deserialize)]
	#[serde(untagged)]
	pub(super) enum StringOrU64 {
		String(String),
		U64(u64),
	}

	pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&value.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
	where
		D: Deserializer<'de>,
	{
		match StringOrU64::deserialize(deserializer)? {
			StringOrU64::String(value) => value.parse().map_err(serde::de::Error::custom),
			StringOrU64::U64(value) => Ok(value),
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidMessage(reason) => write!(f, "invalid MWixnet message: {}", reason),
			Self::InvalidSignature => f.write_str("invalid MWixnet signature"),
			Self::HealthLayerAuthenticationFailed => {
				f.write_str("health layer authentication failed")
			}
		}
	}
}

impl std::error::Error for Error {}

struct HashInput<'a, T> {
	msg_type: MwixnetType,
	payload: &'a T,
}

impl<T: Writeable> Writeable for HashInput<'_, T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(MWIXNET_PROTOCOL_VERSION)?;
		writer.write_u8(self.msg_type as u8)?;
		self.payload.write(writer)
	}
}

impl<T: Writeable> DefaultHashable for HashInput<'_, T> {}

/// Hash a canonical protocol payload.
pub fn hash<T: Writeable>(msg_type: MwixnetType, payload: &T) -> Hash {
	let hash: GrinHash = HashInput { msg_type, payload }.hash();
	Hash(<[u8; 32]>::try_from(hash.as_bytes()).unwrap())
}

/// Verify a protocol signature.
pub fn verify_signature(
	hash: Hash,
	public_key: PublicKey,
	signature: Signature,
) -> Result<(), Error> {
	let public_key =
		VerifyingKey::from_bytes(&public_key.0).map_err(|_| Error::InvalidSignature)?;
	let signature = DalekSignature::from_bytes(&signature.0);
	public_key
		.verify_strict(hash.as_bytes(), &signature)
		.map_err(|_| Error::InvalidSignature)
}

fn write_header<W: Writer>(
	writer: &mut W,
	version: u32,
	msg_type: MwixnetType,
) -> Result<(), ser::Error> {
	writer.write_u32(version)?;
	writer.write_u8(msg_type as u8)
}

fn read_header<R: Reader>(
	reader: &mut R,
	expected: MwixnetType,
) -> Result<(u32, MwixnetType), ser::Error> {
	let version = reader.read_u32()?;
	if version != MWIXNET_PROTOCOL_VERSION {
		return Err(ser::Error::UnsupportedProtocolVersion);
	}
	let msg_type = MwixnetType::try_from(reader.read_u8()?)?;
	if msg_type != expected {
		return Err(ser::Error::CorruptedData);
	}
	Ok((version, msg_type))
}

fn write_keys<W: Writer>(writer: &mut W, keys: &[PublicKey]) -> Result<(), ser::Error> {
	if keys.len() > MAX_ROUTE_HOPS {
		return Err(ser::Error::CountError);
	}
	writer.write_u16(keys.len() as u16)?;
	for key in keys {
		key.write(writer)?;
	}
	Ok(())
}

fn read_keys<R: Reader>(reader: &mut R) -> Result<Vec<PublicKey>, ser::Error> {
	let count = reader.read_u16()? as usize;
	if count > MAX_ROUTE_HOPS {
		return Err(ser::Error::CountError);
	}
	(0..count).map(|_| PublicKey::read(reader)).collect()
}

fn write_option_hash<W: Writer>(writer: &mut W, value: Option<Hash>) -> Result<(), ser::Error> {
	match value {
		None => writer.write_u8(0),
		Some(hash) => {
			writer.write_u8(1)?;
			hash.write(writer)
		}
	}
}

fn read_option_hash<R: Reader>(reader: &mut R) -> Result<Option<Hash>, ser::Error> {
	match reader.read_u8()? {
		0 => Ok(None),
		1 => Ok(Some(Hash::read(reader)?)),
		_ => Err(ser::Error::CorruptedData),
	}
}

fn valid_common(version: u32, msg_type: MwixnetType, expected: MwixnetType) -> bool {
	version == MWIXNET_PROTOCOL_VERSION && msg_type == expected
}

fn valid_times(last_verified: u64, valid_until: u64, now: u64) -> bool {
	last_verified <= now.saturating_add(MAX_CLOCK_SKEW)
		&& valid_until > now
		&& valid_until <= last_verified.saturating_add(MAX_ROUTE_ANNOUNCEMENT_VALIDITY)
}

impl RouteAnnouncement {
	fn read_body<R: Reader>(
		reader: &mut R,
		version: u32,
		msg_type: MwixnetType,
	) -> Result<Self, ser::Error> {
		let route_id = Hash::read(reader)?;
		let manifest_sequence = reader.read_u64()?;
		let entry_onion = OnionAddress::read(reader)?;
		let swap_identity = PublicKey::read(reader)?;
		let hop_count = reader.read_u8()?;
		let participant_identities = read_keys(reader)?;
		let fee_per_hop = reader.read_u64()?;
		let manifest_hash = Hash::read(reader)?;
		let health_hash = Hash::read(reader)?;
		let status = RouteState::try_from(reader.read_u8()?)?;
		let last_verified = reader.read_u64()?;
		let valid_until = reader.read_u64()?;
		let sequence = reader.read_u64()?;
		let signature = Signature::read(reader)?;
		Ok(Self {
			version,
			msg_type,
			route_id,
			manifest_sequence,
			entry_onion,
			swap_identity,
			hop_count,
			participant_identities,
			fee_per_hop,
			manifest_hash,
			health_hash,
			status,
			last_verified,
			valid_until,
			sequence,
			signature,
		})
	}

	fn payload(&self) -> RouteAnnouncementPayload<'_> {
		RouteAnnouncementPayload(self)
	}

	pub fn hash(&self) -> Hash {
		hash(MwixnetType::RouteAnnouncement, &self.payload())
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteAnnouncement) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 || self.sequence == 0 {
			return Err(Error::InvalidMessage("sequence"));
		}
		if self.hop_count as usize != self.participant_identities.len()
			|| !(MIN_ROUTE_HOPS..=MAX_ROUTE_HOPS).contains(&self.participant_identities.len())
		{
			return Err(Error::InvalidMessage("participants"));
		}
		let mut identities = HashSet::new();
		if self
			.participant_identities
			.iter()
			.any(|identity| !identities.insert(*identity))
		{
			return Err(Error::InvalidMessage("duplicate participant"));
		}
		if self
			.participant_identities
			.iter()
			.any(|identity| VerifyingKey::from_bytes(&identity.0).is_err())
		{
			return Err(Error::InvalidMessage("participant identity"));
		}
		if self.participant_identities.first() != Some(&self.swap_identity)
			|| self.entry_onion.0 != self.swap_identity.0
		{
			return Err(Error::InvalidMessage("swap identity"));
		}
		if !matches!(self.status, RouteState::Healthy | RouteState::Degraded) {
			return Err(Error::InvalidMessage("status"));
		}
		if !valid_times(self.last_verified, self.valid_until, now) {
			return Err(Error::InvalidMessage("validity"));
		}
		verify_signature(self.hash(), self.swap_identity, self.signature)
	}
}

struct RouteAnnouncementPayload<'a>(&'a RouteAnnouncement);

impl Writeable for RouteAnnouncementPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.entry_onion.write(writer)?;
		item.swap_identity.write(writer)?;
		writer.write_u8(item.hop_count)?;
		write_keys(writer, &item.participant_identities)?;
		writer.write_u64(item.fee_per_hop)?;
		item.manifest_hash.write(writer)?;
		item.health_hash.write(writer)?;
		writer.write_u8(item.status as u8)?;
		writer.write_u64(item.last_verified)?;
		writer.write_u64(item.valid_until)?;
		writer.write_u64(item.sequence)
	}
}

impl Writeable for RouteAnnouncement {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		self.payload().write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for RouteAnnouncement {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteAnnouncement)?;
		Self::read_body(reader, version, msg_type)
	}
}

impl RouteStatus {
	fn read_body<R: Reader>(
		reader: &mut R,
		version: u32,
		msg_type: MwixnetType,
	) -> Result<Self, ser::Error> {
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			manifest_hash: Hash::read(reader)?,
			status: RouteState::try_from(reader.read_u8()?)?,
			last_verified: reader.read_u64()?,
			valid_until: reader.read_u64()?,
			sequence: reader.read_u64()?,
			swap_identity: PublicKey::read(reader)?,
			signature: Signature::read(reader)?,
		})
	}

	fn payload(&self) -> RouteStatusPayload<'_> {
		RouteStatusPayload(self)
	}

	pub fn hash(&self) -> Hash {
		hash(MwixnetType::RouteStatus, &self.payload())
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteStatus) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 || self.sequence == 0 {
			return Err(Error::InvalidMessage("sequence"));
		}
		if !matches!(
			self.status,
			RouteState::Degraded
				| RouteState::Unavailable
				| RouteState::Draining
				| RouteState::Expired
		) {
			return Err(Error::InvalidMessage("status"));
		}
		if !valid_times(self.last_verified, self.valid_until, now) {
			return Err(Error::InvalidMessage("validity"));
		}
		verify_signature(self.hash(), self.swap_identity, self.signature)
	}
}

struct RouteStatusPayload<'a>(&'a RouteStatus);

impl Writeable for RouteStatusPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.manifest_hash.write(writer)?;
		writer.write_u8(item.status as u8)?;
		writer.write_u64(item.last_verified)?;
		writer.write_u64(item.valid_until)?;
		writer.write_u64(item.sequence)?;
		item.swap_identity.write(writer)
	}
}

impl Writeable for RouteStatus {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		self.payload().write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for RouteStatus {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteStatus)?;
		Self::read_body(reader, version, msg_type)
	}
}

impl RouteRevocation {
	fn read_body<R: Reader>(
		reader: &mut R,
		version: u32,
		msg_type: MwixnetType,
	) -> Result<Self, ser::Error> {
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			manifest_hash: Hash::read(reader)?,
			participant_identity: PublicKey::read(reader)?,
			revoked_at: reader.read_u64()?,
			sequence: reader.read_u64()?,
			signature: Signature::read(reader)?,
		})
	}

	fn payload(&self) -> RouteRevocationPayload<'_> {
		RouteRevocationPayload(self)
	}

	pub fn hash(&self) -> Hash {
		hash(MwixnetType::RouteRevocation, &self.payload())
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteRevocation) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 || self.sequence == 0 {
			return Err(Error::InvalidMessage("sequence"));
		}
		if self.revoked_at > now.saturating_add(MAX_CLOCK_SKEW) {
			return Err(Error::InvalidMessage("revocation time"));
		}
		verify_signature(self.hash(), self.participant_identity, self.signature)
	}
}

struct RouteRevocationPayload<'a>(&'a RouteRevocation);

impl Writeable for RouteRevocationPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.manifest_hash.write(writer)?;
		item.participant_identity.write(writer)?;
		writer.write_u64(item.revoked_at)?;
		writer.write_u64(item.sequence)
	}
}

impl Writeable for RouteRevocation {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		self.payload().write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for RouteRevocation {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteRevocation)?;
		Self::read_body(reader, version, msg_type)
	}
}

impl Writeable for RouteRelayItem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			Self::Announcement(item) => item.write(writer),
			Self::Status(item) => item.write(writer),
			Self::Revocation(item) => item.write(writer),
		}
	}
}

impl Readable for RouteRelayItem {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u32()?;
		if version != MWIXNET_PROTOCOL_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}
		let msg_type = MwixnetType::try_from(reader.read_u8()?)?;
		match msg_type {
			MwixnetType::RouteAnnouncement => Ok(Self::Announcement(RouteAnnouncement::read_body(
				reader, version, msg_type,
			)?)),
			MwixnetType::RouteStatus => Ok(Self::Status(RouteStatus::read_body(
				reader, version, msg_type,
			)?)),
			MwixnetType::RouteRevocation => Ok(Self::Revocation(RouteRevocation::read_body(
				reader, version, msg_type,
			)?)),
			_ => Err(ser::Error::CorruptedData),
		}
	}
}

impl Writeable for GetMwixnetRoutes {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.version)?;
		writer.write_u64(self.request_id)?;
		write_option_hash(writer, self.cursor)?;
		writer.write_u16(self.limit)
	}
}

impl Readable for GetMwixnetRoutes {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let item = Self {
			version: reader.read_u32()?,
			request_id: reader.read_u64()?,
			cursor: read_option_hash(reader)?,
			limit: reader.read_u16()?,
		};
		if item.version != MWIXNET_PROTOCOL_VERSION
			|| item.request_id == 0
			|| item.limit == 0
			|| item.limit as usize > P2P_BATCH_MAX_ROUTES
		{
			return Err(ser::Error::CorruptedData);
		}
		Ok(item)
	}
}

impl Writeable for MwixnetRoutes {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.items.len() > P2P_BATCH_MAX_ROUTES * (MAX_ROUTE_HOPS + 2)
			|| self
				.items
				.iter()
				.map(RouteRelayItem::route_id)
				.collect::<std::collections::HashSet<_>>()
				.len() > P2P_BATCH_MAX_ROUTES
		{
			return Err(ser::Error::CountError);
		}
		writer.write_u32(self.version)?;
		writer.write_u64(self.request_id)?;
		write_option_hash(writer, self.next_cursor)?;
		writer.write_u16(self.items.len() as u16)?;
		for item in &self.items {
			item.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for MwixnetRoutes {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u32()?;
		let request_id = reader.read_u64()?;
		let next_cursor = read_option_hash(reader)?;
		let count = reader.read_u16()? as usize;
		if version != MWIXNET_PROTOCOL_VERSION
			|| request_id == 0
			|| count > P2P_BATCH_MAX_ROUTES * (MAX_ROUTE_HOPS + 2)
		{
			return Err(ser::Error::CorruptedData);
		}
		let items: Vec<RouteRelayItem> = (0..count)
			.map(|_| RouteRelayItem::read(reader))
			.collect::<Result<_, _>>()?;
		if items
			.iter()
			.map(RouteRelayItem::route_id)
			.collect::<std::collections::HashSet<_>>()
			.len() > P2P_BATCH_MAX_ROUTES
		{
			return Err(ser::Error::CountError);
		}
		Ok(Self {
			version,
			request_id,
			next_cursor,
			items,
		})
	}
}

struct OfferPowPayload<'a>(&'a OfferAnnouncement);

impl Writeable for OfferPowPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.0.offer.hash().write(writer)?;
		writer.write_u64(self.0.pow_nonce)
	}
}

impl OfferAnnouncement {
	pub fn mine(offer: MwixnetOffer) -> Self {
		let mut item = Self {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::OfferAnnouncement,
			offer,
			pow_nonce: 0,
		};
		while !item.has_valid_pow() {
			item.pow_nonce = item.pow_nonce.wrapping_add(1);
		}
		item
	}

	pub fn offer_id(&self) -> Hash {
		self.offer.hash()
	}

	pub fn pow_hash(&self) -> Hash {
		hash(MwixnetType::OfferAnnouncement, &OfferPowPayload(self))
	}

	pub fn has_valid_pow(&self) -> bool {
		self.pow_hash().0[..OFFER_POW_DIFFICULTY_BITS / 8]
			.iter()
			.all(|byte| *byte == 0)
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::OfferAnnouncement) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.offer.valid_until() > now.saturating_add(MAX_OFFER_ANNOUNCEMENT_VALIDITY) {
			return Err(Error::InvalidMessage("offer validity"));
		}
		if !self.has_valid_pow() {
			return Err(Error::InvalidMessage("proof of work"));
		}
		self.offer.validate(now)
	}
}

impl Writeable for OfferAnnouncement {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		self.offer.write(writer)?;
		writer.write_u64(self.pow_nonce)
	}
}

impl Readable for OfferAnnouncement {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::OfferAnnouncement)?;
		Ok(Self {
			version,
			msg_type,
			offer: MwixnetOffer::read(reader)?,
			pow_nonce: reader.read_u64()?,
		})
	}
}

impl Writeable for GetMwixnetOffers {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.version)?;
		writer.write_u64(self.request_id)?;
		write_option_hash(writer, self.cursor)?;
		writer.write_u16(self.limit)
	}
}

impl Readable for GetMwixnetOffers {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let item = Self {
			version: reader.read_u32()?,
			request_id: reader.read_u64()?,
			cursor: read_option_hash(reader)?,
			limit: reader.read_u16()?,
		};
		if item.version != MWIXNET_PROTOCOL_VERSION
			|| item.request_id == 0
			|| item.limit == 0
			|| item.limit as usize > P2P_OFFER_BATCH_MAX_ITEMS
		{
			return Err(ser::Error::CorruptedData);
		}
		Ok(item)
	}
}

impl Writeable for MwixnetOffers {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.items.len() > P2P_OFFER_BATCH_MAX_ITEMS {
			return Err(ser::Error::CountError);
		}
		writer.write_u32(self.version)?;
		writer.write_u64(self.request_id)?;
		write_option_hash(writer, self.next_cursor)?;
		writer.write_u16(self.items.len() as u16)?;
		for item in &self.items {
			item.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for MwixnetOffers {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u32()?;
		let request_id = reader.read_u64()?;
		let next_cursor = read_option_hash(reader)?;
		let count = reader.read_u16()? as usize;
		if version != MWIXNET_PROTOCOL_VERSION
			|| request_id == 0
			|| count > P2P_OFFER_BATCH_MAX_ITEMS
		{
			return Err(ser::Error::CorruptedData);
		}
		let items = (0..count)
			.map(|_| OfferAnnouncement::read(reader))
			.collect::<Result<_, _>>()?;
		Ok(Self {
			version,
			request_id,
			next_cursor,
			items,
		})
	}
}
