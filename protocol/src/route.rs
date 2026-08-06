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

//! Route offers and manifests.

use super::*;
use std::collections::HashSet;

/// Mixer availability offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixerOffer {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub identity_public_key: PublicKey,
	pub onion_address: OnionAddress,
	pub onion_public_key: OnionPublicKey,
	#[serde(with = "u64_serde")]
	pub minimum_fee: u64,
	pub capacity: u32,
	#[serde(with = "u64_serde")]
	pub valid_until: u64,
	#[serde(with = "u64_serde")]
	pub sequence: u64,
	pub signature: Signature,
}

/// Swap-server availability offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapOffer {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub identity_public_key: PublicKey,
	pub onion_address: OnionAddress,
	pub onion_public_key: OnionPublicKey,
	#[serde(with = "u64_serde")]
	pub minimum_fee: u64,
	pub capacity: u32,
	pub desired_min_hops: Option<u8>,
	pub desired_max_hops: Option<u8>,
	#[serde(with = "optional_u64_serde")]
	pub maximum_fee_per_hop: Option<u64>,
	pub max_request_ttl_blocks: u16,
	#[serde(with = "u64_serde")]
	pub valid_until: u64,
	#[serde(with = "u64_serde")]
	pub sequence: u64,
	pub signature: Signature,
}

/// Mixer or swap-server offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MwixnetOffer {
	Mixer(MixerOffer),
	Swap(SwapOffer),
}

/// Server position in a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteHop {
	pub role: RouteRole,
	pub identity_public_key: PublicKey,
	pub onion_address: OnionAddress,
	pub onion_public_key: OnionPublicKey,
}

/// Route proposed by the swap server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteProposal {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	#[serde(with = "u64_serde")]
	pub valid_from: u64,
	#[serde(with = "u64_serde")]
	pub valid_until: u64,
	#[serde(with = "u64_serde")]
	pub fee_per_hop: u64,
	pub ordered_hops: Vec<RouteHop>,
	pub proposer_signature: Signature,
}

/// Participant acceptance of a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAcceptance {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub proposal_hash: Hash,
	pub participant_identity: PublicKey,
	#[serde(with = "u64_serde")]
	pub accepted_until: u64,
	pub signature: Signature,
}

/// Fully accepted route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteManifest {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub proposal_hash: Hash,
	#[serde(with = "u64_serde")]
	pub valid_from: u64,
	#[serde(with = "u64_serde")]
	pub valid_until: u64,
	#[serde(with = "u64_serde")]
	pub fee_per_hop: u64,
	pub ordered_hops: Vec<RouteHop>,
	pub proposer_signature: Signature,
	pub acceptances: Vec<RouteAcceptance>,
	pub swap_identity: PublicKey,
	pub signature: Signature,
}

mod optional_u64_serde {
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match value {
			Some(value) => serializer.serialize_some(&value.to_string()),
			None => serializer.serialize_none(),
		}
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<super::u64_serde::StringOrU64>::deserialize(deserializer)?.map_or(
			Ok(None),
			|value| match value {
				super::u64_serde::StringOrU64::String(value) => {
					value.parse().map(Some).map_err(serde::de::Error::custom)
				}
				super::u64_serde::StringOrU64::U64(value) => Ok(Some(value)),
			},
		)
	}
}

fn write_option_u8<W: Writer>(writer: &mut W, value: Option<u8>) -> Result<(), ser::Error> {
	match value {
		Some(value) => {
			writer.write_u8(1)?;
			writer.write_u8(value)
		}
		None => writer.write_u8(0),
	}
}

fn read_option_u8<R: Reader>(reader: &mut R) -> Result<Option<u8>, ser::Error> {
	match reader.read_u8()? {
		0 => Ok(None),
		1 => Ok(Some(reader.read_u8()?)),
		_ => Err(ser::Error::CorruptedData),
	}
}

fn write_option_u64<W: Writer>(writer: &mut W, value: Option<u64>) -> Result<(), ser::Error> {
	match value {
		Some(value) => {
			writer.write_u8(1)?;
			writer.write_u64(value)
		}
		None => writer.write_u8(0),
	}
}

fn read_option_u64<R: Reader>(reader: &mut R) -> Result<Option<u64>, ser::Error> {
	match reader.read_u8()? {
		0 => Ok(None),
		1 => Ok(Some(reader.read_u64()?)),
		_ => Err(ser::Error::CorruptedData),
	}
}

fn write_hops<W: Writer>(writer: &mut W, hops: &[RouteHop]) -> Result<(), ser::Error> {
	if hops.len() > MAX_ROUTE_HOPS {
		return Err(ser::Error::CountError);
	}
	writer.write_u16(hops.len() as u16)?;
	for hop in hops {
		hop.write(writer)?;
	}
	Ok(())
}

fn read_hops<R: Reader>(reader: &mut R) -> Result<Vec<RouteHop>, ser::Error> {
	let count = reader.read_u16()? as usize;
	if count > MAX_ROUTE_HOPS {
		return Err(ser::Error::CountError);
	}
	(0..count).map(|_| RouteHop::read(reader)).collect()
}

fn validate_offer(
	identity: PublicKey,
	onion: OnionAddress,
	key: OnionPublicKey,
	until: u64,
	sequence: u64,
	now: u64,
) -> Result<(), Error> {
	if sequence == 0 {
		return Err(Error::InvalidMessage("offer sequence"));
	}
	if onion.0 != identity.0 || VerifyingKey::from_bytes(&identity.0).is_err() {
		return Err(Error::InvalidMessage("offer identity"));
	}
	if key.0 == [0; 32] {
		return Err(Error::InvalidMessage("onion key"));
	}
	if until <= now || until > now.saturating_add(MAX_MANIFEST_VALIDITY) {
		return Err(Error::InvalidMessage("offer validity"));
	}
	Ok(())
}

impl RouteHop {
	fn valid(&self) -> bool {
		self.onion_address.0 == self.identity_public_key.0
			&& self.onion_public_key.0 != [0; 32]
			&& VerifyingKey::from_bytes(&self.identity_public_key.0).is_ok()
	}
}

impl Writeable for RouteHop {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.role as u8)?;
		self.identity_public_key.write(writer)?;
		self.onion_address.write(writer)?;
		self.onion_public_key.write(writer)
	}
}

impl Readable for RouteHop {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(Self {
			role: RouteRole::try_from(reader.read_u8()?)?,
			identity_public_key: PublicKey::read(reader)?,
			onion_address: OnionAddress::read(reader)?,
			onion_public_key: OnionPublicKey::read(reader)?,
		})
	}
}

struct MixerOfferPayload<'a>(&'a MixerOffer);

impl Writeable for MixerOfferPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.identity_public_key.write(writer)?;
		item.onion_address.write(writer)?;
		item.onion_public_key.write(writer)?;
		writer.write_u64(item.minimum_fee)?;
		writer.write_u32(item.capacity)?;
		writer.write_u64(item.valid_until)?;
		writer.write_u64(item.sequence)
	}
}

impl MixerOffer {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::MixerOffer, &MixerOfferPayload(self))
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::MixerOffer) {
			return Err(Error::InvalidMessage("header"));
		}
		validate_offer(
			self.identity_public_key,
			self.onion_address,
			self.onion_public_key,
			self.valid_until,
			self.sequence,
			now,
		)?;
		verify_signature(self.hash(), self.identity_public_key, self.signature)
	}
}

impl Writeable for MixerOffer {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		MixerOfferPayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for MixerOffer {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::MixerOffer)?;
		Ok(Self {
			version,
			msg_type,
			identity_public_key: PublicKey::read(reader)?,
			onion_address: OnionAddress::read(reader)?,
			onion_public_key: OnionPublicKey::read(reader)?,
			minimum_fee: reader.read_u64()?,
			capacity: reader.read_u32()?,
			valid_until: reader.read_u64()?,
			sequence: reader.read_u64()?,
			signature: Signature::read(reader)?,
		})
	}
}

struct SwapOfferPayload<'a>(&'a SwapOffer);

impl Writeable for SwapOfferPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.identity_public_key.write(writer)?;
		item.onion_address.write(writer)?;
		item.onion_public_key.write(writer)?;
		writer.write_u64(item.minimum_fee)?;
		writer.write_u32(item.capacity)?;
		write_option_u8(writer, item.desired_min_hops)?;
		write_option_u8(writer, item.desired_max_hops)?;
		write_option_u64(writer, item.maximum_fee_per_hop)?;
		writer.write_u16(item.max_request_ttl_blocks)?;
		writer.write_u64(item.valid_until)?;
		writer.write_u64(item.sequence)
	}
}

impl SwapOffer {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::SwapOffer, &SwapOfferPayload(self))
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		let desired = match (self.desired_min_hops, self.desired_max_hops) {
			(Some(min), Some(max)) => {
				min >= MIN_ROUTE_HOPS as u8 && min <= max && max <= MAX_ROUTE_HOPS as u8
			}
			(Some(min), None) => min >= MIN_ROUTE_HOPS as u8 && min <= MAX_ROUTE_HOPS as u8,
			(None, Some(max)) => max >= MIN_ROUTE_HOPS as u8 && max <= MAX_ROUTE_HOPS as u8,
			(None, None) => true,
		};
		if !valid_common(self.version, self.msg_type, MwixnetType::SwapOffer) {
			return Err(Error::InvalidMessage("header"));
		}
		validate_offer(
			self.identity_public_key,
			self.onion_address,
			self.onion_public_key,
			self.valid_until,
			self.sequence,
			now,
		)?;
		if !desired {
			return Err(Error::InvalidMessage("desired hops"));
		}
		if !(MIN_REQUEST_TTL_BLOCKS..=MAX_REQUEST_TTL_BLOCKS).contains(&self.max_request_ttl_blocks)
		{
			return Err(Error::InvalidMessage("request ttl"));
		}
		verify_signature(self.hash(), self.identity_public_key, self.signature)
	}
}

impl Writeable for SwapOffer {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		SwapOfferPayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for SwapOffer {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::SwapOffer)?;
		Ok(Self {
			version,
			msg_type,
			identity_public_key: PublicKey::read(reader)?,
			onion_address: OnionAddress::read(reader)?,
			onion_public_key: OnionPublicKey::read(reader)?,
			minimum_fee: reader.read_u64()?,
			capacity: reader.read_u32()?,
			desired_min_hops: read_option_u8(reader)?,
			desired_max_hops: read_option_u8(reader)?,
			maximum_fee_per_hop: read_option_u64(reader)?,
			max_request_ttl_blocks: reader.read_u16()?,
			valid_until: reader.read_u64()?,
			sequence: reader.read_u64()?,
			signature: Signature::read(reader)?,
		})
	}
}

impl MwixnetOffer {
	pub fn hash(&self) -> Hash {
		match self {
			Self::Mixer(offer) => offer.hash(),
			Self::Swap(offer) => offer.hash(),
		}
	}

	pub fn sequence(&self) -> u64 {
		match self {
			Self::Mixer(offer) => offer.sequence,
			Self::Swap(offer) => offer.sequence,
		}
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		match self {
			Self::Mixer(offer) => offer.validate(now),
			Self::Swap(offer) => offer.validate(now),
		}
	}

	pub fn identity(&self) -> PublicKey {
		match self {
			Self::Mixer(offer) => offer.identity_public_key,
			Self::Swap(offer) => offer.identity_public_key,
		}
	}

	pub fn valid_until(&self) -> u64 {
		match self {
			Self::Mixer(offer) => offer.valid_until,
			Self::Swap(offer) => offer.valid_until,
		}
	}

	pub fn minimum_fee(&self) -> u64 {
		match self {
			Self::Mixer(offer) => offer.minimum_fee,
			Self::Swap(offer) => offer.minimum_fee,
		}
	}
}

impl Writeable for MwixnetOffer {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			Self::Mixer(offer) => offer.write(writer),
			Self::Swap(offer) => offer.write(writer),
		}
	}
}

impl Readable for MwixnetOffer {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u32()?;
		if version != MWIXNET_PROTOCOL_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}
		let msg_type = MwixnetType::try_from(reader.read_u8()?)?;
		match msg_type {
			MwixnetType::MixerOffer => Ok(Self::Mixer(MixerOffer {
				version,
				msg_type,
				identity_public_key: PublicKey::read(reader)?,
				onion_address: OnionAddress::read(reader)?,
				onion_public_key: OnionPublicKey::read(reader)?,
				minimum_fee: reader.read_u64()?,
				capacity: reader.read_u32()?,
				valid_until: reader.read_u64()?,
				sequence: reader.read_u64()?,
				signature: Signature::read(reader)?,
			})),
			MwixnetType::SwapOffer => Ok(Self::Swap(SwapOffer {
				version,
				msg_type,
				identity_public_key: PublicKey::read(reader)?,
				onion_address: OnionAddress::read(reader)?,
				onion_public_key: OnionPublicKey::read(reader)?,
				minimum_fee: reader.read_u64()?,
				capacity: reader.read_u32()?,
				desired_min_hops: read_option_u8(reader)?,
				desired_max_hops: read_option_u8(reader)?,
				maximum_fee_per_hop: read_option_u64(reader)?,
				max_request_ttl_blocks: reader.read_u16()?,
				valid_until: reader.read_u64()?,
				sequence: reader.read_u64()?,
				signature: Signature::read(reader)?,
			})),
			_ => Err(ser::Error::CorruptedData),
		}
	}
}

struct RouteIdPayload<'a> {
	fee_per_hop: u64,
	hops: &'a [RouteHop],
}

impl Writeable for RouteIdPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.fee_per_hop)?;
		writer.write_u16(self.hops.len() as u16)?;
		for hop in self.hops {
			writer.write_u8(hop.role as u8)?;
			hop.identity_public_key.write(writer)?;
			hop.onion_public_key.write(writer)?;
		}
		Ok(())
	}
}

/// Derive the stable ID for a route.
pub fn route_id(fee_per_hop: u64, hops: &[RouteHop]) -> Result<Hash, Error> {
	if hops.len() < MIN_ROUTE_HOPS || hops.len() > MAX_ROUTE_HOPS {
		return Err(Error::InvalidMessage("route length"));
	}
	Ok(hash(
		MwixnetType::RouteId,
		&RouteIdPayload { fee_per_hop, hops },
	))
}

struct RouteProposalPayload<'a>(&'a RouteProposal);

impl Writeable for RouteProposalPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		writer.write_u64(item.valid_from)?;
		writer.write_u64(item.valid_until)?;
		writer.write_u64(item.fee_per_hop)?;
		write_hops(writer, &item.ordered_hops)
	}
}

impl RouteProposal {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::RouteProposal, &RouteProposalPayload(self))
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteProposal) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 {
			return Err(Error::InvalidMessage("manifest sequence"));
		}
		if !(MIN_ROUTE_HOPS..=MAX_ROUTE_HOPS).contains(&self.ordered_hops.len()) {
			return Err(Error::InvalidMessage("route length"));
		}
		if self.ordered_hops.first().map(|hop| hop.role) != Some(RouteRole::Swap)
			|| self
				.ordered_hops
				.iter()
				.skip(1)
				.any(|hop| hop.role != RouteRole::Mixer)
		{
			return Err(Error::InvalidMessage("route roles"));
		}
		if self.ordered_hops.iter().any(|hop| !hop.valid()) {
			return Err(Error::InvalidMessage("route hop"));
		}
		let identities = self
			.ordered_hops
			.iter()
			.map(|hop| hop.identity_public_key)
			.collect::<HashSet<_>>();
		if identities.len() != self.ordered_hops.len() {
			return Err(Error::InvalidMessage("duplicate route hop"));
		}
		if self.valid_from > now.saturating_add(MAX_CLOCK_SKEW)
			|| self.valid_until <= self.valid_from
			|| self.valid_until > self.valid_from.saturating_add(MAX_MANIFEST_VALIDITY)
			|| self.valid_until <= now
		{
			return Err(Error::InvalidMessage("route validity"));
		}
		if route_id(self.fee_per_hop, &self.ordered_hops)? != self.route_id {
			return Err(Error::InvalidMessage("route id"));
		}
		verify_signature(
			self.hash(),
			self.ordered_hops[0].identity_public_key,
			self.proposer_signature,
		)
	}
}

impl Writeable for RouteProposal {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		RouteProposalPayload(self).write(writer)?;
		self.proposer_signature.write(writer)
	}
}

impl Readable for RouteProposal {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteProposal)?;
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			valid_from: reader.read_u64()?,
			valid_until: reader.read_u64()?,
			fee_per_hop: reader.read_u64()?,
			ordered_hops: read_hops(reader)?,
			proposer_signature: Signature::read(reader)?,
		})
	}
}

struct RouteAcceptancePayload<'a>(&'a RouteAcceptance);

impl Writeable for RouteAcceptancePayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.proposal_hash.write(writer)?;
		item.participant_identity.write(writer)?;
		writer.write_u64(item.accepted_until)
	}
}

impl RouteAcceptance {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::RouteAcceptance, &RouteAcceptancePayload(self))
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteAcceptance) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 {
			return Err(Error::InvalidMessage("manifest sequence"));
		}
		if self.accepted_until <= now
			|| self.accepted_until > now.saturating_add(MAX_MANIFEST_VALIDITY)
		{
			return Err(Error::InvalidMessage("acceptance validity"));
		}
		verify_signature(self.hash(), self.participant_identity, self.signature)
	}
}

impl Writeable for RouteAcceptance {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		RouteAcceptancePayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for RouteAcceptance {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteAcceptance)?;
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			proposal_hash: Hash::read(reader)?,
			participant_identity: PublicKey::read(reader)?,
			accepted_until: reader.read_u64()?,
			signature: Signature::read(reader)?,
		})
	}
}

struct RouteManifestPayload<'a>(&'a RouteManifest);

impl Writeable for RouteManifestPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.proposal_hash.write(writer)?;
		writer.write_u64(item.valid_from)?;
		writer.write_u64(item.valid_until)?;
		writer.write_u64(item.fee_per_hop)?;
		write_hops(writer, &item.ordered_hops)?;
		item.proposer_signature.write(writer)?;
		writer.write_u16(item.acceptances.len() as u16)?;
		for acceptance in &item.acceptances {
			acceptance.write(writer)?;
		}
		item.swap_identity.write(writer)
	}
}

impl RouteManifest {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::RouteManifest, &RouteManifestPayload(self))
	}

	pub fn proposal(&self) -> RouteProposal {
		RouteProposal {
			version: self.version,
			msg_type: MwixnetType::RouteProposal,
			route_id: self.route_id,
			manifest_sequence: self.manifest_sequence,
			valid_from: self.valid_from,
			valid_until: self.valid_until,
			fee_per_hop: self.fee_per_hop,
			ordered_hops: self.ordered_hops.clone(),
			proposer_signature: self.proposer_signature,
		}
	}

	pub fn validate(&self, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteManifest) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.acceptances.len() != self.ordered_hops.len() {
			return Err(Error::InvalidMessage("acceptance count"));
		}
		let first = self
			.ordered_hops
			.first()
			.ok_or(Error::InvalidMessage("empty route"))?;
		if self.swap_identity != first.identity_public_key {
			return Err(Error::InvalidMessage("swap identity"));
		}
		let proposal = self.proposal();
		proposal.validate(now)?;
		if proposal.hash() != self.proposal_hash {
			return Err(Error::InvalidMessage("proposal hash"));
		}
		let mut accepted = HashSet::new();
		for acceptance in &self.acceptances {
			acceptance.validate(now)?;
			if acceptance.route_id != self.route_id
				|| acceptance.manifest_sequence != self.manifest_sequence
				|| acceptance.proposal_hash != self.proposal_hash
			{
				return Err(Error::InvalidMessage("acceptance binding"));
			}
			if acceptance.accepted_until < self.valid_until {
				return Err(Error::InvalidMessage("acceptance validity"));
			}
			if !self
				.ordered_hops
				.iter()
				.any(|hop| hop.identity_public_key == acceptance.participant_identity)
			{
				return Err(Error::InvalidMessage("acceptance identity"));
			}
			if !accepted.insert(acceptance.participant_identity) {
				return Err(Error::InvalidMessage("duplicate acceptance"));
			}
		}
		verify_signature(self.hash(), self.swap_identity, self.signature)
	}
}

impl Writeable for RouteManifest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.acceptances.len() > MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		write_header(writer, self.version, self.msg_type)?;
		RouteManifestPayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for RouteManifest {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteManifest)?;
		let route_id = Hash::read(reader)?;
		let manifest_sequence = reader.read_u64()?;
		let proposal_hash = Hash::read(reader)?;
		let valid_from = reader.read_u64()?;
		let valid_until = reader.read_u64()?;
		let fee_per_hop = reader.read_u64()?;
		let ordered_hops = read_hops(reader)?;
		let proposer_signature = Signature::read(reader)?;
		let count = reader.read_u16()? as usize;
		if count > MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		let acceptances = (0..count)
			.map(|_| RouteAcceptance::read(reader))
			.collect::<Result<_, _>>()?;
		Ok(Self {
			version,
			msg_type,
			route_id,
			manifest_sequence,
			proposal_hash,
			valid_from,
			valid_until,
			fee_per_hop,
			ordered_hops,
			proposer_signature,
			acceptances,
			swap_identity: PublicKey::read(reader)?,
			signature: Signature::read(reader)?,
		})
	}
}
