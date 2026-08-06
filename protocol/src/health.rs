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

//! End-to-end route health protocol.

use super::*;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use grin_core::ser::ProtocolVersion;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// ChaCha20-Poly1305 nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AeadNonce(pub [u8; 12]);

impl fmt::Debug for AeadNonce {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0.to_hex())
	}
}

impl Serialize for AeadNonce {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.0.to_hex())
	}
}

impl<'de> Deserialize<'de> for AeadNonce {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = from_hex(&value).map_err(D::Error::custom)?;
		Ok(Self(<[u8; 12]>::try_from(bytes.as_slice()).map_err(
			|_| D::Error::custom("invalid AEAD nonce length"),
		)?))
	}
}

impl Writeable for AeadNonce {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.0)
	}
}

impl Readable for AeadNonce {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let bytes = reader.read_fixed_bytes(12)?;
		Ok(Self(<[u8; 12]>::try_from(bytes.as_slice()).unwrap()))
	}
}

/// Swap-server health challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthChallenge {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub nonce: Hash,
	#[serde(with = "u64_serde")]
	pub created_at: u64,
	#[serde(with = "u64_serde")]
	pub expires_at: u64,
	pub signature: Signature,
}

/// Encrypted health onion layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthLayer {
	pub ephemeral_public_key: OnionPublicKey,
	pub aead_nonce: AeadNonce,
	#[serde(with = "bytes_serde")]
	pub ciphertext: Vec<u8>,
}

/// Plaintext carried by a health layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthLayerPayload {
	pub hop_nonce: Hash,
	#[serde(default, with = "optional_bytes_serde")]
	pub next_layer: Option<Vec<u8>>,
}

/// Health request forwarded between mixers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRequest {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub challenge_hash: Hash,
	pub challenge_signature: Signature,
	pub hop_position: u8,
	pub layer: HealthLayer,
	pub sender_identity: PublicKey,
	pub sender_signature: Signature,
}

/// Signed health observation by a mixer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthAttestation {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub challenge_hash: Hash,
	pub hop_nonce_hash: Hash,
	pub hop_position: u8,
	pub participant_identity: PublicKey,
	#[serde(with = "u64_serde")]
	pub observed_at: u64,
	pub next_attestation_hash: Option<Hash>,
	pub signature: Signature,
}

/// Ordered health attestations returned to the swap server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub challenge_hash: Hash,
	pub attestations: Vec<HealthAttestation>,
}

/// Swap-server certificate for a successful probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteHealthCertificate {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub route_id: Hash,
	#[serde(with = "u64_serde")]
	pub manifest_sequence: u64,
	pub challenge_hash: Hash,
	pub attestation_root: Hash,
	#[serde(with = "u64_serde")]
	pub verified_at: u64,
	#[serde(with = "u64_serde")]
	pub expires_at: u64,
	pub swap_identity: PublicKey,
	pub signature: Signature,
}

/// Records proving a successful route probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteHealthProof {
	pub version: u32,
	#[serde(rename = "type")]
	pub msg_type: MwixnetType,
	pub challenge: HealthChallenge,
	pub hop_nonces: Vec<Hash>,
	pub response: HealthResponse,
	pub certificate: RouteHealthCertificate,
}

mod bytes_serde {
	use grin_util::{from_hex, ToHex};
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&value.to_hex())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		from_hex(&value).map_err(serde::de::Error::custom)
	}
}

mod optional_bytes_serde {
	use grin_util::{from_hex, ToHex};
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match value {
			Some(value) => serializer.serialize_some(&value.to_hex()),
			None => serializer.serialize_none(),
		}
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer)?
			.map(|value| from_hex(&value).map_err(serde::de::Error::custom))
			.transpose()
	}
}

fn write_bytes<W: Writer>(writer: &mut W, value: &[u8]) -> Result<(), ser::Error> {
	if value.len() > HEALTH_REQUEST_MAX_BYTES {
		return Err(ser::Error::CountError);
	}
	writer.write_u32(value.len() as u32)?;
	writer.write_fixed_bytes(value)
}

fn read_bytes<R: Reader>(reader: &mut R) -> Result<Vec<u8>, ser::Error> {
	let count = reader.read_u32()? as usize;
	if count > HEALTH_REQUEST_MAX_BYTES {
		return Err(ser::Error::CountError);
	}
	reader.read_fixed_bytes(count)
}

fn write_option_bytes<W: Writer>(
	writer: &mut W,
	value: &Option<Vec<u8>>,
) -> Result<(), ser::Error> {
	match value {
		Some(value) => {
			writer.write_u8(1)?;
			write_bytes(writer, value)
		}
		None => writer.write_u8(0),
	}
}

fn read_option_bytes<R: Reader>(reader: &mut R) -> Result<Option<Vec<u8>>, ser::Error> {
	match reader.read_u8()? {
		0 => Ok(None),
		1 => Ok(Some(read_bytes(reader)?)),
		_ => Err(ser::Error::CorruptedData),
	}
}

impl Writeable for HealthLayer {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.ephemeral_public_key.write(writer)?;
		self.aead_nonce.write(writer)?;
		write_bytes(writer, &self.ciphertext)
	}
}

impl Readable for HealthLayer {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(Self {
			ephemeral_public_key: OnionPublicKey::read(reader)?,
			aead_nonce: AeadNonce::read(reader)?,
			ciphertext: read_bytes(reader)?,
		})
	}
}

impl Writeable for HealthLayerPayload {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.hop_nonce.write(writer)?;
		write_option_bytes(writer, &self.next_layer)
	}
}

impl Readable for HealthLayerPayload {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Ok(Self {
			hop_nonce: Hash::read(reader)?,
			next_layer: read_option_bytes(reader)?,
		})
	}
}

struct HealthChallengePayload<'a>(&'a HealthChallenge);

impl Writeable for HealthChallengePayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.nonce.write(writer)?;
		writer.write_u64(item.created_at)?;
		writer.write_u64(item.expires_at)
	}
}

impl HealthChallenge {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::HealthChallenge, &HealthChallengePayload(self))
	}

	pub fn validate(&self, now: u64, swap_identity: PublicKey) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::HealthChallenge) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 {
			return Err(Error::InvalidMessage("manifest sequence"));
		}
		if self.created_at > now.saturating_add(MAX_CLOCK_SKEW) {
			return Err(Error::InvalidMessage("challenge time"));
		}
		if self.expires_at <= self.created_at
			|| self.expires_at
				> self
					.created_at
					.saturating_add(MAX_HEALTH_CHALLENGE_LIFETIME)
		{
			return Err(Error::InvalidMessage("challenge validity"));
		}
		verify_signature(self.hash(), swap_identity, self.signature)
	}
}

impl Writeable for HealthChallenge {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		HealthChallengePayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for HealthChallenge {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::HealthChallenge)?;
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			nonce: Hash::read(reader)?,
			created_at: reader.read_u64()?,
			expires_at: reader.read_u64()?,
			signature: Signature::read(reader)?,
		})
	}
}

struct HealthRequestPayload<'a>(&'a HealthRequest);

impl Writeable for HealthRequestPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.challenge_hash.write(writer)?;
		item.challenge_signature.write(writer)?;
		writer.write_u8(item.hop_position)?;
		item.layer.write(writer)?;
		item.sender_identity.write(writer)
	}
}

impl HealthRequest {
	pub fn hash(&self) -> Hash {
		hash(MwixnetType::HealthRequest, &HealthRequestPayload(self))
	}

	pub fn validate(&self, predecessor: PublicKey) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::HealthRequest) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.manifest_sequence == 0 {
			return Err(Error::InvalidMessage("manifest sequence"));
		}
		if self.hop_position == 0 || self.hop_position as usize >= MAX_ROUTE_HOPS {
			return Err(Error::InvalidMessage("hop position"));
		}
		if self.sender_identity != predecessor {
			return Err(Error::InvalidMessage("sender identity"));
		}
		if self.layer.ciphertext.len() > HEALTH_REQUEST_MAX_BYTES {
			return Err(Error::InvalidMessage("health layer size"));
		}
		verify_signature(self.hash(), predecessor, self.sender_signature)
	}
}

impl Writeable for HealthRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		HealthRequestPayload(self).write(writer)?;
		self.sender_signature.write(writer)
	}
}

impl Readable for HealthRequest {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::HealthRequest)?;
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			challenge_hash: Hash::read(reader)?,
			challenge_signature: Signature::read(reader)?,
			hop_position: reader.read_u8()?,
			layer: HealthLayer::read(reader)?,
			sender_identity: PublicKey::read(reader)?,
			sender_signature: Signature::read(reader)?,
		})
	}
}

struct HealthAttestationPayload<'a>(&'a HealthAttestation);

impl Writeable for HealthAttestationPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.challenge_hash.write(writer)?;
		item.hop_nonce_hash.write(writer)?;
		writer.write_u8(item.hop_position)?;
		item.participant_identity.write(writer)?;
		writer.write_u64(item.observed_at)?;
		write_option_hash(writer, item.next_attestation_hash)
	}
}

impl HealthAttestation {
	pub fn hash(&self) -> Hash {
		hash(
			MwixnetType::HealthAttestation,
			&HealthAttestationPayload(self),
		)
	}

	pub fn validate(&self, challenge: &HealthChallenge, identity: PublicKey) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::HealthAttestation) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.route_id != challenge.route_id
			|| self.manifest_sequence != challenge.manifest_sequence
			|| self.challenge_hash != challenge.hash()
		{
			return Err(Error::InvalidMessage("challenge binding"));
		}
		if self.participant_identity != identity {
			return Err(Error::InvalidMessage("participant identity"));
		}
		if self.observed_at.saturating_add(MAX_CLOCK_SKEW) < challenge.created_at
			|| self.observed_at > challenge.expires_at.saturating_add(MAX_CLOCK_SKEW)
		{
			return Err(Error::InvalidMessage("observation time"));
		}
		verify_signature(self.hash(), identity, self.signature)
	}
}

impl Writeable for HealthAttestation {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		HealthAttestationPayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for HealthAttestation {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::HealthAttestation)?;
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			challenge_hash: Hash::read(reader)?,
			hop_nonce_hash: Hash::read(reader)?,
			hop_position: reader.read_u8()?,
			participant_identity: PublicKey::read(reader)?,
			observed_at: reader.read_u64()?,
			next_attestation_hash: read_option_hash(reader)?,
			signature: Signature::read(reader)?,
		})
	}
}

fn write_attestations<W: Writer>(
	writer: &mut W,
	values: &[HealthAttestation],
) -> Result<(), ser::Error> {
	if values.len() >= MAX_ROUTE_HOPS {
		return Err(ser::Error::CountError);
	}
	writer.write_u16(values.len() as u16)?;
	for value in values {
		value.write(writer)?;
	}
	Ok(())
}

impl HealthResponse {
	pub fn validate(
		&self,
		manifest: &RouteManifest,
		challenge: &HealthChallenge,
		hop_nonces: &[Hash],
	) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::HealthResponse) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.route_id != manifest.route_id
			|| self.manifest_sequence != manifest.manifest_sequence
			|| self.challenge_hash != challenge.hash()
		{
			return Err(Error::InvalidMessage("challenge binding"));
		}
		if self.attestations.len() != manifest.ordered_hops.len().saturating_sub(1)
			|| self.attestations.len() != hop_nonces.len()
		{
			return Err(Error::InvalidMessage("attestation count"));
		}
		for (index, attestation) in self.attestations.iter().enumerate() {
			let position = index + 1;
			attestation.validate(
				challenge,
				manifest.ordered_hops[position].identity_public_key,
			)?;
			let next = self
				.attestations
				.get(index + 1)
				.map(HealthAttestation::hash);
			if attestation.hop_position as usize != position {
				return Err(Error::InvalidMessage("attestation position"));
			}
			if attestation.hop_nonce_hash != health_hop_nonce_hash(hop_nonces[index]) {
				return Err(Error::InvalidMessage("hop nonce"));
			}
			if attestation.next_attestation_hash != next {
				return Err(Error::InvalidMessage("attestation chain"));
			}
		}
		Ok(())
	}
}

impl Writeable for HealthResponse {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		self.route_id.write(writer)?;
		writer.write_u64(self.manifest_sequence)?;
		self.challenge_hash.write(writer)?;
		write_attestations(writer, &self.attestations)
	}
}

impl Readable for HealthResponse {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::HealthResponse)?;
		let route_id = Hash::read(reader)?;
		let manifest_sequence = reader.read_u64()?;
		let challenge_hash = Hash::read(reader)?;
		let count = reader.read_u16()? as usize;
		if count >= MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		Ok(Self {
			version,
			msg_type,
			route_id,
			manifest_sequence,
			challenge_hash,
			attestations: (0..count)
				.map(|_| HealthAttestation::read(reader))
				.collect::<Result<_, _>>()?,
		})
	}
}

struct RouteHealthCertificatePayload<'a>(&'a RouteHealthCertificate);

impl Writeable for RouteHealthCertificatePayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let item = self.0;
		item.route_id.write(writer)?;
		writer.write_u64(item.manifest_sequence)?;
		item.challenge_hash.write(writer)?;
		item.attestation_root.write(writer)?;
		writer.write_u64(item.verified_at)?;
		writer.write_u64(item.expires_at)?;
		item.swap_identity.write(writer)
	}
}

impl RouteHealthCertificate {
	pub fn hash(&self) -> Hash {
		hash(
			MwixnetType::RouteHealthCertificate,
			&RouteHealthCertificatePayload(self),
		)
	}

	pub fn validate(
		&self,
		manifest: &RouteManifest,
		challenge: &HealthChallenge,
		response: &HealthResponse,
	) -> Result<(), Error> {
		if !valid_common(
			self.version,
			self.msg_type,
			MwixnetType::RouteHealthCertificate,
		) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.route_id != manifest.route_id
			|| self.manifest_sequence != manifest.manifest_sequence
			|| self.challenge_hash != challenge.hash()
		{
			return Err(Error::InvalidMessage("challenge binding"));
		}
		let root = response
			.attestations
			.first()
			.map(HealthAttestation::hash)
			.ok_or(Error::InvalidMessage("empty response"))?;
		if self.attestation_root != root {
			return Err(Error::InvalidMessage("attestation root"));
		}
		if self.verified_at < challenge.created_at
			|| self.verified_at > challenge.expires_at
			|| self.expires_at <= self.verified_at
			|| self.expires_at > self.verified_at.saturating_add(MAX_HEALTH_CERTIFICATE_AGE)
			|| self.expires_at > manifest.valid_until
		{
			return Err(Error::InvalidMessage("certificate validity"));
		}
		if self.swap_identity != manifest.swap_identity {
			return Err(Error::InvalidMessage("swap identity"));
		}
		verify_signature(self.hash(), self.swap_identity, self.signature)
	}
}

impl Writeable for RouteHealthCertificate {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		write_header(writer, self.version, self.msg_type)?;
		RouteHealthCertificatePayload(self).write(writer)?;
		self.signature.write(writer)
	}
}

impl Readable for RouteHealthCertificate {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteHealthCertificate)?;
		Ok(Self {
			version,
			msg_type,
			route_id: Hash::read(reader)?,
			manifest_sequence: reader.read_u64()?,
			challenge_hash: Hash::read(reader)?,
			attestation_root: Hash::read(reader)?,
			verified_at: reader.read_u64()?,
			expires_at: reader.read_u64()?,
			swap_identity: PublicKey::read(reader)?,
			signature: Signature::read(reader)?,
		})
	}
}

pub fn health_hop_nonce_hash(nonce: Hash) -> Hash {
	hash(MwixnetType::HealthHopNonce, &nonce)
}

fn health_layer_info(manifest_sequence: u64, challenge_hash: Hash, hop_position: u8) -> Vec<u8> {
	let mut info = Vec::with_capacity(4 + 1 + 8 + 32 + 1);
	info.extend_from_slice(&MWIXNET_PROTOCOL_VERSION.to_be_bytes());
	info.push(MwixnetType::HealthOnionLayer as u8);
	info.extend_from_slice(&manifest_sequence.to_be_bytes());
	info.extend_from_slice(&challenge_hash.0);
	info.push(hop_position);
	info
}

pub fn health_layer_aad(
	route_id: Hash,
	manifest_sequence: u64,
	challenge_hash: Hash,
	hop_position: u8,
	ephemeral_public_key: OnionPublicKey,
) -> Vec<u8> {
	let mut aad = Vec::with_capacity(4 + 1 + 32 + 8 + 32 + 1 + 32);
	aad.extend_from_slice(&MWIXNET_PROTOCOL_VERSION.to_be_bytes());
	aad.push(MwixnetType::HealthOnionLayer as u8);
	aad.extend_from_slice(&route_id.0);
	aad.extend_from_slice(&manifest_sequence.to_be_bytes());
	aad.extend_from_slice(&challenge_hash.0);
	aad.push(hop_position);
	aad.extend_from_slice(&ephemeral_public_key.0);
	aad
}

fn health_layer_key(
	shared_secret: [u8; 32],
	route_id: Hash,
	manifest_sequence: u64,
	challenge_hash: Hash,
	hop_position: u8,
) -> Result<[u8; 32], Error> {
	if shared_secret == [0; 32] {
		return Err(Error::HealthLayerAuthenticationFailed);
	}
	let hkdf = Hkdf::<Sha256>::new(Some(&route_id.0), &shared_secret);
	let mut key = [0; 32];
	hkdf.expand(
		&health_layer_info(manifest_sequence, challenge_hash, hop_position),
		&mut key,
	)
	.map_err(|_| Error::HealthLayerAuthenticationFailed)?;
	Ok(key)
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_health_layer(
	ephemeral_secret: [u8; 32],
	receiver_public_key: OnionPublicKey,
	aead_nonce: AeadNonce,
	route_id: Hash,
	manifest_sequence: u64,
	challenge_hash: Hash,
	hop_position: u8,
	payload: &HealthLayerPayload,
) -> Result<HealthLayer, Error> {
	let ephemeral_secret = StaticSecret::from(ephemeral_secret);
	let ephemeral_public_key = OnionPublicKey(X25519PublicKey::from(&ephemeral_secret).to_bytes());
	let shared_secret = ephemeral_secret
		.diffie_hellman(&X25519PublicKey::from(receiver_public_key.0))
		.to_bytes();
	let key = health_layer_key(
		shared_secret,
		route_id,
		manifest_sequence,
		challenge_hash,
		hop_position,
	)?;
	let plaintext = ser::ser_vec(payload, ProtocolVersion::local())
		.map_err(|_| Error::InvalidMessage("health layer payload"))?;
	let aad = health_layer_aad(
		route_id,
		manifest_sequence,
		challenge_hash,
		hop_position,
		ephemeral_public_key,
	);
	let ciphertext = ChaCha20Poly1305::new((&key).into())
		.encrypt(
			Nonce::from_slice(&aead_nonce.0),
			Payload {
				msg: &plaintext,
				aad: &aad,
			},
		)
		.map_err(|_| Error::HealthLayerAuthenticationFailed)?;
	Ok(HealthLayer {
		ephemeral_public_key,
		aead_nonce,
		ciphertext,
	})
}

pub fn decrypt_health_layer(
	receiver_secret: [u8; 32],
	route_id: Hash,
	manifest_sequence: u64,
	challenge_hash: Hash,
	hop_position: u8,
	layer: &HealthLayer,
) -> Result<HealthLayerPayload, Error> {
	let receiver_secret = StaticSecret::from(receiver_secret);
	let shared_secret = receiver_secret
		.diffie_hellman(&X25519PublicKey::from(layer.ephemeral_public_key.0))
		.to_bytes();
	let key = health_layer_key(
		shared_secret,
		route_id,
		manifest_sequence,
		challenge_hash,
		hop_position,
	)?;
	let aad = health_layer_aad(
		route_id,
		manifest_sequence,
		challenge_hash,
		hop_position,
		layer.ephemeral_public_key,
	);
	let plaintext = ChaCha20Poly1305::new((&key).into())
		.decrypt(
			Nonce::from_slice(&layer.aead_nonce.0),
			Payload {
				msg: &layer.ciphertext,
				aad: &aad,
			},
		)
		.map_err(|_| Error::HealthLayerAuthenticationFailed)?;
	ser::deserialize_default(&mut plaintext.as_slice())
		.map_err(|_| Error::HealthLayerAuthenticationFailed)
}

impl RouteHealthProof {
	pub fn validate(&self, manifest: &RouteManifest, now: u64) -> Result<(), Error> {
		if !valid_common(self.version, self.msg_type, MwixnetType::RouteHealthProof) {
			return Err(Error::InvalidMessage("header"));
		}
		if self.challenge.route_id != manifest.route_id
			|| self.challenge.manifest_sequence != manifest.manifest_sequence
		{
			return Err(Error::InvalidMessage("manifest binding"));
		}
		if self.certificate.expires_at <= now {
			return Err(Error::InvalidMessage("expired certificate"));
		}
		self.challenge.validate(now, manifest.swap_identity)?;
		self.response
			.validate(manifest, &self.challenge, &self.hop_nonces)?;
		self.certificate
			.validate(manifest, &self.challenge, &self.response)
	}
}

impl Writeable for RouteHealthProof {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.hop_nonces.len() >= MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		write_header(writer, self.version, self.msg_type)?;
		self.challenge.write(writer)?;
		writer.write_u16(self.hop_nonces.len() as u16)?;
		for nonce in &self.hop_nonces {
			nonce.write(writer)?;
		}
		self.response.write(writer)?;
		self.certificate.write(writer)
	}
}

impl Readable for RouteHealthProof {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let (version, msg_type) = read_header(reader, MwixnetType::RouteHealthProof)?;
		let challenge = HealthChallenge::read(reader)?;
		let count = reader.read_u16()? as usize;
		if count >= MAX_ROUTE_HOPS {
			return Err(ser::Error::CountError);
		}
		Ok(Self {
			version,
			msg_type,
			challenge,
			hop_nonces: (0..count)
				.map(|_| Hash::read(reader))
				.collect::<Result<_, _>>()?,
			response: HealthResponse::read(reader)?,
			certificate: RouteHealthCertificate::read(reader)?,
		})
	}
}
