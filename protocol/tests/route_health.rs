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

use ed25519_dalek::{Signer, SigningKey};
use grin_core::ser::{self, ProtocolVersion, Readable, Writeable};
use grin_util::{from_hex, ToHex};
use mwixnet_protocol::*;
use serde::Deserialize;

const NOW: u64 = 1_800_000_000;

fn key(value: u8) -> SigningKey {
	SigningKey::from_bytes(&[value; 32])
}

fn public(key: &SigningKey) -> PublicKey {
	PublicKey(key.verifying_key().to_bytes())
}

fn sign(key: &SigningKey, hash: Hash) -> Signature {
	Signature(key.sign(hash.as_bytes()).to_bytes())
}

fn roundtrip<T>(value: &T)
where
	T: Writeable + Readable + PartialEq + std::fmt::Debug,
{
	let bytes = ser::ser_vec(value, ProtocolVersion::local()).unwrap();
	let decoded: T = ser::deserialize_default(&mut bytes.as_slice()).unwrap();
	assert_eq!(value, &decoded);
}

fn binary<T: Writeable>(value: &T) -> String {
	ser::ser_vec(value, ProtocolVersion::local())
		.unwrap()
		.to_hex()
}

#[derive(Deserialize)]
struct SignedVector<T> {
	value: T,
	binary: String,
	hash: Hash,
}

#[derive(Deserialize)]
struct BinaryVector<T> {
	value: T,
	binary: String,
}

#[derive(Deserialize)]
struct OfferVectors {
	mixer: SignedVector<MixerOffer>,
	swap: SignedVector<SwapOffer>,
	announcement: OfferAnnouncementVector,
	get_binary: String,
	batch_binary: String,
}

#[derive(Deserialize)]
struct OfferAnnouncementVector {
	value: OfferAnnouncement,
	binary: String,
	pow_hash: Hash,
}

#[derive(Deserialize)]
struct RouteVectors {
	route_id: Hash,
	proposal: SignedVector<RouteProposal>,
	acceptances: Vec<SignedVector<RouteAcceptance>>,
	manifest: SignedVector<RouteManifest>,
}

#[derive(Deserialize)]
struct HealthVectors {
	challenge: SignedVector<HealthChallenge>,
	attestations: Vec<SignedVector<HealthAttestation>>,
	response: BinaryVector<HealthResponse>,
	certificate: SignedVector<RouteHealthCertificate>,
	proof: BinaryVector<RouteHealthProof>,
}

#[derive(Deserialize)]
struct HealthLayerVector {
	receiver_secret: String,
	receiver_public: OnionPublicKey,
	ephemeral_secret: String,
	aead_nonce: AeadNonce,
	route_id: Hash,
	manifest_sequence: String,
	challenge_hash: Hash,
	hop_position: u8,
	payload: HealthLayerPayload,
	layer: HealthLayer,
	aad: String,
	shared_secret: String,
	hkdf_prk: String,
	hkdf_info: String,
	layer_key: String,
	tag: String,
}

#[derive(Deserialize)]
struct Vectors {
	negative_cases: Vec<String>,
	offers: OfferVectors,
	route: RouteVectors,
	health_layer: HealthLayerVector,
	health: HealthVectors,
}

fn vectors() -> Vectors {
	serde_json::from_str(include_str!("route_health_vectors.json")).unwrap()
}

#[test]
fn negative_vector_inventory_is_complete() {
	assert_eq!(
		vectors().negative_cases,
		vec![
			"wrong_version",
			"wrong_type",
			"truncated_list",
			"limit_exceeded",
			"low_order_x25519",
			"invalid_aead_tag",
			"idempotency_hash_mismatch",
			"wrong_sequence",
			"invalid_signature",
			"swapped_hop_positions",
		]
	);
}

fn manifest() -> RouteManifest {
	let swap_key = key(7);
	let mixer_key = key(8);
	let hops = vec![
		RouteHop {
			role: RouteRole::Swap,
			identity_public_key: public(&swap_key),
			onion_address: OnionAddress(public(&swap_key).0),
			onion_public_key: OnionPublicKey([17; 32]),
		},
		RouteHop {
			role: RouteRole::Mixer,
			identity_public_key: public(&mixer_key),
			onion_address: OnionAddress(public(&mixer_key).0),
			onion_public_key: OnionPublicKey([18; 32]),
		},
	];
	let route_id = route_id(12_500_000, &hops).unwrap();
	let mut proposal = RouteProposal {
		version: MWIXNET_PROTOCOL_VERSION,
		msg_type: MwixnetType::RouteProposal,
		route_id,
		manifest_sequence: 1,
		valid_from: NOW - 60,
		valid_until: NOW + 3_600,
		fee_per_hop: 12_500_000,
		ordered_hops: hops,
		proposer_signature: Signature([0; 64]),
	};
	proposal.proposer_signature = sign(&swap_key, proposal.hash());
	let proposal_hash = proposal.hash();
	let mut acceptances = Vec::new();
	for participant in [&swap_key, &mixer_key] {
		let mut acceptance = RouteAcceptance {
			version: MWIXNET_PROTOCOL_VERSION,
			msg_type: MwixnetType::RouteAcceptance,
			route_id,
			manifest_sequence: 1,
			proposal_hash,
			participant_identity: public(participant),
			accepted_until: proposal.valid_until,
			signature: Signature([0; 64]),
		};
		acceptance.signature = sign(participant, acceptance.hash());
		acceptances.push(acceptance);
	}
	let mut manifest = RouteManifest {
		version: MWIXNET_PROTOCOL_VERSION,
		msg_type: MwixnetType::RouteManifest,
		route_id,
		manifest_sequence: 1,
		proposal_hash,
		valid_from: proposal.valid_from,
		valid_until: proposal.valid_until,
		fee_per_hop: proposal.fee_per_hop,
		ordered_hops: proposal.ordered_hops,
		proposer_signature: proposal.proposer_signature,
		acceptances,
		swap_identity: public(&swap_key),
		signature: Signature([0; 64]),
	};
	manifest.signature = sign(&swap_key, manifest.hash());
	manifest
}

#[test]
fn route_records_validate_and_roundtrip() {
	let manifest = manifest();
	assert_eq!(
		"8b6397eebb9273931835b624ef392c169d3e1ab6af62eafdf049f44ca707d86a",
		manifest.route_id.0.to_hex()
	);
	manifest.validate(NOW).unwrap();
	roundtrip(&manifest);
	let proposal = manifest.proposal();
	let vectors = vectors().route;
	assert_eq!(vectors.route_id, manifest.route_id);
	assert_eq!(vectors.proposal.value, proposal);
	assert_eq!(vectors.proposal.binary, binary(&proposal));
	assert_eq!(vectors.proposal.hash, proposal.hash());
	assert_eq!(vectors.manifest.value, manifest);
	assert_eq!(vectors.manifest.binary, binary(&manifest));
	assert_eq!(vectors.manifest.hash, manifest.hash());
	assert_eq!(vectors.acceptances.len(), manifest.acceptances.len());
	for (expected, acceptance) in vectors.acceptances.iter().zip(&manifest.acceptances) {
		assert_eq!(&expected.value, acceptance);
		assert_eq!(expected.binary, binary(acceptance));
		assert_eq!(expected.hash, acceptance.hash());
	}
	let mut invalid = manifest;
	invalid.ordered_hops.swap(0, 1);
	assert!(invalid.validate(NOW).is_err());
}

#[test]
fn offers_validate_and_roundtrip() {
	let key = key(9);
	let identity = public(&key);
	let mut mixer = MixerOffer {
		version: 1,
		msg_type: MwixnetType::MixerOffer,
		identity_public_key: identity,
		onion_address: OnionAddress(identity.0),
		onion_public_key: OnionPublicKey([2; 32]),
		minimum_fee: 1,
		capacity: 32,
		valid_until: NOW + 3_600,
		sequence: 1,
		signature: Signature([0; 64]),
	};
	mixer.signature = sign(&key, mixer.hash());
	mixer.validate(NOW).unwrap();
	roundtrip(&mixer);

	let mut swap = SwapOffer {
		version: 1,
		msg_type: MwixnetType::SwapOffer,
		identity_public_key: identity,
		onion_address: OnionAddress(identity.0),
		onion_public_key: OnionPublicKey([2; 32]),
		minimum_fee: 1,
		capacity: 32,
		desired_min_hops: Some(2),
		desired_max_hops: Some(4),
		maximum_fee_per_hop: Some(12_500_000),
		max_request_ttl_blocks: 120,
		valid_until: NOW + 3_600,
		sequence: 1,
		signature: Signature([0; 64]),
	};
	swap.signature = sign(&key, swap.hash());
	swap.validate(NOW).unwrap();
	roundtrip(&swap);
	let vectors = vectors().offers;
	assert_eq!(vectors.mixer.value, mixer);
	assert_eq!(vectors.mixer.binary, binary(&mixer));
	assert_eq!(vectors.mixer.hash, mixer.hash());
	assert_eq!(vectors.swap.value, swap);
	assert_eq!(vectors.swap.binary, binary(&swap));
	assert_eq!(vectors.swap.hash, swap.hash());

	let announcement = OfferAnnouncement::mine(MwixnetOffer::Mixer(mixer));
	assert_eq!(vectors.announcement.value, announcement);
	assert_eq!(vectors.announcement.binary, binary(&announcement));
	assert_eq!(vectors.announcement.pow_hash, announcement.pow_hash());
	announcement.validate(NOW).unwrap();
	roundtrip(&announcement);

	let get = GetMwixnetOffers {
		version: MWIXNET_PROTOCOL_VERSION,
		request_id: 9,
		cursor: Some(announcement.offer_id()),
		limit: 10,
	};
	assert_eq!(vectors.get_binary, binary(&get));
	roundtrip(&get);
	let batch = MwixnetOffers {
		version: MWIXNET_PROTOCOL_VERSION,
		request_id: 9,
		next_cursor: None,
		items: vec![announcement],
	};
	assert_eq!(vectors.batch_binary, binary(&batch));
	roundtrip(&batch);
}

#[test]
fn health_layer_authenticates_context() {
	use hkdf::Hkdf;
	use sha2::Sha256;
	let receiver_secret = [21; 32];
	let receiver_public = OnionPublicKey(
		x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(receiver_secret))
			.to_bytes(),
	);
	let payload = HealthLayerPayload {
		hop_nonce: Hash([22; 32]),
		next_layer: Some(vec![1, 2, 3]),
	};
	let route_id = Hash([23; 32]);
	let challenge_hash = Hash([24; 32]);
	let layer = encrypt_health_layer(
		[25; 32],
		receiver_public,
		AeadNonce([26; 12]),
		route_id,
		1,
		challenge_hash,
		1,
		&payload,
	)
	.unwrap();
	assert_eq!(
		"973ac258850f1ca00630b7aaa5cd9ab76ef29265eb81061618b7874cfa2ba156",
		layer.ephemeral_public_key.0.to_hex()
	);
	assert_eq!(
		"1715f60da9af1b7a06b37050926e49e26527b3420992053def770a2fc9a9a59be88c205f461c3d6f010f182e294184053f30c23aad84e142",
		layer.ciphertext.to_hex()
	);
	assert_eq!(
		"000000011417171717171717171717171717171717171717171717171717171717171717170000000000000001181818181818181818181818181818181818181818181818181818181818181801973ac258850f1ca00630b7aaa5cd9ab76ef29265eb81061618b7874cfa2ba156",
		health_layer_aad(route_id, 1, challenge_hash, 1, layer.ephemeral_public_key).to_hex()
	);
	assert_eq!(
		payload,
		decrypt_health_layer(receiver_secret, route_id, 1, challenge_hash, 1, &layer).unwrap()
	);
	let vector = vectors().health_layer;
	assert_eq!(from_hex(&vector.receiver_secret).unwrap(), receiver_secret);
	assert_eq!(vector.receiver_public, receiver_public);
	assert_eq!(from_hex(&vector.ephemeral_secret).unwrap(), vec![25; 32]);
	assert_eq!(vector.aead_nonce, AeadNonce([26; 12]));
	assert_eq!(vector.route_id, route_id);
	assert_eq!(vector.manifest_sequence, "1");
	assert_eq!(vector.challenge_hash, challenge_hash);
	assert_eq!(vector.hop_position, 1);
	assert_eq!(vector.payload, payload);
	assert_eq!(vector.layer, layer);
	assert_eq!(
		vector.aad,
		health_layer_aad(route_id, 1, challenge_hash, 1, layer.ephemeral_public_key).to_hex()
	);
	let shared_secret = x25519_dalek::StaticSecret::from([25; 32])
		.diffie_hellman(&x25519_dalek::PublicKey::from(receiver_public.0))
		.to_bytes();
	let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&route_id.0), &shared_secret);
	let mut info = Vec::new();
	info.extend_from_slice(&MWIXNET_PROTOCOL_VERSION.to_be_bytes());
	info.push(MwixnetType::HealthOnionLayer as u8);
	info.extend_from_slice(&1u64.to_be_bytes());
	info.extend_from_slice(&challenge_hash.0);
	info.push(1);
	let mut layer_key = [0; 32];
	hkdf.expand(&info, &mut layer_key).unwrap();
	assert_eq!(vector.shared_secret, shared_secret.to_hex());
	assert_eq!(vector.hkdf_prk, prk.to_hex());
	assert_eq!(vector.hkdf_info, info.to_hex());
	assert_eq!(vector.layer_key, layer_key.to_hex());
	assert_eq!(
		vector.tag,
		layer.ciphertext[layer.ciphertext.len() - 16..]
			.to_vec()
			.to_hex()
	);
	let mut invalid = layer;
	invalid.ciphertext[0] ^= 1;
	assert_eq!(
		Err(Error::HealthLayerAuthenticationFailed),
		decrypt_health_layer(receiver_secret, route_id, 1, challenge_hash, 1, &invalid)
	);
	assert_eq!(
		Err(Error::HealthLayerAuthenticationFailed),
		encrypt_health_layer(
			[25; 32],
			OnionPublicKey([0; 32]),
			AeadNonce([26; 12]),
			route_id,
			1,
			challenge_hash,
			1,
			&payload,
		)
	);
}

#[test]
fn health_proof_validates_and_roundtrips() {
	let manifest = manifest();
	let swap_key = key(7);
	let mixer_key = key(8);
	let mut challenge = HealthChallenge {
		version: 1,
		msg_type: MwixnetType::HealthChallenge,
		route_id: manifest.route_id,
		manifest_sequence: 1,
		nonce: Hash([31; 32]),
		created_at: NOW - 60,
		expires_at: NOW + 240,
		signature: Signature([0; 64]),
	};
	challenge.signature = sign(&swap_key, challenge.hash());
	let hop_nonce = Hash([32; 32]);
	let mut attestation = HealthAttestation {
		version: 1,
		msg_type: MwixnetType::HealthAttestation,
		route_id: manifest.route_id,
		manifest_sequence: 1,
		challenge_hash: challenge.hash(),
		hop_nonce_hash: health_hop_nonce_hash(hop_nonce),
		hop_position: 1,
		participant_identity: public(&mixer_key),
		observed_at: NOW,
		next_attestation_hash: None,
		signature: Signature([0; 64]),
	};
	attestation.signature = sign(&mixer_key, attestation.hash());
	let response = HealthResponse {
		version: 1,
		msg_type: MwixnetType::HealthResponse,
		route_id: manifest.route_id,
		manifest_sequence: 1,
		challenge_hash: challenge.hash(),
		attestations: vec![attestation.clone()],
	};
	let mut certificate = RouteHealthCertificate {
		version: 1,
		msg_type: MwixnetType::RouteHealthCertificate,
		route_id: manifest.route_id,
		manifest_sequence: 1,
		challenge_hash: challenge.hash(),
		attestation_root: attestation.hash(),
		verified_at: NOW,
		expires_at: NOW + 600,
		swap_identity: public(&swap_key),
		signature: Signature([0; 64]),
	};
	certificate.signature = sign(&swap_key, certificate.hash());
	let proof = RouteHealthProof {
		version: 1,
		msg_type: MwixnetType::RouteHealthProof,
		challenge,
		hop_nonces: vec![hop_nonce],
		response,
		certificate,
	};
	proof.validate(&manifest, NOW + 300).unwrap();
	roundtrip(&proof);
	let vectors = vectors().health;
	assert_eq!(vectors.challenge.value, proof.challenge);
	assert_eq!(vectors.challenge.binary, binary(&proof.challenge));
	assert_eq!(vectors.challenge.hash, proof.challenge.hash());
	assert_eq!(
		vectors.attestations.len(),
		proof.response.attestations.len()
	);
	for (expected, attestation) in vectors
		.attestations
		.iter()
		.zip(&proof.response.attestations)
	{
		assert_eq!(&expected.value, attestation);
		assert_eq!(expected.binary, binary(attestation));
		assert_eq!(expected.hash, attestation.hash());
	}
	assert_eq!(vectors.response.value, proof.response);
	assert_eq!(vectors.response.binary, binary(&proof.response));
	assert_eq!(vectors.certificate.value, proof.certificate);
	assert_eq!(vectors.certificate.binary, binary(&proof.certificate));
	assert_eq!(vectors.certificate.hash, proof.certificate.hash());
	assert_eq!(vectors.proof.value, proof);
	assert_eq!(vectors.proof.binary, binary(&proof));
	let mut truncated = ser::ser_vec(&proof, ProtocolVersion::local()).unwrap();
	truncated.pop();
	assert!(ser::deserialize_default::<RouteHealthProof, _>(&mut truncated.as_slice()).is_err());

	let mut invalid = proof;
	invalid.hop_nonces[0].0[0] ^= 1;
	assert!(invalid.validate(&manifest, NOW + 300).is_err());
}
