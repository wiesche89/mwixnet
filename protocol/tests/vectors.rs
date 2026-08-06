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
use grin_core::ser::{self, ProtocolVersion};
use grin_util::ToHex;
use mwixnet_protocol::{
	Error, GetMwixnetRoutes, Hash, MwixnetRoutes, OnionAddress, RouteAnnouncement, RouteRelayItem,
	RouteRevocation, RouteState, RouteStatus, Signature, MWIXNET_PROTOCOL_VERSION,
	P2P_BATCH_MAX_ROUTES,
};
use serde::Deserialize;

const NOW: u64 = 1_800_000_000;

fn signing_key(value: u8) -> SigningKey {
	SigningKey::from_bytes(&[value; 32])
}

fn binary<T: grin_core::ser::Writeable>(value: &T) -> String {
	ser::ser_vec(value, ProtocolVersion::local())
		.unwrap()
		.to_hex()
}

#[derive(Deserialize)]
struct SignedVector<T> {
	value: T,
	binary: String,
	hash: String,
	signature: String,
}

#[derive(Deserialize)]
struct Vectors {
	entry_onion: String,
	announcement: SignedVector<RouteAnnouncement>,
	status: SignedVector<RouteStatus>,
	revocation: SignedVector<RouteRevocation>,
	get_routes_binary: String,
	routes_binary: String,
}

fn vectors() -> Vectors {
	serde_json::from_str(include_str!("vectors.json")).unwrap()
}

#[test]
fn vectors_match() {
	let vectors = vectors();
	let announcement = &vectors.announcement.value;
	let status = &vectors.status.value;
	let revocation = &vectors.revocation.value;
	let get = GetMwixnetRoutes {
		version: MWIXNET_PROTOCOL_VERSION,
		request_id: 9,
		cursor: Some(Hash([4; 32])),
		limit: 10,
	};
	let routes = MwixnetRoutes {
		version: MWIXNET_PROTOCOL_VERSION,
		request_id: 9,
		next_cursor: None,
		items: vec![
			RouteRelayItem::Announcement(announcement.clone()),
			RouteRelayItem::Status(status.clone()),
			RouteRelayItem::Revocation(revocation.clone()),
		],
	};

	assert_eq!(vectors.announcement.binary, binary(&announcement));
	assert_eq!(vectors.entry_onion, announcement.entry_onion.to_string());
	assert_eq!(vectors.announcement.hash, announcement.hash().0.to_hex());
	assert_eq!(
		vectors.announcement.signature,
		announcement.signature.0.to_hex()
	);
	assert_eq!(vectors.status.binary, binary(&status));
	assert_eq!(vectors.status.hash, status.hash().0.to_hex());
	assert_eq!(vectors.status.signature, status.signature.0.to_hex());
	assert_eq!(vectors.revocation.binary, binary(&revocation));
	assert_eq!(vectors.revocation.hash, revocation.hash().0.to_hex());
	assert_eq!(
		vectors.revocation.signature,
		revocation.signature.0.to_hex()
	);
	assert_eq!(vectors.get_routes_binary, binary(&get));
	assert_eq!(vectors.routes_binary, binary(&routes));

	announcement.validate(NOW).unwrap();
	status.validate(NOW).unwrap();
	revocation.validate(NOW).unwrap();

	let json = serde_json::to_string(&announcement).unwrap();
	let decoded: RouteAnnouncement = serde_json::from_str(&json).unwrap();
	assert_eq!(announcement, &decoded);
}

#[test]
fn rejects_invalid_messages() {
	let mut item = vectors().announcement.value;
	item.signature.0[0] ^= 1;
	assert_eq!(item.validate(NOW), Err(Error::InvalidSignature));

	let mut item = vectors().announcement.value;
	item.participant_identities.pop();
	assert_eq!(
		item.validate(NOW),
		Err(Error::InvalidMessage("participants"))
	);

	let key = signing_key(7);
	let mut item = vectors().status.value;
	item.status = RouteState::Healthy;
	item.signature = Signature(key.sign(item.hash().as_bytes()).to_bytes());
	assert_eq!(item.validate(NOW), Err(Error::InvalidMessage("status")));

	let invalid_onion = format!("\"{}a.onion\"", "a".repeat(55));
	assert!(serde_json::from_str::<OnionAddress>(&invalid_onion).is_err());

	let mut bytes = ser::ser_vec(
		&GetMwixnetRoutes {
			version: MWIXNET_PROTOCOL_VERSION,
			request_id: 9,
			cursor: None,
			limit: 10,
		},
		ProtocolVersion::local(),
	)
	.unwrap();
	bytes[3] = 2;
	assert!(ser::deserialize_default::<GetMwixnetRoutes, _>(&mut bytes.as_slice()).is_err());

	let announcement = vectors().announcement.value;
	let items = (0..=P2P_BATCH_MAX_ROUTES)
		.map(|index| {
			let mut item = announcement.clone();
			item.route_id = Hash([index as u8; 32]);
			RouteRelayItem::Announcement(item)
		})
		.collect();
	let routes = MwixnetRoutes {
		version: MWIXNET_PROTOCOL_VERSION,
		request_id: 1,
		next_cursor: None,
		items,
	};
	assert!(ser::ser_vec(&routes, ProtocolVersion::local()).is_err());
}
