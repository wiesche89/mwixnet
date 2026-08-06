- Titel: `mwixnet-route-discovery`
- Autoren: `github/wiesche89`
- Startdatum: 30. Juli 2026
- RFC-PR: noch nicht eingereicht
- Tracking-Issue: noch nicht vorhanden

---

Diese Kurzfassung beschreibt dasselbe Protokoll wie der vollständige RFC. Implementierungen richten sich zusätzlich nach den gemeinsamen Testvektoren.

## Summary
[summary]: #summary

Der RFC ergänzt MWixnet um feste, auffindbare Routen. Ein Swap-Server schlägt eine geordnete Route vor; alle Teilnehmer signieren denselben Routenkern. Das Manifest bindet
Reihenfolge, Identitäten, Onion-Keys, Gebühr und Laufzeit. Ein Healthcheck prüft die Kette über den später verwendeten Tor-Pfad.

Grin-Nodes verteilen nur kurzlebige, signierte Metadaten. Manifest und Health-Nachweis lädt die Wallet direkt über Tor. Erst nach vollständigem Preflight sperrt sie den Output.
Freie Routen pro Swap, ein Ersatz für Tor und ein Nachweis unabhängiger Betreiber sind nicht Teil dieses RFCs.

## Terminology
[terminology]: #terminology

- **Route/Hop:** geordnete Kette aus einem Swap-Server und mindestens einem Mixer beziehungsweise ein Teilnehmer an seiner festen Position.
- **Offer:** signierte Beschreibung eines Swap-Servers oder Mixers.
- **Proposal/Acceptance/Manifest:** Routenvorschlag, Zustimmung eines Teilnehmers und der von allen akzeptierte Routendatensatz.
- **Route-ID:** Hash über Reihenfolge, Rollen, Identitäten, Onion-Keys und `fee_per_hop`.
- **Announcement/Status/Revocation:** P2P-Ankündigung, Zustandsänderung und signierter Widerruf eines Manifests.
- **Healthcheck:** End-to-End-Prüfung des Serverpfads mit signierten Attestations; der Entry-Zugriff der Wallet wird getrennt geprüft.
- **SwapReq/MixReq/MixResp:** Wallet-Anfrage, routengebundener Batch und dessen gefilterte Antwort.
- **Preflight:** Prüfung von Route, Manifest, Offer, Health und Gebühr vor dem Output-Lock.
- **Draining:** keine neuen Requests; bereits angenommene werden beendet.

## Motivation
[motivation]: #motivation

Heute werden Vorgänger, Nachfolger, Onion-Adressen, X25519-Schlüssel und Gebühren manuell konfiguriert. Routen sind weder auffindbar noch gemeinsam signiert, und Erreichbarkeit
sowie Widerruf sind nicht standardisiert.

Der RFC belässt Ausführung und Healthchecks auf Tor. Grin-P2P dient nur der Discovery zwischen Swap-Server, Nodes und Wallets. Das Mainnet-Relay fertiger Routen bleibt
allowlist-basiert; das Offer-Relay ist permissionless und durch Proof-of-Work, Ablaufzeiten, Cache-Grenzen und Ratenlimits geschützt.

## Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

Eine Route lautet `Swap -> Mixer 1 -> ... -> Mixer n`. Identitäten dürfen in einer Route nicht mehrfach vorkommen, ein Mixer darf aber mehreren Routen angehören. Der Swap-Server
sammelt Acceptances, aktiviert das Manifest bei allen Mixern und startet den ersten Healthcheck. Nur eine vollständig aktivierte und gesunde Route wird angekündigt.

Die Wallet liest Ankündigungen von ihrer Grin-Node, wählt eine Route und lädt die vollständigen Belege vom Entry-Onion. Der Node transportiert Daten und spricht keine Empfehlung
aus.

### Ausfälle

Eine Route wechselt nach dem ersten Erfolg von `Proposed` nach `Healthy`. Ein Fehler setzt `Degraded`, drei aufeinanderfolgende Fehler setzen `Unavailable`; ein späterer Erfolg
stellt `Healthy` wieder her. `Draining`, `Expired` und `Revoked` sind terminal für neue Requests. Ein gültiger Health-Nachweis ersetzt nicht den lokalen Entry-Preflight der Wallet.

## Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

Alle Nachrichten tragen Version und Typ. Felder sind verpflichtend, sofern nicht ausdrücklich als optional bezeichnet.

### Schlüsselrollen

Ed25519 identifiziert Server und signiert Protokolldaten. Die Identität stimmt mit der Tor-v3-Service-Identität überein. X25519 verschlüsselt Onion- und Health-Schichten und ist
eine getrennte Schlüsselrolle. Wallet-Requests nutzen die bestehende Commitment-Signatur. Private Schlüssel verlassen den Server nicht; `MixResp` und `HealthResponse` benötigen
keine äußere Signatur.

### Hashes und Signaturen

Die kanonische Binärdarstellung verwendet Grins `Writeable`, `Readable` und `Hashed` in Big Endian. Jeder Hash bindet `version:u32`, `type:u8` und den Payload ohne äußere Signatur:

```text
HASH(type, payload) = (version=1, type, payload).hash()
```

`MwixnetType` belegt fortlaufend 0 bis 23 für `MixerOffer`, `SwapOffer`, Proposal, Acceptance, Manifest, Swap/Mix, Health, Cancel, Route-Relay, `RouteId`, Nonce/Onion-Hashes,
`HealthResponse`, `RouteHealthProof` und `OfferAnnouncement`. Rollen sind `Swap=0`, `Mixer=1`; Routenzustände sind `Proposed=0` bis `Revoked=6`. Listen zählen mit `u16`, variable
Bytes mit `u32`; Größen werden vor Allokation geprüft. Bestehende Grin-Typen behalten ihre Serialisierung. Eine Wire-Änderung verlangt eine neue Protokollversion.

### Protokollkonstanten und Implementierungsgrenzen

| Bereich | Festgelegter Wert |
| --- | --- |
| Version und Routenlänge | `1`; 2 bis 8 Hops einschließlich Swap |
| Manifest und Uhrabweichung | höchstens 30 Tage; 2 Minuten |
| Health | Challenge 5, Zertifikat 15, Standardintervall 5 Minuten |
| Ausfallgrenze | 3 aufeinanderfolgende Fehler |
| Announcement/Offer | höchstens 15 Minuten / 24 Stunden |
| Offer-PoW | 16 führende Nullbits |
| Request-TTL | 10 bis 1.440 Blöcke; Wallet-Standard 120 |
| Batch | höchstens 128 Onions beziehungsweise Einträge |
| P2P-Batch | höchstens 128 KiB |
| Health/RPC-Body | höchstens 64 KiB / 2 MiB |

Lokale Standardgrenzen sind 32 Routen je Mixer, 1.024 Route- und Offer- Cacheeinträge sowie begrenzte Proposal-, Health-, Peer- und Update-Raten.

### MWixnet-Offers

`MixerOffer` und `SwapOffer` binden Identität, Onion-Adresse, X25519-Key, Mindestgebühr, Kapazität, Laufzeit und monotone Sequenz. Das Swap-Offer kann zusätzlich Hop-, Gebühren-
und Request-TTL-Grenzen nennen. `capacity` ist unverbindlich. Eine Route endet spätestens mit dem zuerst ablaufenden Offer.

Das permissionless Relay verpackt das signierte Offer mit einem PoW-Nonce. Vor einem Proposal lädt der Swap-Server das Offer nochmals direkt über Tor. Konfigurierte Mixer bleiben
der feste Routenanfang; Discovery ergänzt bis `target_route_hops` (Standard 2). Eine bestehende Route wird erst drainend, wenn ihr vollständig akzeptierter und gesunder Ersatz
angekündigt ist.

### Routenbildung

Nur der Swap-Server erstellt ein signiertes `RouteProposal` mit Route-ID, Manifest-Sequenz, Laufzeit, einheitlicher Gebühr und geordneten Hops. Hop 0 ist der Swap-Server, danach
folgen Mixer. Jeder Teilnehmer prüft Schlüssel, Onion-Identität, Position, Nachbarn, Offers, Gebühr, Laufzeit, Grenzen und doppelte Identitäten und signiert anschließend eine
`RouteAcceptance`.

```text
route_id = HASH(RouteId,
  fee_per_hop, hop_count, ordered(role, identity, onion_public_key))
```

Eine neue Route beginnt mit Sequenz 1. Verlängerungen behalten die Route-ID, erhöhen die Manifest-Sequenz und benötigen neue Acceptances. Proposal und Acceptance sind über
`(route_id, manifest_sequence)` idempotent; ein anderer Hash unter demselben Schlüssel ist ein Konflikt.

### Route-Manifest

Das Manifest enthält den Proposal-Kern, die ursprüngliche Proposal-Signatur, genau eine Acceptance pro Hop und eine abschließende Swap-Signatur. Alle Bestandteile binden Route-ID,
Sequenz und Proposal-Hash. `valid_until` liegt nicht nach einer Acceptance oder einem Offer. Mixer speichern mindestens die Route, Sequenz, Gültigkeit, Swap-Identität und ihre
beiden Nachbarn.

### Mehrere Routen pro Mixer

Routentabellen werden mit `(route_id, manifest_sequence)` adressiert; eine aktive Erneuerung und ihre drainende Vorgängerin dürfen parallel bestehen. Requests wechseln niemals
nachträglich die Sequenz. `MixReq` bindet Route, Sequenz, zufällige `batch_id`, Onions und Vorgängersignatur. Die Batch-ID bleibt entlang der Route, Wallet-IDs werden nicht
weitergegeben.

`MixResp.indices` ist sortiert, eindeutig und auf den jeweiligen Eingangsbatch bezogen. Teilmengen werden beim Rückweg auf frühere Positionen abgebildet. Leere Indizes sind ein
erfolgreicher Abschluss ohne Transaktion. Jeder Hop speichert Request-Hash und Antwort idempotent; Konflikte, falsche Vorgänger, Routen oder Grenzen lehnen den ganzen Batch ab.

### Healthcheck

Der Swap-Server erstellt eine kurzlebige signierte Challenge und eine verschachtelte Health-Schicht pro Mixer. Jede Schicht nutzt frisches X25519, HKDF-SHA-256 und
ChaCha20-Poly1305; Route, Sequenz, Challenge, Position und ephemerer Schlüssel sind AAD. Low-Order-Schlüssel und ungültige Tags werden abgelehnt. Der autorisierte Vorgänger
signiert jede `HealthRequest`.

Jeder Mixer entschlüsselt seinen Nonce, leitet die nächste Schicht weiter und stellt seine signierte Attestation vor die Antwort des Nachfolgers. Der Swap-Server prüft
Reihenfolge, Nonce-Hashes, Signaturen und Hashkette und signiert ein höchstens 15 Minuten gültiges `RouteHealthCertificate`. Challenge, Nonces, Attestations und Zertifikat bilden
den über Tor abrufbaren `RouteHealthProof`; über P2P geht nur dessen Hash. Retries sind byteidentisch und idempotent. Der Nachweis belegt vergangene Pfaderreichbarkeit, nicht die
vollständige Mix-Verarbeitung oder einen späteren Erfolg.

### Routenankündigung

`RouteAnnouncement` enthält Route und Manifest-Sequenz, Entry-Onion, Teilnehmer, Gebühr, Manifest- und Health-Hash, Zustand, Prüfzeit, Ablauf und monotone Swap-Sequenz.
`RouteStatus` aktualisiert den Zustand, verlängert aber keinen Health-Nachweis. `RouteRevocation` wird von einem Teilnehmer signiert und hat dessen eigenen Sequenzzähler. Alle
Zähler werden vor Versand persistiert. Manifest und Health-Proof bleiben auf Tor.

### Grin-P2P-Relay

Die Capabilities `MWIXNET_ROUTE_RELAY=0x100` und `MWIXNET_OFFER_RELAY=0x200` verwenden die Nachrichtentypen 31 bis 38. Push verteilt neue Items; ein periodischer, paginierter Pull
repariert Lücken. Nodes prüfen Größe, Signatur, Ablauf, Sequenz, PoW und lokale Limits und speichern je Route nur die höchste Manifest-Sequenz.

Routenbatches sind nach Route-ID, Offer-Batches nach Offer-ID sortiert und durch Item- sowie Byte-Grenzen beschränkt. Duplikate und alte Sequenzen werden nicht erneut verteilt.
Revocations bleiben vorrangig erhalten. Mainnet-Nodes relayn fertige Routen nur für eine nichtleere Swap-Allowlist; im Testnet ist dies optional. Das Offer-Relay bleibt in beiden
Netzen permissionless.

### RPC-Schnittstellen

Alle neuen Methoden verwenden JSON-RPC 2.0. Binärdaten erscheinen als Hex, `u64` als Dezimalstring und Onion-Adressen mit `.onion`. Unbekannte Felder werden abgelehnt. Signiert
wird ausschließlich die kanonische Binärform.

#### Grin-Node

Die Foreign-API `/v2/foreign` erhält `submit_mwixnet_route`, `get_mwixnet_routes`, `submit_mwixnet_offer` und `get_mwixnet_offers`. Einreichung und P2P-Empfang folgen denselben
Prüfungen, Cache- und Ratenlimits. Die Owner-API erhält keine MWixnet-Methode.

#### MWixnet-Server

Der Swap-Server bietet über Tor `swap`, `get_mwixnet_offer`, `get_route`, `get_route_health` und `cancel_mwixnet_request`. Zwischen Servern kommen `mix`, `probe_route`,
`propose_route`, `activate_route` und `revoke_route` hinzu. Verlorene Antworten werden mit identischen Nachrichten wiederholt. Legacy-`swap` und statische Nachbarn bleiben während
der Einführung erhalten.

#### grin-wallet

Die verschlüsselte Owner-API erhält Route-Liste, routebasierte Request-Erzeugung, Request-Status und Stornierung. Die Erzeugung führt zuerst den Preflight aus und schreibt
Request-Datensatz, Transaktionslog und Output-Lock atomar. Ein Refresh wiederholt denselben `SwapReq` als idempotente Statusabfrage. Die Foreign-API bleibt unverändert.

#### Anzeige pro Route

Die Wallet zeigt Route-ID, signierten Health-Zustand, lokalen Entry-Preflight, Hop-Anzahl, Gesamtgebühr, letzte Prüfung und Ablauf. Es gilt `total_fee = fee_per_hop * hop_count`;
die Multiplikation wird geprüft und die Gebühr muss unter Output-Wert und lokalem Maximum liegen. Eine Route wird nur explizit oder über eine lokale Standardroute beziehungsweise
Allowlist gewählt.

### Request-Ablauf, Stornierung und Recovery

`SwapReq` bindet zufällige Wallet-Request-ID, Route, Manifest-Sequenz, Ablaufhöhe und Onion-Hash mit der Commitment-Signatur. Der Swap-Server prüft Idempotenz vor dem aktuellen
Routenzustand und hält zusätzlich einen Index auf das Input-Commitment. Ein gleicher Schlüssel mit anderem Hash ist ein Konflikt; derselbe Input mit anderer Request-ID wird
abgelehnt.

Der persistente Ablauf ist `Accepted -> Batched -> Posting -> Posted <-> Confirmed`; Filterung kann `Batched -> Rejected` setzen. Vor dem Posten wird die vollständige Transaktion
gespeichert und bei Retry unverändert verwendet. Ein Request wird nie in einen anderen Batch oder eine andere Route verschoben.

Nur `Accepted` kann mit signiertem `CancelSwapReq` storniert werden. Der signierte `CancelAck` und ein Tombstone bleiben mindestens bis zur Ablaufhöhe gespeichert. Ablauf oder Ack
machen eine bereits gebaute Transaktion nicht kryptografisch ungültig. Die Wallet erstellt daher einen gespeicherten Reclaim-Self-Spend und beobachtet Chain sowie Reorgs, bis
Reclaim, MWixnet-Transaktion oder ein konkurrierender Spend ausreichend bestätigt ist. Ein bloßer Txpool-Konflikt oder eine Servermeldung entsperrt den Input nicht.

### Route-Lebenszyklus

Erlaubte Übergänge sind `Proposed -> Healthy/Degraded`, `Healthy -> Degraded`, `Degraded -> Healthy/Unavailable` und `Unavailable -> Healthy`. Geplante Stilllegung oder Ablauf mit
offenen Requests führt nach `Draining`, sonst nach `Expired`. Eine gültige Revocation führt aus jedem nichtterminalen Zustand nach `Revoked`.

Health-Ergebnisse dürfen `Draining`, `Expired` oder `Revoked` nicht überschreiben. Draining darf `Accepted` noch batchen; nach Revocation werden nur bereits `Batched` oder
`Posting` befindliche Arbeiten beendet. Routenkonfiguration und Reorg-Daten bleiben bis zum terminalen Abschluss.

### Persistenz und Nebenläufigkeit

Zustand wird vor erfolgreicher RPC-Antwort dauerhaft und zusammengehörig atomar geschrieben. Server speichern Schlüssel, Sequenzen, Proposals, Acceptances, Manifeste,
Routenzustand, Requests, Tombstones, Transaktionen, Batches und Health-Idempotenzdaten. Nodes persistieren Cache- und Sequenzstände. Wallets schreiben Request und Output-Lock
gemeinsam und speichern Reclaim-Transaktionen vor dem Versand.

Je Route läuft nur eine Manifestbildung, je Route/Sequenz ein Healthcheck, je Request ein Zustandsübergang und je Route/Batch eine Verarbeitung. Nach einem Neustart entscheiden
persistente Idempotenzschlüssel, nicht Prozesssperren.

### Aufteilung auf die drei Projekte und Rust-Crates

Grin implementiert P2P-Capabilities, Relay-Cache und Foreign-API. MWixnet implementiert Offers, Routenbildung, Health, Server-RPC, Mix und Persistenz. grin-wallet implementiert
Discovery, Preflight, Request-Erzeugung, Anzeige und Recovery.

Gemeinsame Wire-Typen, Hashes, Signaturen und Prüfungen liegen in der kleinen, zustandslosen Crate `mwixnet-protocol`. Sie darf `grin_core`, aber weder `grin_p2p`, grin-wallet
noch die Server-Crate verwenden. Alle drei Projekte binden dieselbe veröffentlichte Version oder denselben Commit ein.

### Konformitätsvektoren

Gemeinsame maschinenlesbare Vektoren prüfen Bytes, Hashes und Signaturen aller Offers, Routen-, Health-, Relay-, Request-, Cancel- und Mix-Nachrichten. Negative Fälle umfassen
Versionen, Grenzen, Sequenzen, Signaturen, Idempotenzkonflikte, X25519-Low-Order-Punkte, AEAD-Tags und Hop-Reihenfolgen.

### Rückwärtskompatibilität und Einführung

Die Einführung erfolgt in fünf Schritten: MWixnet-Routentabelle und Health, Wallet-Preflight, Grin-Relay, Offer-Discovery und Testnet-Aktivierung. Nodes ohne Capability erhalten
keine neuen Nachrichten. Unbekannte, begrenzte P2P-Typen führen nicht allein zu einem Peer-Bann. Statische `prev_server`/`next_server`-Routen bleiben als nicht angekündigter
Legacy- Betrieb erhalten; es gibt keine automatische Migration.

### Sicherheitsgrenzen

Signaturen verhindern Manipulation, nicht Sybil-Angriffe oder Kollusion. Öffentliche Manifeste legen die Topologie offen; verschiedene Identitäten beweisen keine unabhängigen
Betreiber. Die Anonymitätsmenge ist der Batch, nicht der einzelne Onion. Health belegt nur vergangene Erreichbarkeit. Cancel-Acks und Reclaims garantieren ohne Chain-Bestätigung
keine Verdrängung einer konkurrierenden MWixnet-Transaktion.

## Drawbacks
[drawbacks]: #drawbacks

Der Entwurf erweitert P2P und Foreign-API um begrenzten, nicht konsensrelevanten Zustand. Öffentliche Routen verringern Topologie-Privatsphäre. Mehrere Routen, Healthchecks,
Draining, Widerruf und Recovery erhöhen Betriebs- und Nebenläufigkeitsaufwand, ohne Sybil-Angriffe oder Kollusion zu lösen.

## Rationale and alternatives
[rationale-and-alternatives]: #rationale-and-alternatives

### Warum feste, veröffentlichte Routen?

Sie erhalten das bestehende MWixnet-Nachbarschaftsmodell. Die Route-ID macht Änderungen an Reihenfolge, Schlüsseln oder Gebühren sichtbar.

### Warum eine einheitliche Gebühr?

`fee_per_hop` deckt das höchste Teilnehmerminimum ab und vereinfacht Prüfung und Vergleich. Da die Gebühr Teil der Route-ID ist, erzeugt jede Änderung bewusst eine neue Route und
neue Acceptances.

### Warum Grin-P2P nur für Discovery?

Nodes verteilen nur signierte, kurzlebige Metadaten. Geheimnisse, Manifeste, Health-Nachweise und Ausführung bleiben auf Tor; Nodes brauchen keinen Tor-Client.

### Alternativen

Manuelle Routen lösen Discovery, Health und Widerruf nicht. Eine zentrale Liste wäre zensierbar. Frei pro Swap gebaute Routen würden dynamische Nachbarschaftsautorisierung
erfordern. Aktive Onion-Prüfung durch Grin-Nodes würde Tor-Betrieb und vervielfachten Prüfverkehr auf jeder Node verlangen.

## Prior art
[prior-art]: #prior-art

John Tromps Mimblewimble-CoinSwap nutzt eine geordnete Menge bekannter Mixnodes; dieser RFC ergänzt deren Bildung und Prüfung. WabiSabi und JoinMarket zeigen Discovery-, Auswahl-
und DoS-Mechanismen, verwenden aber andere Transaktions- und Koordinationsmodelle. Tor-v3-Adressen authentisieren einen Dienstschlüssel, nicht Ehrlichkeit oder
Betreiber-Unabhängigkeit.

## Resolved constraints and validation
[resolved-constraints-and-validation]: #resolved-constraints-and-validation

Die Gebühr bleibt Teil der Route-ID. Manifestlaufzeit, Health-Intervall und Zertifikatsalter sind für Version 1 festgelegt, obwohl Testnet-Messreihen noch fehlen. Permissionless
Mainnet-Relay gilt nur für Offers; fertige Routen bleiben allowlist-basiert. Nicht behauptet werden Betreiber-Unabhängigkeit, freie Routen pro Swap oder ein Tor-Ersatz.
Datenbankschema und UI sind lokal, die Persistenzinvarianten und Konformitätsvektoren nicht.

## Future possibilities
[future-possibilities]: #future-possibilities

Spätere Versionen können Routen automatisch erneuern, Wallets über mehrere Routen verteilen und stärkeren Sybil-Schutz durch Reputation oder Bonds ergänzen. Änderungen an
Offer-Schwierigkeit oder Wire-Format benötigen eine neue Protokollversion.

## References
[references]: #references

- [Grin-RFC-Vorlage](https://github.com/mimblewimble/grin-rfcs/blob/master/0000-template.md)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 8439: ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [Mimblewimble CoinSwap](https://forum.grin.mw/t/mimblewimble-coinswap-proposal/8322)
- [MWixnet](https://github.com/mimblewimble/mwixnet)
- [Grin-Referenzstand](https://github.com/mimblewimble/grin/commit/857254bb1e98fdb039a4e2579a024835e1bd20cb)
- [grin-wallet-Referenzstand](https://github.com/wiesche89/grin-wallet/commit/fed6733a2209aec2ed963a5691d91c6f00b4261d)
