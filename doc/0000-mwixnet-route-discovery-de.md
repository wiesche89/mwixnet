- Titel: `mwixnet-route-discovery`
- Autoren: `github/wiesche89`
- Startdatum: 30. Juli 2026
- RFC-PR: noch nicht eingereicht
- Tracking-Issue: noch nicht vorhanden

---

## Summary
[summary]: #summary

Dieser RFC beschreibt Bildung, Prüfung, Veröffentlichung und Verwendung
fester MWixnet-Routen. Heute benötigt eine Wallet Onion-Adressen, geordnete
öffentliche X25519-Schlüssel und Gebühren aus manueller Konfiguration.
Künftig schlägt der Swap-Server eine vollständige Route vor. Jeder Teilnehmer
bestätigt denselben Routenkern mit einer signierten Acceptance. Das daraus entstehende
Manifest bindet Reihenfolge, Identitäten, öffentliche Onion-Keys, Gebühr und
Gültigkeit.
Ein Healthcheck prüft anschließend die gesamte Kette über denselben Tor-Pfad,
den später auch Mix-Anfragen verwenden.

Grin-Nodes können kurzlebige, signierte Routenankündigungen (Gültigkeit:
15 Minuten) weiterleiten. Das vollständige Manifest und der Health-Nachweis
bleiben auf Tor. Vor dem Sperren
eines Outputs lädt die Wallet beide Dokumente, prüft Route-ID, Signaturen,
Acceptances, Aktualität und Gesamtgebühr und verwendet danach die geordnete
Route. Ein Mixer kann mehreren Routen angehören, innerhalb einer Route aber
nur einmal vorkommen. Der RFC behält die feste Ausführungskette von MWixnet
bei. Frei pro Swap gebildete Routen und die Ersetzung von Tor sind nicht
Gegenstand dieses Vorschlags. Unterschiedliche Serveridentitäten gelten nicht
als Nachweis unabhängiger Betreiber.

## Terminology
[terminology]: #terminology

- **Route:** geordnete Kette aus einem Swap-Server und mindestens einem Mixer.
- **Hop:** ein einzelner Teilnehmer an einer bestimmten Position der Route.
- **Swap-Server:** öffentlicher Einstiegspunkt einer Route. Er nimmt
  Wallet-Anfragen an und koordiniert Runden und Healthchecks.
- **Mixer:** nachgelagerter Server, der eine Onion-Schicht verarbeitet und das
  Ergebnis an den nächsten Hop weitergibt.
- **MixerOffer und SwapOffer:** signierte Beschreibung eines einzelnen Mixers
  oder Swap-Servers mit Identität, Onion-Adresse, öffentlichem Onion-Key,
  Mindestgebühr und Gültigkeit.
- **RouteProposal:** vollständiger, vom Swap-Server signierter Vorschlag für
  Reihenfolge, Schlüssel, Gebühr und Gültigkeit einer Route.
- **RouteAcceptance:** signierte Bestätigung eines Teilnehmers, dass er seine
  festgelegte Position in genau diesem `RouteProposal` akzeptiert.
- **RouteManifest:** `RouteProposal` mit den `RouteAcceptance`-Nachrichten
  aller Teilnehmer und der abschließenden Signatur des Swap-Servers.
- **Route-ID:** Hash über den unveränderlichen Kern einer Route. Änderungen
  an Reihenfolge, Teilnehmern, öffentlichen Onion-Keys oder Gebühr erzeugen
  eine neue ID.
- **RouteAnnouncement:** kurzlebige, signierte Zusammenfassung eines
  `RouteManifest` und des letzten `RouteHealthCertificate` für das
  Grin-P2P-Relay.
- **RouteStatus:** signierte Aktualisierung des Zustands einer angekündigten
  Route.
- **RouteRevocation:** signierter Widerruf der Teilnahme an einem bestimmten
  `RouteManifest`.
- **Healthcheck:** Prüfung der vollständigen Route ab dem Swap-Server über
  denselben Tor-Pfad wie eine spätere Server-zu-Server-Mix-Anfrage. Er prüft
  nicht, ob eine fremde Wallet den öffentlichen Entry-Onion erreichen kann.
- **HealthRequest:** signierte Server-zu-Server-Hülle mit der verschlüsselten
  Healthcheck-Schicht für genau einen Hop.
- **HealthAttestation:** signierte Antwort eines Hops, die Route, Challenge,
  Position und die Antwort des Nachfolgers bindet.
- **HealthResponse:** unsignierte Tor-Antworthülle mit der geordneten Kette
  einzeln signierter `HealthAttestation`-Einträge.
- **RouteHealthCertificate:** vom Swap-Server signiertes Ergebnis eines
  vollständig erfolgreichen Healthchecks.
- **RouteHealthProof:** über Tor gelieferter Nachweis aus Challenge,
  Hop-Nonces, Attestation-Kette und `RouteHealthCertificate`.
- **SwapReq:** bestehende Wallet-Anfrage an den Swap-Server. Dieser RFC ergänzt
  Route, Ablaufhöhe und eine stabile Request-ID.
- **SwapSubmission:** unsignierte RPC-Antwort des Swap-Servers mit dem
  persistenten Zustand eines `SwapReq` und, sobald vorhanden, dem
  Kernel-Excess der gebauten Transaktion.
- **MixReq:** signierte Server-zu-Server-Anfrage mit einem Batch von
  MWixnet-Onions für eine bestimmte Route und Runde.
- **MixResp:** bestehende Antwort auf `MixReq` mit den akzeptierten
  Eingabeindizes und Transaktionsbestandteilen.
- **CancelSwapReq:** signierte Stornierungsanfrage der Wallet für einen noch
  nicht verarbeiteten `SwapReq`.
- **CancelAck:** signierte Bestätigung des Swap-Servers, dass eine noch nicht
  verarbeitete Wallet-Anfrage storniert und mindestens bis zu ihrem Ablauf als
  storniert gespeichert wurde.
- **Preflight:** Verbindung der Wallet zum Entry-Onion und Prüfung von
  `RouteManifest`, `RouteAcceptance`-Nachrichten, `RouteHealthProof` und
  Gebühr, bevor sie einen Output sperrt.
- **Draining:** Routenzustand, in dem keine neuen Anfragen angenommen, bereits
  als `Accepted` gespeicherte Anfragen aber noch gebatcht und abgeschlossen
  werden.

## Motivation
[motivation]: #motivation

Im heutigen MWixnet sind der Zugriff auf die Grin-Chain und die
MWixnet-Ausführung über Tor getrennt:

```text
Zugriff auf die Grin-Chain:
Wallet      -> eigene Grin-Node
Swap-Server -> konfigurierte Grin-Node
Mixer 1     -> konfigurierte Grin-Node
...         -> ...
Mixer n     -> konfigurierte Grin-Node

MWixnet-Ausführung über Tor:
Wallet -> Swap-Server -> Mixer 1 -> ... -> Mixer n
```

Jeder MWixnet-Server kann auf eine konfigurierte Grin-Node zugreifen. Der
Swap-Server prüft den Input und Chain-Tip und veröffentlicht die fertige
Transaktion. Der letzte Mixer prüft, ob ein erzeugter Output bereits im UTXO-Set
liegt. Diese Verbindungen können dieselbe oder unterschiedliche Grin-Nodes
verwenden.

In der aktuellen Implementierung wird die Route statisch konfiguriert. Jeder
Server kennt seinen Vorgänger und Nachfolger. Die Wallet benötigt zusätzlich
die Onion-Adresse des Swap-Servers, die geordneten öffentlichen
X25519-Schlüssel und die Gebühr pro Hop. Aus dieser statischen Konfiguration
folgen:

- Benutzer geben kryptografische Routendaten manuell ein.
- Routen können nicht über Grin-Nodes entdeckt werden.
- Erreichbarkeit und Widerruf sind nicht standardisiert.
- Betreiber können Routen nicht protokolliert bilden.
- Die heutigen Parameter `prev_server` und `next_server` erlauben nur eine
  Route pro Mixer-Instanz.

Der RFC behält die feste Ausführungsroute bei und ergänzt dafür einen
signierten Lebenszyklus, Tor-Healthchecks und ein Grin-P2P-Relay. Zusätzlich
können MWixnet-Betreiber ihre signierten Offers über Grin-Nodes veröffentlichen,
damit ein Swap-Server geeignete Mixer ohne administrativ ausgetauschte
Onion-Adressen finden kann.
Damit kommt ein dritter, ausschließlich für die Discovery bestimmter Pfad
hinzu:

```text
Discovery mit diesem RFC:
Swap-Server -> Grin-Node <-> Grin-P2P-Netzwerk <-> Grin-Node <-> Wallet
Mixer/Swap  -> Grin-Node <-> Grin-P2P-Netzwerk <-> Grin-Node -> Swap-Server
```

Der Swap-Server übergibt seine signierten Routenmeldungen an eine verbundene
Grin-Node. Die Wallet fragt ihre eigene Grin-Node nach bekannten Routen. Die
eigentliche MWixnet-Ausführung bleibt davon getrennt und läuft weiterhin über
Tor.

Im Mainnet bleibt das Relay fertiger Wallet-Routen allowlist-basiert. Das
separate Offer-Relay ist permissionless und durch einen kleinen Proof-of-Work,
kurze Gültigkeit, Cache-Grenzen und Ratenlimits gegen billigen Spam begrenzt.
Ein gefundenes Offer ist keine Empfehlung und berechtigt seinen Betreiber
nicht, eine Route im Mainnet an Wallets anzukündigen.

## Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

Eine Route besteht aus einem Swap-Server und mindestens einem Mixer:

```text
Route A: Swap A -> Mixer X -> Mixer Y
Route B: Swap B -> Mixer Z -> Mixer X
```

Ein Mixer kann mehreren Routen angehören. Eine Identität kann innerhalb einer
Route nicht wiederholt werden.

```text
Ungültig: Swap A -> Mixer X -> Mixer Y -> Mixer X
```

Der Swap-Server schlägt eine vollständige Route vor. Jeder Teilnehmer
akzeptiert dasselbe Manifest. Anschließend prüft der Swap-Server die Kette
über den später verwendeten Tor-Pfad:

```text
Swap A -> Mixer X -> Mixer Y -> signierte Antwort
```

Nur akzeptierte und kürzlich geprüfte Routen werden angekündigt. Ein
MWixnet-fähiger Grin-Node hält dafür eine flüchtige Liste:

```text
get_mwixnet_routes
```

Der Node transportiert signierte Discovery-Daten. Er empfiehlt keine Route.
Die Wallet wählt eine Route, lädt Manifest und Health-Nachweis über Tor und
führt den in der Referenzbeschreibung definierten Preflight aus.

```bash
grin-wallet --testnet mwixnet send <commitment> --route <route-id>
```

### Ausfälle

Eine neu vereinbarte Route beginnt als `Proposed` und wird erst nach einem
vollständig erfolgreichen Healthcheck `Healthy`. Schlägt ein Healthcheck fehl,
etwa wegen eines Tor-Timeouts, wechselt sie zu `Degraded`.
Ein erfolgreicher Healthcheck setzt sie wieder auf `Healthy`. Nach drei
aufeinanderfolgenden Fehlschlägen wird sie `Unavailable` und nimmt keine neuen
Anfragen an. Auch aus diesem Zustand kann sie nach einem vollständig
erfolgreichen Healthcheck wieder `Healthy` werden. Jeder Erfolg setzt den
Fehlerzähler auf null.

`Healthy` beschreibt ausschließlich den zuletzt belegten Zustand der
Server-zu-Server-Route. Der Status behauptet keine globale Erreichbarkeit des
öffentlichen Entry-Onions. Diese Eigenschaft kann ein Swap-Server nicht für
fremde Tor-Clients belegen. Jede Wallet prüft den Entry-Onion deshalb selbst;
ohne erfolgreichen Entry-Preflight ist auch eine `Healthy` Route lokal nicht
verwendbar.

Ankündigungen laufen ohne Erneuerung ab. `Draining` verhindert neue Anfragen,
lässt bereits als `Accepted` gespeicherte Anfragen noch in Runden eingehen und
auslaufen.

Die Wallet kann diese Zustände für jede bekannte Route zusammen mit
Hop-Anzahl, Gesamtgebühr, letzter erfolgreicher Prüfung und Gültigkeitsende
anzeigen.

## Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

Alle Regeln sind direkt im Text formuliert. Sofern nicht anders angegeben,
sind alle Felder einer aufgeführten Nachrichtenstruktur verpflichtend.

### Schlüsselrollen

Jeder Swap-Server und Mixer besitzt eine Ed25519-Identität. Der öffentliche
Schlüssel bezeichnet den Server. Der private Schlüssel signiert lokal seine
Offers, Aussagen über Routen, Healthcheck-Antworten und die in diesem RFC als
signiert beschriebenen Nachrichten.

X25519 dient nur der Verschlüsselung. Die Wallet verwendet die geordnete Liste
der öffentlichen X25519-Schlüssel aus dem `RouteManifest`, um die
Onion-Schichten aufzubauen. Der zugehörige private Schlüssel verbleibt auf dem
jeweiligen Server. Private Ed25519- und X25519-Schlüssel werden weder in Offers
oder Manifeste aufgenommen noch über das Netzwerk übertragen. Wallet-Anfragen
werden weiterhin mit der bestehenden Commitment-Signatur des ausgegebenen
Outputs signiert. `MixResp` und `HealthResponse` tragen keine zusätzliche
Hüllensignatur. Ihre Inhalte werden durch signierte Anfragen beziehungsweise
Attestations gebunden und ausschließlich über die authentifizierte
Tor-Verbindung zurückgegeben.

Die heutige Implementierung leitet Ed25519, X25519 und den Tor-v3-Service aus
demselben geschützten 32-Byte-Server-Secret ab. Das Protokoll verlangt, dass
Ed25519-Identität und Tor-v3-Service-Identität übereinstimmen. Der
X25519-Schlüssel ist eine getrennte Schlüsselrolle. Er kann bei einer Migration
weiterhin aus demselben Secret abgeleitet oder separat erzeugt werden. In
beiden Fällen bindet die Acceptance den verwendeten öffentlichen X25519-Key.

### Hashes und Signaturen

Hashing und Binärserialisierung verwenden die vorhandenen Grin-Traits
`Writeable`, `Readable` und `Hashed`. Jeder signierte oder gehashte Datensatz
bindet zuerst eine MWixnet-Version als `u32` und danach einen Typ als `u8`.
Die Typkennung verhindert, dass ein Hash in einem anderen Zusammenhang
verwendet wird.

`MwixnetType` verwendet folgende feste Werte:

| Wert | Typ |
| ---: | --- |
| 0 | `MixerOffer` |
| 1 | `SwapOffer` |
| 2 | `RouteProposal` |
| 3 | `RouteAcceptance` |
| 4 | `RouteManifest` |
| 5 | `SwapReq` |
| 6 | `MixReq` |
| 7 | `MixResp` |
| 8 | `HealthChallenge` |
| 9 | `HealthRequest` |
| 10 | `HealthAttestation` |
| 11 | `RouteHealthCertificate` |
| 12 | `CancelSwapReq` |
| 13 | `CancelAck` |
| 14 | `RouteAnnouncement` |
| 15 | `RouteStatus` |
| 16 | `RouteRevocation` |
| 17 | `RouteId` |
| 18 | `HealthHopNonce` |
| 19 | `SwapReqOnion` |
| 20 | `HealthOnionLayer` |
| 21 | `HealthResponse` |
| 22 | `RouteHealthProof` |
| 23 | `OfferAnnouncement` |

Der Hash-Eingang ist ein eigener serialisierbarer Datensatz:

```text
MwixnetHashInput = (version:u32, msg_type:u8, payload)
HASH(type, payload) = MwixnetHashInput(version, u8(type), payload).hash()
```

`MwixnetHashInput` und `payload` implementieren `Writeable`, der Hash-Eingang
zusätzlich `DefaultHashable`. `hash()` ist dadurch die vorhandene Methode
`grin_core::core::hash::Hashed::hash()` und liefert den in Grin üblichen
32-Byte-BLAKE2b-Hash. Bei einer Nachricht enthält `payload` alle aufgeführten
Felder außer `version`, `type` und dem äußeren Signaturfeld. Diese Werte werden
dadurch nicht doppelt serialisiert. Eingebettete Signaturen, etwa die
Acceptances eines Manifests, bleiben Teil des Payloads.

Bei reinen Hash-Typen wie `RouteId`, `HealthHopNonce`, `SwapReqOnion` und
`HealthOnionLayer` ist `version = MWIXNET_PROTOCOL_VERSION`.

Die `Writeable`-Implementierungen dieser Datensätze hängen nicht von der
ausgehandelten Grin-P2P-Version ab. Die MWixnet-Version im Datensatz bestimmt
das Format. APIs und Diagnose können JSON verwenden, gehasht und signiert wird
die Binärdarstellung.

Server signieren den mit `HASH` berechneten Wert mit Ed25519.
Wallet-Nachrichten verwenden dafür die bestehende Commitment-Signatur. Ein
bereits berechneter Hash wird vor der Signatur nicht erneut mit `HASH`
verarbeitet.

`MwixnetType` ist vom Grin-P2P-Enum `msg::Type` getrennt. Die P2P-Werte 31 bis
38 kennzeichnen die MWixnet-Nachrichtenheader, während `MwixnetType`
Bestandteil der signierten MWixnet-Daten ist.

Diese Typen sind im heutigen Grin- und grin-wallet-Code noch nicht definiert.
Bei der Umsetzung erhalten MWixnet-Server und Wallet dieselben festen
`MwixnetType`-Werte und dieselbe Binärserialisierung. Die Grin-Node benötigt
davon nur die Discovery-Datensätze. Der vorhandene `SwapReq` aus grin-wallet
und die vorhandenen `MixReq`- und `MixResp`-Strukturen aus MWixnet behalten
ihre Namen und werden um die hier aufgeführten Felder erweitert.

Die Binärdarstellung verwendet Grins Big-Endian-`Writer`. Folgende Typen
gelten in allen Hash-Eingängen und P2P-Nachrichten:

| Feldart | Darstellung |
| --- | --- |
| Version | `u32`, Wert `1` |
| Typ, Rolle, Status und Hop-Position | `u8` |
| Sequenznummern | `u64` |
| Zeitstempel | `u64` Unix-Sekunden in UTC |
| Blockhöhen | `u64` |
| Gebühren | `u64` Nanogrin |
| Route-ID, Hash, Nonce und Batch-ID | 32 Byte |
| Ed25519- und X25519-Public-Key | 32 Byte |
| Ed25519-Signatur | 64 Byte |
| Pedersen-Commitment | vorhandene 33-Byte-Grin-Darstellung |
| Tor-v3-Onion-Adresse | 32-Byte-Service-Identität |
| `Option<T>` | `0:u8` oder `1:u8 || T` |
| Liste | `count:u16 || elements[count]` |
| variables Bytefeld | `length:u32 || bytes[length]` |

Die textuelle Tor-Adresse mit Prüfsumme, Versionsbyte und `.onion` wird nur
für Anzeige und JSON verwendet. Hashes und P2P-Nachrichten enthalten die
32-Byte-Service-Identität. Listen verwenden immer den genannten Zähler und
nicht Grins generische `Vec<T>`-Serialisierung. Beim Lesen wird der Zähler vor
einer Speicherallokation gegen die jeweilige Protokollgrenze geprüft.
Ein anderer Wert als `MWIXNET_PROTOCOL_VERSION` wird als nicht unterstützte
Protokollversion abgelehnt.

Die Listenregel gilt für die in diesem RFC neu eingeführten Felder. Bereits
vorhandene eingebettete Grin-Typen behalten ihre am Referenzstand vorhandene
`Writeable`-Darstellung. Das betrifft `Onion`, `ComSignature`, `FeeFields`,
`RangeProof`, `Input`, `Output`, `TxKernel`, `Transaction` und die darin
enthaltenen Listen. Insbesondere verwendet `MixReq.onions[]` außen einen
`u16`-Zähler. Jeder einzelne `Onion` verwendet innen weiterhin die vorhandene
Darstellung mit `u64` für Anzahl und Länge seiner verschlüsselten Payloads.
`TxComponents` wird als `(offset, kernels, outputs)` serialisiert. `offset`,
`TxKernel` und `Output` behalten ihre vorhandene Grin-Darstellung, die beiden
äußeren Listen verwenden einen `u16`-Zähler.

Für `SwapReq` ist der Hash-Payload ausdrücklich:

```text
SwapReqSignedPayload = (
  wallet_request_id, route_id, manifest_sequence,
  expires_at_height, onion_hash
)
```

Der vollständige `Onion` wird einmal mit seiner vorhandenen
`Writeable`-Darstellung in `onion_hash` gebunden und nicht ein zweites Mal in
`swap_req_hash` serialisiert. `payload_without_comsig` bezeichnet bei
`SwapReq` genau `SwapReqSignedPayload`.

`role` verwendet `Swap = 0` und `Mixer = 1`. `status` verwendet
`Proposed = 0`, `Healthy = 1`, `Degraded = 2`, `Unavailable = 3`,
`Draining = 4`, `Expired = 5` und `Revoked = 6`. Eine ungültige Enum-Kennung
wird abgelehnt. `TERMINAL` ist die leere Variante einer `Option`.

### Protokollkonstanten und Implementierungsgrenzen

Folgende Werte sind Teil des Protokolls:

| Konstante | Wert |
| --- | ---: |
| `MWIXNET_PROTOCOL_VERSION` | 1 |
| `MIN_ROUTE_HOPS` | 2 einschließlich Swap-Server |
| `MAX_ROUTE_HOPS` | 8 einschließlich Swap-Server |
| `MAX_MANIFEST_VALIDITY` | 30 Tage |
| `MAX_CLOCK_SKEW` | 2 Minuten |
| `MAX_HEALTH_CERTIFICATE_AGE` | 15 Minuten |
| `UNAVAILABLE_AFTER_FAILURES` | 3 aufeinanderfolgende Fehlschläge |
| `MAX_ROUTE_ANNOUNCEMENT_VALIDITY` | 15 Minuten |
| `MAX_OFFER_ANNOUNCEMENT_VALIDITY` | 24 Stunden |
| `OFFER_POW_DIFFICULTY_BITS` | 16 führende Nullbits |
| `MIN_REQUEST_TTL_BLOCKS` | 10 Blöcke |
| `MAX_REQUEST_TTL_BLOCKS` | 1.440 Blöcke |
| `P2P_GET_ROUTES_MAX_BYTES` | 64 Byte |
| `P2P_BATCH_MAX_ROUTES` | 128 |
| `P2P_BATCH_MAX_BYTES` | 128 KiB |
| `P2P_ANNOUNCEMENT_MAX_BYTES` | 1 KiB |
| `P2P_STATUS_MAX_BYTES` | 512 Byte |
| `P2P_REVOCATION_MAX_BYTES` | 512 Byte |
| `P2P_GET_OFFERS_MAX_BYTES` | 64 Byte |
| `P2P_OFFER_BATCH_MAX_ITEMS` | 128 |
| `P2P_OFFER_BATCH_MAX_BYTES` | 128 KiB |
| `P2P_OFFER_ANNOUNCEMENT_MAX_BYTES` | 1 KiB |
| `MAX_MIX_BATCH_SIZE` | 128 Onions |
| `MAX_HEALTH_CHALLENGE_LIFETIME` | 5 Minuten |
| `HEALTH_REQUEST_MAX_BYTES` | 64 KiB |
| `MWIXNET_RPC_MAX_BYTES` | 2 MiB |

Folgende Werte sind lokale Standardwerte und keine Netzwerkparameter:

| Einstellung | Standardwert |
| --- | ---: |
| `HEALTH_INTERVAL` | 5 Minuten mit zufälligem Jitter |
| `HEALTH_REQUESTS_PER_MINUTE` | 16 je Serverinstanz |
| `MIXER_ROUTE_LIMIT` | 32 aktive oder drainende Routen |
| `MIXER_PROPOSAL_RATE` | 16 Proposals je Mixer und Minute |
| `ROUTE_RENEWAL_WINDOW` | 1 Stunde |
| `NODE_ROUTE_CACHE_LIMIT` | 1.024 Routen |
| `NODE_OFFER_CACHE_LIMIT` | 1.024 Offers |
| `NODE_NEW_MESSAGE_RATE` | 16 Nachrichten je Peer und Minute |
| `NODE_NEW_ROUTE_RATE` | 128 Routeneinträge je Peer und Minute |
| `NODE_ROUTE_UPDATE_RATE` | 1 reguläres Update je Route und Minute |
| `NODE_REVOCATION_UPDATE_RATE` | 1 Update je Route und Teilnehmer pro Minute |
| `NODE_NEW_OFFER_RATE` | 32 neue Offer-Identitäten je Peer und Minute |
| `NODE_OFFER_UPDATE_RATE` | 1 Update je Identität und Offer-Typ pro Minute |
| `ROUTE_RELAY_SYNC_INTERVAL` | 5 Minuten mit zufälligem Jitter |
| `OFFER_RELAY_SYNC_INTERVAL` | 5 Minuten mit zufälligem Jitter |
| `WALLET_REQUEST_TTL_BLOCKS` | 120 Blöcke |
| `max_request_ttl_blocks` | 1.440 Blöcke |

Einige Werte stehen in einem direkten Verhältnis zueinander.
`MAX_ROUTE_HOPS = 8` ist eine defensive Obergrenze und keine empfohlene
Routenlänge. Erwartet werden ein Swap-Server und ein bis drei Mixer. Jeder
weitere Hop erhöht Gebühr, Tor-Latenz und Ausfallwahrscheinlichkeit, ohne die
Unabhängigkeit der Betreiber zu belegen. Bei einem Health-Intervall von fünf
Minuten soll das 15-Minuten-Zertifikatsalter zwei ausgefallene Prüfungen
tolerieren, bevor eine Route für Wallets unbrauchbar wird. 120 Blöcke
entsprechen bei Grins Zielzeit ungefähr zwei Stunden. Die Obergrenze von 1.440
Blöcken entspricht ungefähr einem Tag.

Die Cache- und Batchgrenzen begrenzen vor allem Speicher- und
Deserialisierungsarbeit. 1.024 Ankündigungen belegen höchstens 1 MiB. Mit je
einem Status und bis zu acht Widerrufen pro Route liegt die theoretische
Obergrenze der serialisierten Cache-Daten bei 5,5 MiB, bevor
Implementierungs-Overhead hinzukommt. 128 Routengruppen passen nur dann in
einen Batch, wenn zugleich die 128-KiB-Grenze eingehalten wird. Die 30 Tage
Manifestgültigkeit sind eine Obergrenze, keine empfohlene Laufzeit. Ob sie
unter realer Gebührenrotation sinnvoll ist, zeigt erst der Testnet-Betrieb.
Die lokalen `NODE_*`-Raten sind Ausgangswerte und können ohne
Protokolländerung geändert werden.

`HEALTH_REQUESTS_PER_MINUTE` gilt gemeinsam für alle Routen einer
Serverinstanz; bei Überschreitung antwortet sie mit `server_busy`.
`ROUTE_RENEWAL_WINDOW` bestimmt ausschließlich lokale Erneuerungspolitik:
Solange ein nicht drainendes und nicht terminales Manifest noch länger als
dieses Fenster gültig ist, darf der Swap-Server es weiterverwenden. Innerhalb
des Fensters bildet er bei fortgesetztem Betrieb die nächste
Manifest-Sequenz. Der Standard für `max_request_ttl_blocks` entspricht in der
ersten Ausbaustufe der Netzwerkobergrenze. Eine Laufzeitkonfiguration dieses
Werts ist nicht erforderlich; ein anderer lokaler Wert muss jedoch innerhalb
der Protokollgrenzen liegen und im `SwapOffer` veröffentlicht werden.

`MAX_MIX_BATCH_SIZE = 128` begrenzt Onion-Prüfung und Antwortabbildung einer
einzelnen Runde. Die zusätzliche 2-MiB-RPC-Grenze bindet auch ungewöhnlich
große, aber formal gültige Onion-Payloads. Health-Schichten sind wesentlich
kleiner und erhalten mit 64 KiB eine eigene Grenze, damit ihre rekursive
Struktur vor der Kryptographie vollständig geprüft werden kann.

### MWixnet-Offers

Ein `MixerOffer` enthält:

```text
MixerOffer = (
  version, type=MixerOffer, identity_public_key,
  onion_address, onion_public_key, minimum_fee,
  capacity, valid_until, sequence, signature
)
```

Ein `SwapOffer` enthält:

```text
SwapOffer = (
  version, type=SwapOffer, identity_public_key,
  onion_address, onion_public_key, minimum_fee,
  capacity, desired_min_hops:Option<u8>,
  desired_max_hops:Option<u8>,
  maximum_fee_per_hop:Option<u64>,
  max_request_ttl_blocks:u16,
  valid_until, sequence, signature
)
```

`capacity` ist eine unverbindliche `u32`-Angabe zur Zahl neuer Onions pro
Runde. Sie dient der Routenbildung, reserviert aber keine Kapazität.
Gewünschte Hop-Zahlen zählen den Swap-Server mit und liegen innerhalb der
Protokollgrenzen. MWixnet-Offers sind keine Wallet-Routen.

Die Offer-Sequenz beginnt je Kombination aus Identität und Offer-Typ bei 1
und steigt bei jeder inhaltlichen Änderung. Eine identische Wiederholung
derselben Sequenz ist zulässig. Dieselbe Sequenz mit anderem Inhalt und jede
kleinere Sequenz werden abgelehnt. Der Sequenzstand wird dauerhaft
gespeichert. Ist `u64::MAX` erreicht, veröffentlicht der Betreiber unter
dieser Identität kein weiteres Offer.

Ein Offer ist bei Annahme noch nicht abgelaufen und `valid_until` liegt nicht
mehr als `MAX_MANIFEST_VALIDITY` in der Zukunft. Eine daraus gebildete Route
endet spätestens mit dem zuerst ablaufenden Offer. Onion-Adresse und
öffentlicher Onion-Key stimmen mit den aktiven Schlüsseln der unterzeichnenden
Identität überein. `max_request_ttl_blocks` liegt zwischen
`MIN_REQUEST_TTL_BLOCKS` und `MAX_REQUEST_TTL_BLOCKS`.

Für die Veröffentlichung wird das unveränderte signierte Offer in eine
`OfferAnnouncement`-Hülle gelegt:

```text
OfferAnnouncement = (
  version, type=OfferAnnouncement, offer:MwixnetOffer, pow_nonce:u64
)
```

Der Proof-of-Work-Hash ist:

```text
offer_pow_hash = HASH(
  MwixnetType::OfferAnnouncement,
  offer.hash(),
  pow_nonce
)
```

Die ersten `OFFER_POW_DIFFICULTY_BITS` des Hashes sind null. Der Nonce ist
nicht Teil des signierten Offers; seine Änderung kann deshalb weder Endpunkt,
Gebühr noch Identität verändern. Die Node prüft zuerst Größen- und
Zeitgrenzen, dann den Proof-of-Work und erst danach die Ed25519-Signatur.
`valid_until` liegt bei Relay-Annahme höchstens
`MAX_OFFER_ANNOUNCEMENT_VALIDITY` in der Zukunft.

Ein Swap-Server mit aktivierter Offer-Discovery fragt seine Grin-Node nach
Mixer-Offers. Er verwirft abgelaufene, ungültige, zu teure und mit seiner
Route kollidierende Identitäten. Vor Aufnahme in einen Proposal ruft er über
die angekündigte Onion-Adresse `get_mwixnet_offer` auf. Das direkt geladene,
gültige Offer stammt von derselben Identität und hat mindestens die
angekündigte Sequenz; in den Proposal gelangt ausschließlich dieses direkt
geladene Offer. Eine feste Mixer-Liste bleibt als Betreiberkonfiguration
erhalten. Ist zusätzlich Discovery aktiv, bildet sie den festen Anfang der
Route und wird nur bis zur Zielgröße ergänzt.

Jeder MWixnet-Server reicht sein eigenes Offer unmittelbar nach dem Start und
danach alle sechs Stunden erneut bei seiner Grin-Node ein. Sinkt die restliche
Gültigkeit unter zwölf Stunden, erzeugt er vor der nächsten Veröffentlichung
ein neues signiertes Offer mit erhöhter Sequenz. Der Proof-of-Work wird für
die jeweilige `OfferAnnouncement` lokal berechnet.

Ein Swap-Server verwendet Offer-Discovery nur mit `discover_mixers = true`.
`target_route_hops` gibt die gewünschte Zahl der Teilnehmer einschließlich
des Swap-Servers an und liegt zwischen 2 und `MAX_ROUTE_HOPS`; der Standard
ist 2. Ohne feste Mixer-Konfiguration wählt der Swap-Server beim Start ein
gültiges Mixer-Offer als ersten Mixer. Danach synchronisiert er Offers
regelmäßig und ergänzt die geordnete Route, bis die Zielgröße erreicht ist.
Die konkrete Auswahl unter gleich geeigneten Offers ist lokale Politik des
Swap-Betreibers und nicht konsensrelevant.

Die Referenzimplementierung behält konfigurierte Mixer als festen
Routenanfang und mischt zusätzliche Kandidaten vor jedem Auswahlzyklus in
zufälliger Reihenfolge. Liegen wider Erwarten mehrere Ankündigungen derselben
Identität vor, wird nur die höchste Sequenz berücksichtigt. In der gemischten
Reihenfolge nimmt sie den ersten über Tor direkt erreichbaren Mixer mit
gültigem Offer auf, bis `target_route_hops` erreicht ist. Ein ungültiger oder
nicht erreichbarer Kandidat wird übersprungen und für 15 Minuten nicht erneut
geprüft. `minimum_fee` und `capacity` bestimmen keine Rangfolge;
`capacity = 0` schließt einen Kandidaten lediglich aus.

Eine veröffentlichte Route wird dabei niemals verändert. Für jeden neuen
Mixer bildet der Swap-Server aus der bisherigen Hop-Reihenfolge plus dem neuen
Mixer eine neue Route-ID und ein neues Manifest. Die alte Route bleibt aktiv,
bis alle Teilnehmer das neue Manifest akzeptiert haben und dessen
End-to-End-Healthcheck erfolgreich war. Erst danach wird die neue Route
angekündigt und die alte Route auf `Draining` gesetzt. Schlagen Proposal,
Aktivierung oder Healthcheck fehl, bleibt die alte Route unverändert aktiv.
Jeder Mixer bestimmt Vorgänger und Nachfolger einer dynamischen Route aus dem
aktivierten Manifest; `prev_server` und `next_server` gelten weiterhin für
den statischen Legacy-Pfad.

Erreicht eine Route nach `UNAVAILABLE_AFTER_FAILURES` fehlgeschlagenen
End-to-End-Healthchecks den Zustand `Unavailable`, prüft die
Referenzimplementierung die Offers aller nach dem Entry automatisch entdeckten
Mixer erneut direkt über Tor. Ungültige oder nicht erreichbare
Discovery-Mixer werden aus der lokalen Routenkandidatenliste entfernt. Lässt
sich der Fehler dadurch nicht einem Teilnehmer zuordnen, wird höchstens der
zuletzt ergänzte Discovery-Mixer entfernt. Konfigurierte Mixer und der
Entry-Mixer werden niemals automatisch entfernt, weil offene Requests älterer
Routen weiterhin an ihren ursprünglichen ersten Hop gebunden sind. Entfernte
Identitäten unterliegen dem normalen Retry-Backoff und die Route wird erst
nach Erreichen von `target_route_hops`, vollständiger Annahme und erfolgreichem
End-to-End-Healthcheck ersetzt. Die ausgefallene Route bleibt bis dahin
`Unavailable`; sie wird nicht als kürzere Route neu veröffentlicht.

Offer-Discovery belegt weder Kapazität noch Betreiber-Unabhängigkeit. Sie
ermöglicht einem neuen Mixer lediglich, auffindbar zu werden. Nur ein
Swap-Server entscheidet lokal über die Auswahl und nur eine vollständig
akzeptierte, gesunde Route wird anschließend für Wallets angekündigt.

Ein noch keiner Route zugeordneter Betreiber startet seine Instanz mit
`mixer = true` und ohne `prev_server` oder `next_server`. Die Instanz arbeitet
damit als letzter Mixer, veröffentlicht ihr Offer und wartet auf Proposals.
Die bisherige Rollenerkennung über ein gesetztes `prev_server` bleibt aus
Kompatibilitätsgründen gültig.

### Routenbildung

Ein `RouteProposal` ist von der enthaltenen `swap`-Identität signiert. Nur
Swap-Server initiieren Routen. Wallets und reine Mixer tun dies nicht.

Ein `RouteProposal` enthält:

```text
RouteProposal = (
  version, type=RouteProposal, route_id, manifest_sequence,
  valid_from, valid_until, fee_per_hop, ordered_hops[],
  proposer_signature
)

Hop = (role, identity_public_key, onion_address, onion_public_key)
```

`ordered_hops[0]` ist genau der Swap-Server. Alle weiteren Einträge sind
Mixer. Die Identität des Proposal-Unterzeichners entspricht
`ordered_hops[0].identity_public_key`. Im Manifest gilt dasselbe für
`swap_identity`. Jede Onion-Adresse wird aus der zugehörigen
Ed25519-Identität hergeleitet und geprüft. Eine Route enthält keine Identität
mehrfach.

Der Proposal-Hash ist:

```text
proposal_hash = HASH(
  MwixnetType::RouteProposal,
  RouteProposal.payload_without_signature
)
```

`proposer_signature` signiert diesen Hash.

Für eine neue Route ist `manifest_sequence = 1`. Eine Erneuerung derselben
Route verwendet genau den Nachfolger der zuletzt abgeschlossenen
Manifest-Sequenz. Ein Swap-Server beginnt je Route nur einen Vorschlag für
diese nächste Sequenz. Bei `u64::MAX` kann die Route nicht weiter verlängert
werden. `valid_from` liegt höchstens `MAX_CLOCK_SKEW` in der Zukunft.
`valid_until` liegt nach `valid_from`, höchstens
`MAX_MANIFEST_VALIDITY` danach und nicht nach dem Ablauf eines beigefügten
Offers.

Vor einer Acceptance prüft jeder Teilnehmer:

- seine eigene Position,
- seinen Vorgänger und Nachfolger in der signierten Hop-Reihenfolge,
- die signierten MWixnet-Offers und vollständigen Schlüsseltupel aller Hops,
- dass sein eigenes `(identity_public_key, onion_address,
  onion_public_key)`-Tupel exakt seinen aktiven öffentlichen Schlüsseln
  entspricht,
- die Übereinstimmung der angegebenen Route-ID mit der selbst berechneten
  Route-ID,
- Gebühr und Gültigkeitsdauer,
- dass `fee_per_hop` mindestens seinem veröffentlichten `minimum_fee`
  entspricht,
- maximale Hop-Anzahl,
- doppelte Identitäten,
- lokale Kapazitäts- und Betreiberregeln.

Eine `RouteAcceptance` enthält:

```text
RouteAcceptance = (
  version, type=RouteAcceptance, route_id, manifest_sequence,
  proposal_hash, participant_identity, accepted_until, signature
)
```

Die Signatur verwendet
`HASH(MwixnetType::RouteAcceptance, payload_without_signature)`. Alle
Acceptances binden denselben Proposal-Hash. Eine Route bleibt unvereinbart,
solange eine gültige Acceptance fehlt. Abweichende Manifest-Sequenzen sind
ungültig.

Jeder Teilnehmer speichert zu `(route_id, manifest_sequence)` den
`proposal_hash` und seine erzeugte Acceptance. Eine Wiederholung desselben
Vorschlags gibt byteidentisch dieselbe Acceptance zurück. Ein anderer
Proposal-Hash unter demselben Schlüssel ergibt `proposal_conflict`. Eine
verlorene RPC-Antwort kann dadurch ohne neuen Vorschlag wiederholt werden.
`accepted_until` liegt nicht nach `proposal.valid_until` oder dem Ablauf des
eigenen Offers. Der Swap-Server erzeugt seine eigene Acceptance nach denselben
Regeln lokal.

Wird aus einem Proposal kein Manifest, bleibt seine Idempotenzbindung bis
`proposal.valid_until + MAX_CLOCK_SKEW` bestehen. Danach kann der Swap-Server
für dieselbe noch nicht abgeschlossene Manifest-Sequenz einen neuen Proposal
erzeugen. Der abgelaufene Vorschlag wird unabhängig von seinem früheren
Sequenzstand nicht erneut akzeptiert.

Die `route_id` ist:

```text
route_id = HASH(
  MwixnetType::RouteId,
  (fee_per_hop, hop_count,
   ordered(role, identity_public_key, onion_public_key))
)
```

Signaturen, Sequenznummern, Health-Daten, `valid_from`, `valid_until` und die
aus der Ed25519-Identität abgeleitete Onion-Adresse gehen nicht in die
Route-ID ein.

Änderungen an Reihenfolge, Rolle, Identität, öffentlichem Onion-Key oder
`fee_per_hop` erzeugen eine neue Route-ID. Eine Verlängerung verwendet dieselbe
Route-ID, eine höhere Manifest-Sequenz und neue Acceptances.

### Route-Manifest

```text
RouteManifest = (
  version, type=RouteManifest, route_id, manifest_sequence,
  proposal_hash, valid_from, valid_until, fee_per_hop,
  ordered_hops[], proposer_signature, acceptances[],
  swap_identity, signature
)

manifest_hash = HASH(
  MwixnetType::RouteManifest,
  RouteManifest.payload_without_signature
)
```

`ordered_hops` enthält die geordnete Liste aus Rolle, öffentlichem
Identitätsschlüssel, Onion-Adresse und öffentlichem Onion-Key.
`proposer_signature` ist die ursprüngliche Signatur des aus diesen Feldern
rekonstruierten `RouteProposal` und wird gegen `proposal_hash` geprüft.
`acceptances` enthält die signierte `RouteAcceptance` jedes Teilnehmers. Die
abschließende Signatur des Swap-Servers bindet `manifest_hash`. Beide Listen
haben dieselbe Länge. Zu jeder Hop-Identität existiert genau eine Acceptance,
weitere Acceptances sind ungültig.

Jeder Teilnehmer signiert mit seiner Acceptance den vollständigen,
unveränderlichen Route-Kern. Manifest, Proposal und Acceptances referenzieren
dieselbe Route-ID, Manifest-Sequenz und denselben Proposal-Hash. Zur Laufzeit
genügt es, wenn ein Mixer Route-ID,
Manifest-Sequenz, Gültigkeit, Swap-Identität und seine Nachbarn speichert.
Ein lokal gespeicherter Mixer-Zustand beschreibt nur, ob dieser Mixer für die
Route arbeiten kann. Er ist keine eigenständige, öffentlich angekündigte Sicht
auf den Gesamtzustand; diesen signiert ausschließlich der Swap-Server.

Die Gültigkeit eines Manifests überschreitet `MAX_MANIFEST_VALIDITY` nicht.
Eine Erneuerung enthält eine höhere Manifest-Sequenz und neue Acceptances.
`valid_until` ist kleiner oder gleich jedem `accepted_until`. Ein Manifest,
das nur mit einer größeren Zeitabweichung als `MAX_CLOCK_SKEW` gültig wäre,
wird abgelehnt.

### Mehrere Routen pro Mixer

Die bisherige Einzelkonfiguration aus `prev_server` und `next_server` wird
durch eine Routentabelle ergänzt. Jeder Eintrag speichert mindestens
`route_id`, `manifest_sequence`, `prev_server`, `next_server` und
`valid_until`. Schlüssel der Tabelle ist `(route_id, manifest_sequence)`.
Eine erneuerte Manifest-Sequenz und ihre drainende Vorgängerin können dadurch
gleichzeitig existieren. Kein Request oder Batch wird nachträglich auf eine
andere Sequenz umgebogen.

Bei einem routengebundenen Request entspricht die Zahl der verschlüsselten
Onion-Payloads genau der Zahl der `ordered_hops` im zugehörigen Manifest. Der
Swap-Server leitet diese Prüfung und den nächsten Mixer aus dem Manifest ab.
Eine zusätzliche statische `next_server`-Konfiguration ist für per Discovery
gebildete Routen nicht erforderlich. Der Legacy-Betrieb verwendet weiterhin
`next_server`.

Der bestehende `MixReq` wird um Route und Runde erweitert. `MixResp` behält
seine Felder `indices` und `components` und bindet die Antwort an `batch_id`:

```text
MixReq = (
  version, type=MixReq, route_id, manifest_sequence,
  batch_id[32], onions[], sig
)
MixResp = (
  version, type=MixResp, batch_id[32], indices:u16[], components
)
```

```text
mix_req_hash = HASH(MwixnetType::MixReq, payload_without_sig)
```

`sig` signiert `mix_req_hash`.

Der Mixer prüft den Absender gegen den autorisierten Vorgänger der Route. Der
Swap-Server erzeugt `batch_id` als zufälligen 32-Byte-Wert für die
gesamte Runde. Die ID bleibt entlang der Route erhalten. Eine individuelle
Wallet-Kennung wird weder an einen Mixer weitergegeben noch in einer
Onion-Schicht offengelegt.

`MixReq` verarbeitet einen Batch von Onions. `MixResp.indices` enthält die
Indizes der erfolgreich verarbeiteten Einträge im empfangenen `MixReq`. Die
Indizes sind aufsteigend, eindeutig und kleiner als die Zahl der angefragten
Onions. Damit bleibt die bestehende Teilfilterung ungültiger oder bereits
verbrauchter Einträge erhalten. Eine interne Sortierung oder Weiterleitung
ändert die auf den Eingangsbatch bezogenen Indizes nicht.

Leitet ein Mixer nur eine Teilmenge weiter, merkt er sich die Abbildung auf
die Positionen seines Eingangsbatches. Die vom Nachfolger gelieferten Indizes
beziehen sich auf die weitergeleitete Teilmenge und werden vor der Antwort an
den Vorgänger auf die ursprünglichen Positionen dieses Mixers zurückgeführt.
So kann der Swap-Server jeden angenommenen oder abgelehnten Eintrag seinem
Wallet-Request zuordnen, ohne eine Wallet-Kennung weiterzugeben.

Die Runde und nicht eine einzelne Onion bildet die Anonymitätsmenge. Ein
Fehler wie `server_busy` lehnt den gesamten Batch ab und erzeugt keine
`MixResp`. Eine erfolgreiche Antwort kann dagegen weniger Indizes als die
Anfrage Onions enthalten. `MixResp` wird nicht separat signiert. Die
authentifizierte Tor-Verbindung, `batch_id` und die gespeicherte
Idempotenzantwort binden sie an die Anfrage.

Auch eine leere Indexliste ist eine erfolgreiche, abgeschlossene Antwort.
`components` enthält dann den Null-Offset sowie leere Kernel- und
Output-Listen. Sie bedeutet, dass kein Eintrag dieses Batches die vollständige
Reststrecke durchlaufen hat. Der Vorgänger baut daraus keine Transaktion. Ein
lokal ungültiger Onion-Eintrag wird gefiltert und nicht als Fehler des ganzen
Batches behandelt. Signaturfehler, unbekannte Route, falsche
Manifest-Sequenz, ein abgelaufener oder nicht mehr ausführbarer Routeneintrag
und Größenüberschreitungen lehnen dagegen den gesamten Aufruf ab.

Ein `MixReq` enthält zwischen 1 und `MAX_MIX_BATCH_SIZE` Onions und bleibt mit
JSON-RPC-Hülle innerhalb von `MWIXNET_RPC_MAX_BYTES`. Größere Runden werden am
Swap-Server in getrennte Batches mit unterschiedlichen `batch_id`-Werten
aufgeteilt.

Vor dem Speichern einer Antwort prüft jeder Vorgänger `batch_id`, Ordnung und
Grenzen der Indizes sowie die Deserialisierung aller Komponenten. Bei einer
nichtleeren Antwort entspricht die Zahl der Outputs der Zahl der Indizes. Die
Zahl der bereits enthaltenen Kernel entspricht der Zahl der durchlaufenen
Mixer ab dem antwortenden Nachfolger bis zum letzten Hop. Der Swap-Server
erwartet daher genau einen Mixer-Kernel je Mixer der Route, bevor er seinen
eigenen Kernel ergänzt. Abweichungen sind
`invalid_mwixnet_message` und werden nicht als abgeschlossene Antwort
gespeichert.

Eine Route hält `MIN_ROUTE_HOPS` und `MAX_ROUTE_HOPS` ein.
Der Wallet-Wert `MAX_MWIXNET_HOPS` wird bei der Integration auf dieselbe
Obergrenze gesetzt. Für Mixer gilt `MIXER_ROUTE_LIMIT` als lokaler
Standardwert.

Für jede Kombination aus `route_id` und `batch_id` speichert der Mixer
`mix_req_hash` und Batch-Antwort. Eine identische Wiederholung liefert dieselbe
Antwort. Ein abweichender `mix_req_hash` wird mit `batch_conflict` abgelehnt.

Pro `route_id` und `batch_id` läuft höchstens eine Verarbeitung.
Unterschiedliche Routen können parallel verarbeitet werden. Bei erschöpfter
lokaler Kapazität antwortet der Mixer mit `server_busy` und markiert den Batch
nicht als verarbeitet.

Ein Mixer schreibt `mix_req_hash` vor der ersten Weiterleitung als
`InFlight`. Nach einer vollständigen `MixResp`, einschließlich einer leeren
Antwort, speichert er `Completed` und die Antwort atomar. Ein transienter
Transport-, Node- oder `server_busy`-Fehler entfernt nur die laufende
Verarbeitung. Derselbe Hash kann danach erneut ausgeführt werden. Ein
abgeschlossener Batch wird nie erneut ausgeführt.

### Healthcheck

Der Healthcheck durchläuft denselben Server-zu-Server-Tor-Pfad wie ein Mix und
zurück. Der Swap-Server signiert eine kurzlebige Challenge mit:

```text
HealthChallenge = (
  version, type=HealthChallenge, route_id,
  manifest_sequence, nonce[32],
  created_at, expires_at, signature
)
```

`challenge_hash` ist
`HASH(MwixnetType::HealthChallenge, payload_without_signature)`. Die Signatur
bindet diesen Hash. Der Klartext wird nicht weitergereicht.

`created_at` liegt höchstens `MAX_CLOCK_SKEW` in der Zukunft. `expires_at`
liegt nach `created_at` und höchstens
`MAX_HEALTH_CHALLENGE_LIFETIME` danach. Der Swap-Server verwirft eine Antwort,
die nach `expires_at + MAX_CLOCK_SKEW` eintrifft.

`HealthOnion` ist ein eigenes geschachteltes Format, nicht
`Onion.enc_payloads` oder `Onion::peel_layer`. Es verwendet die öffentlichen
X25519-Schlüssel der Mixer und den realen Tor-Pfad. Der Swap-Server an
`ordered_hops[0]` erhält keine eigene Health-Schicht. Der erste Mixer verwendet
`hop_position = 1`, jeder weitere Mixer seinen Index in `ordered_hops`.
Jede Schicht reist in:

```text
HealthRequest = (
  version, type=HealthRequest, route_id,
  manifest_sequence, challenge_hash,
  challenge_signature, hop_position, layer,
  sender_identity, sender_signature
)
layer   = (ephemeral_public_key, aead_nonce, ciphertext)
payload = (hop_nonce, next_layer:Option<bytes>)
```

`ephemeral_public_key` ist 32 Byte, `aead_nonce` 12 Byte und `ciphertext` ein
variables Bytefeld. `next_layer = None` bezeichnet `TERMINAL`. Bei `Some`
enthält das Bytefeld die vollständig serialisierte Schicht des nächsten Mixers.
`ciphertext` ist die Ausgabe von ChaCha20-Poly1305 als verschlüsselter
Klartext gefolgt vom 16-Byte-Authentisierungstag. Eine `HealthRequest` bleibt
einschließlich der rekursiv enthaltenen Schichten innerhalb von
`HEALTH_REQUEST_MAX_BYTES` und der gesamten JSON-RPC-Grenze. Größe,
Hop-Position und maximale Routentiefe werden vor X25519 und AEAD geprüft.

`challenge_signature` bleibt unverändert und wird gegen die Swap-Identität
des Manifests geprüft. Sie autorisiert den Digest. Ohne Preimage kann
der Mixer `created_at`, `expires_at` und `nonce` nicht prüfen.
```text
health_request_hash = HASH(
  MwixnetType::HealthRequest,
  payload_without_sender_signature
)
```

`sender_signature` bindet `health_request_hash` und gehört zum autorisierten
Vorgänger.
Andernfalls gilt `unauthorized_predecessor`. Beim Weiterleiten bleiben Route,
Manifest-Sequenz, Challenge-Hash und -Signatur erhalten. Der Mixer setzt
`hop_position + 1`, verwendet `next_layer` und signiert die neue Hülle.

Da der Mixer die Challenge-Frist ohne Preimage nicht prüfen kann, hält er
einen Cache für `health_request_hash` und eine abgeschlossene Antwort. Der
Schlüssel ist
`(route_id, manifest_sequence, challenge_hash)`. Die Aufbewahrung beginnt beim
ersten Empfang und dauert mindestens
`MAX_HEALTH_CERTIFICATE_AGE + MAX_CLOCK_SKEW`.

Eine Wiederholung mit identischem `health_request_hash` liefert dieselbe gespeicherte
Antwort. Fehlt sie nach einem transienten Transportfehler, kann der
Mixer die Verarbeitung wiederholen. Währenddessen läuft pro Cache-Eintrag
höchstens eine Weiterleitung. Eine Anfrage mit demselben `challenge_hash`,
aber abweichendem `health_request_hash` wird mit `health_challenge_replayed`
abgelehnt. Ein Fehler vor dem Empfang einer gültigen Antwort des Nachfolgers
gilt nicht als abgeschlossene Verarbeitung. Eine vollständig aufgebaute
`HealthResponse` wird vor der Rückgabe gespeichert und bleibt auch dann die
Idempotenzantwort, wenn die Verbindung zum Vorgänger anschließend abbricht.

Ein Cache-Miss beweist keine Frische. Vorgängersignatur und lokales Rate-Limit
werden deshalb weiterhin bei jeder Anfrage geprüft.

Die Frischeanforderung gilt je Healthcheck, nicht je Übertragungsversuch. Bei
einem Retry derselben Challenge sendet der Swap-Server die serialisierte
`HealthRequest` byteidentisch erneut und verschlüsselt die Schichten nicht
neu. Eine neue Challenge erfordert dagegen neue `hop_nonce`-Werte,
ephemere Schlüsselpaare und AEAD-Nonces.

Der Swap-Server erzeugt pro Mixer einen frischen 32-Byte-`hop_nonce`, pro
Mixer-Schicht ein frisches ephemeres X25519-Schlüsselpaar und einen frischen
96-Bit-AEAD-Nonce. Ephemere Secret-Keys werden nicht wiederverwendet und nach
dem Schichtaufbau verworfen.

Der 32-Byte-Schichtschlüssel ist:

```text
salt = route_id
info = version || u8(MwixnetType::HealthOnionLayer) ||
       manifest_sequence || challenge_hash || hop_position
PRK = HKDF-SHA-256-Extract(salt, x25519_shared_secret)
layer_key = HKDF-SHA-256-Expand(PRK, info, 32)
```

Ein vollständig aus Nullbytes bestehendes X25519-Shared-Secret ist als
Low-Order-Punkt abzulehnen. Die Schicht verwendet ChaCha20-Poly1305 mit:

```text
AAD = version || u8(MwixnetType::HealthOnionLayer) || route_id ||
      manifest_sequence || challenge_hash || hop_position ||
      ephemeral_public_key
```

Bei Low-Order-Punkt oder ungültigem Tag antwortet der Hop mit
`health_layer_authentication_failed`, erzeugt keine Attestation und bricht ab.
Die Vorgängersignatur bindet zusätzlich Absender, Layer und Ciphertext.

Nach erfolgreicher Entschlüsselung leitet der Mixer `next_layer` weiter. Der
letzte erzeugt bei `TERMINAL` die terminale Attestation. Jeder Vorgänger prüft
und ergänzt:

```text
HealthAttestation = (
  version, type=HealthAttestation, route_id,
  manifest_sequence, challenge_hash, hop_nonce_hash,
  hop_position, participant_identity, observed_at,
  next_attestation_hash:Option<hash>, signature
)

hop_nonce_hash = HASH(
  MwixnetType::HealthHopNonce,
  hop_nonce
)
```

`attestation_hash` ist
`HASH(MwixnetType::HealthAttestation, payload_without_signature)` über diese
Felder. Die Signatur bindet ihn. Der letzte Mixer setzt
`next_attestation_hash = None`. Jeder Vorgänger setzt das Feld auf den Hash der
Attestation seines direkten Nachfolgers.

Die Antwort auf einen Healthcheck ist:

```text
HealthResponse = (
  version, type=HealthResponse, route_id, manifest_sequence,
  challenge_hash, attestations[]
)
```

Der letzte Mixer gibt eine Liste mit seiner Attestation zurück. Jeder
Vorgänger prüft die erhaltene Kette und stellt seine eigene Attestation voran.
Die Liste beim Swap-Server enthält damit genau eine Attestation je Mixer in
aufsteigender `hop_position`. Der Swap-Server prüft Identität, Position,
Signatur, `hop_nonce_hash` und die Verkettung aller Einträge. `observed_at`
liegt unter Berücksichtigung von `MAX_CLOCK_SKEW` im Gültigkeitsfenster der
Challenge. Der Hash der ersten Attestation ist `attestation_root`.

Nach Prüfung der vollständigen Kette erzeugt der Swap-Server:

```text
RouteHealthCertificate = (
  version, type=RouteHealthCertificate, route_id,
  manifest_sequence, challenge_hash, attestation_root,
  verified_at, expires_at, swap_identity, signature
)

health_hash = HASH(
  MwixnetType::RouteHealthCertificate,
  RouteHealthCertificate.payload_without_signature
)
```

Die Swap-Signatur bindet `health_hash`. Der über Tor abrufbare Nachweis ist:

```text
RouteHealthProof = (
  version, type=RouteHealthProof, challenge,
  hop_nonces[32][], response, certificate
)
```

`challenge` ist die vollständige signierte `HealthChallenge`, `response` die
geprüfte `HealthResponse` und `certificate` das
`RouteHealthCertificate`. Die Zahl und Reihenfolge der `hop_nonces` entspricht
den Mixer-Attestations. Damit kann die Wallet jeden `hop_nonce_hash`, die
Attestation-Kette, `attestation_root` und `health_hash` selbst berechnen. Nur
`health_hash` wird über P2P verteilt.

`verified_at` liegt im Gültigkeitsfenster der Challenge.
`certificate.expires_at` liegt nicht nach
`verified_at + MAX_HEALTH_CERTIFICATE_AGE` oder dem Ablauf des Manifests.

Der Nachweis belegt zum Prüfzeitpunkt Entschlüsselung durch alle Mixer,
Hin- und Rückweg sowie konfigurierte Nachbarschaften. Er prüft weder
`Onion.enc_payloads` noch Excess- oder Rangeproof-Verarbeitung und garantiert
keinen späteren Swap. Es gelten `HEALTH_INTERVAL` und
`MAX_HEALTH_CERTIFICATE_AGE`.

Der erste Fehlschlag setzt die Route auf `Degraded`. Der letzte Nachweis
bleibt bis zu seinem Ablauf gültig. Nach `UNAVAILABLE_AFTER_FAILURES`
signiert der Swap-Server `Unavailable` und lehnt neue Anfragen ab. Ein
späterer Erfolg erlaubt eine Ankündigung mit höherer Sequenz.
`RouteRevocation` ist dem dauerhaften Rückzug einer Acceptance vorbehalten.

Pro Route und Manifest-Sequenz läuft höchstens eine aktive Challenge. Ein
Retry derselben Challenge ist kein neuer Healthcheck und erhöht den
Fehlerzähler nicht. Erst der endgültige Ablauf einer Challenge oder ein
nicht transienter Protokollfehler zählt als ein Fehlschlag. Ein vollständiger
Erfolg setzt den Zähler auf null. Antworten zu einer ersetzten Challenge,
einer älteren Manifest-Sequenz oder einer bereits abgeschlossenen Challenge
ändern weder Zustand noch Fehlerzähler.

HealthRequests sind lokal rate-limitiert und können nur von autorisierten
Vorgängern ausgelöst werden.

### Routenankündigung

Nach einem erfolgreichen Healthcheck erzeugt der Swap-Server:

```text
RouteAnnouncement = (
  version, type=RouteAnnouncement, route_id,
  manifest_sequence, entry_onion,
  swap_identity, hop_count, participant_identities[], fee_per_hop,
  manifest_hash, health_hash, status, last_verified,
  valid_until, sequence, signature
)

RouteStatus = (
  version, type=RouteStatus, route_id, manifest_sequence,
  manifest_hash, status, last_verified, valid_until,
  sequence, swap_identity, signature
)

RouteRevocation = (
  version, type=RouteRevocation, route_id, manifest_sequence,
  manifest_hash, participant_identity, revoked_at,
  sequence, signature
)
```

Jede Signatur bindet `HASH` mit dem zugehörigen `MwixnetType` und dem Payload
ohne Signatur.

`RouteAnnouncement` und `RouteStatus` teilen je
`(route_id, manifest_sequence, swap_identity)` einen Sequenzzähler. Er beginnt
bei 1 und steigt bei jeder neuen Meldung. Dadurch kann ein älterer Status
nicht eine neuere Ankündigung überholen. Jede Teilnehmeridentität führt für
`RouteRevocation` je Route und Manifest einen eigenen Zähler, ebenfalls ab 1.
Die Zähler werden vor Veröffentlichung dauerhaft geschrieben. Bei
`u64::MAX` wird für dieses Manifest keine weitere Meldung erzeugt.

`hop_count` entspricht der Zahl der `participant_identities` und der
Hop-Anzahl des referenzierten Manifests. Reihenfolge und Identitäten stimmen
mit `ordered_hops` überein.

`RouteStatus` meldet Zustandsänderungen ohne neuen Health-Nachweis, insbesondere
`Degraded`, `Unavailable`, `Draining` oder `Expired`. Sein `valid_until` ist die
Gültigkeitsgrenze der signierten Meldung und nicht der Zeitpunkt des gemeldeten
Zustandsübergangs; auch ein Status `Expired` besitzt daher während seiner
Relay-Lebensdauer ein `valid_until` in der Zukunft. Nach einem erfolgreichen
Healthcheck wird wegen des neuen `health_hash` stets eine vollständige
`RouteAnnouncement` mit höherer Sequenz gesendet. Ein `RouteStatus` verlängert
die Gültigkeit der zuletzt akzeptierten Ankündigung nicht.

Manifest und Health-Nachweis werden nicht über P2P verbreitet. Die Wallet lädt
sie über Tor vom Swap-Server.

Die Signatur einer `RouteAnnouncement` bestätigt die Entry-Adresse, aber nicht
deren globale Erreichbarkeit. Nodes führen keinen Entry-Preflight im Namen von
Wallets aus. Eine Wallet behandelt `status = Healthy` und einen erfolgreichen
lokalen Entry-Preflight als zwei getrennte Bedingungen.

`RouteAnnouncement.valid_until` liegt nicht nach dem Ablauf des Manifests, des
Health-Zertifikats oder
`last_verified + MAX_ROUTE_ANNOUNCEMENT_VALIDITY`. Die Wallet prüft diese
Beziehungen nach dem Laden der vollständigen Dokumente. Nodes prüfen die aus
der Ankündigung selbst ableitbaren Zeitgrenzen.
Nach Ablauf des referenzierten Health-Zertifikats werden weder Ankündigung noch
Status weitergeleitet; die Wallet leitet den Zustand dann lokal als `Expired`
ab. `RouteStatus` ändert einen Zustand daher nur innerhalb der verbleibenden
Gültigkeit des letzten Health-Nachweises.

Routen in `Unavailable`, `Draining`, `Expired` oder `Revoked` werden nicht als
verwendbar angekündigt. `Degraded` bleibt nur bis zum Ablauf des letzten
erfolgreichen Health-Zertifikats verwendbar.

`RouteAnnouncement`, `RouteStatus` und `RouteRevocation` referenzieren immer
Route-ID, Manifest-Sequenz und Manifest-Hash. Sequenznummern werden pro
Kombination aus Route-ID, Manifest-Sequenz und unterzeichnender Identität
ausgewertet. Innerhalb dieser Kombination ist ein abweichender Manifest-Hash
ungültig. Eine Revocation widerruft genau dieses Manifest. Eine spätere
Manifest-Sequenz enthält neue Acceptances aller Teilnehmer.

Der Swap-Server reicht jede neu erzeugte Ankündigung und jeden Status über
`submit_mwixnet_route` bei seiner konfigurierten Grin-Node ein. Nach einem
Transportfehler wiederholt er dieselbe signierte Meldung. Eine neue Sequenz
wird erst für einen neuen Inhalt vergeben. Ohne erfolgreiche Einreichung
bleibt die Route lokal ausführbar, ist aber nicht über Grin-Discovery
auffindbar.

### Grin-P2P-Relay

Das Relay ist Bestandteil der in diesem RFC beschriebenen Route-Discovery.
Eine Grin-Node, die MWixnet-Routen verteilt oder über ihre Foreign-API
bereitstellt, implementiert die folgenden Nachrichten und die zugehörige
Capability. Nodes ohne MWixnet-Discovery nehmen nicht am Relay teil.

```text
MWIXNET_ROUTE_RELAY = 0x00000100
MWIXNET_OFFER_RELAY = 0x00000200
31 GetMwixnetRoutes
32 MwixnetRoutes
33 MwixnetRouteAnnouncement
34 MwixnetRouteStatus
35 MwixnetRouteRevocation
36 GetMwixnetOffers
37 MwixnetOffers
38 MwixnetOfferAnnouncement
```

Nodes senden Routennachrichten nur an Peers mit `MWIXNET_ROUTE_RELAY` und
Offer-Nachrichten nur an Peers mit `MWIXNET_OFFER_RELAY`. Anfrage und Antwort
sind:

```text
GetMwixnetRoutes = (version, request_id:u64,
                    cursor:Option<route_id>, limit:u16)
MwixnetRoutes = (version, request_id:u64,
                 next_cursor:Option<route_id>, items[])

RouteRelayItem = RouteAnnouncement | RouteStatus | RouteRevocation

GetMwixnetOffers = (version, request_id:u64,
                    cursor:Option<offer_id>, limit:u16)
MwixnetOffers = (version, request_id:u64,
                 next_cursor:Option<offer_id>, items:OfferAnnouncement[])
```

Jedes `RouteRelayItem` beginnt mit den bereits definierten Feldern `version`
und `type`. Andere `MwixnetType`-Werte sind in diesem Batch ungültig. Pro
Route enthält ein Batch die neueste gespeicherte Ankündigung und, sofern
vorhanden, den neuesten Status sowie den neuesten Widerruf jedes Teilnehmers.

Anfragen verwenden eine zufällige ID ungleich null und `limit` zwischen 1 und
`P2P_BATCH_MAX_ROUTES`. Der Peer liefert lexikografisch nach Route-ID die
Routengruppen nach `cursor`. `limit` zählt Route-IDs, nicht einzelne
`RouteRelayItem`-Nachrichten. Alle gespeicherten Items derselben Route werden
gemeinsam geliefert. `next_cursor` ist bei weiterem Bestand die letzte
gelieferte Route-ID, sonst `None`. Eine Antwort trägt exakt die ID ihrer
Anfrage. ID null ist ungültig. Pagination ist wegen gleichzeitiger
Cache-Änderungen Best-Effort und garantiert keine vollständige
Momentaufnahme.

Typnummern, Capability-Bits, Größenprüfung und Behandlung unbekannter
Nachrichten wurden am 30. Juli 2026 gegen
`mimblewimble/grin@857254bb1e98fdb039a4e2579a024835e1bd20cb`
(`staging`) geprüft. Dort ist `HeaderSegment = 30` der höchste belegte Typ und
31 der nächste freie Wert. Die Typen 31 bis 38 und die Capability-Bits
`0x00000100` und `0x00000200` sind durch diesen RFC belegt.
Die Wallet-Annahmen beziehen sich auf
`wiesche89/grin-wallet@fed6733a2209aec2ed963a5691d91c6f00b4261d`.
Vor der Integration werden `MAX_MWIXNET_HOPS` und jede Zuteilung gegen den
tatsächlichen Zielstand neu geprüft und an dieses Protokoll angeglichen.

Nodes prüfen Syntax, Größe, Signatur, Entry-Onion/Swap-Identität, Zeit und
Ablauf, monotone Sequenz sowie lokale Limits. Alle `P2P_*`-Grenzen gelten.

Die Teilnahme am Relay setzt weder einen Tor-Client noch aktive
Routenprüfungen voraus.

Nach Annahme eines neuen `RouteRelayItem` sendet eine Node die zugehörige
Einzelnachricht einmal an jeden verbundenen Peer mit
`MWIXNET_ROUTE_RELAY`, ausgenommen den Absender. Der Schlüssel für die
Duplikaterkennung besteht aus MWixnet-Typ, Route-ID, Manifest-Sequenz,
unterzeichnender Identität und Sequenz. Er bleibt bis zum Ablauf des Items
gespeichert. Dadurch laufen Push-Nachrichten nicht dauerhaft im Kreis.

Nach dem Start und danach alle `ROUTE_RELAY_SYNC_INTERVAL` wählt die Node
mindestens einen verbundenen, fähigen Peer und beginnt einen Pull-Zyklus mit
`cursor = None`. Ist beim Fälligkeitstermin kein solcher Peer verbunden,
beginnt der Zyklus nach der nächsten passenden Verbindung. Die Node folgt
`next_cursor`, bis `None` zurückgegeben wird oder der Peer beziehungsweise
ein lokales Arbeitslimit den Zyklus beendet. Der nächste Zyklus beginnt
wieder bei `None`. Peer-Auswahl und Zahl paralleler Zyklen sind lokale
Implementierungsentscheidungen. Zufälliger Jitter verhindert synchrone
Anfragen vieler Nodes. Push verteilt neue Meldungen zeitnah, Pull repariert
verpasste Meldungen und einen leeren Cache nach einem erstmaligen Start oder
einer ausdrücklichen Cache-Löschung.

Ein Zyklus gilt erst nach dem tatsächlichen Versand seiner ersten Anfrage als
begonnen. Das Fehlen eines passenden Peers und ein lokal fehlgeschlagener
Versand verschieben seine Fälligkeit daher nicht auf das nächste reguläre
Intervall. Route- und Offer-Pull führen getrennte Fälligkeitszustände. Solange
beide Intervalle gleich sind, darf eine Implementierung dafür denselben
Zeitgeber verwenden und beide Pulls gemeinsam auslösen; der Erfolg eines
Pulls darf den weiterhin fälligen anderen Pull nicht zurückstellen.

Nodes stellen je Route-ID nur die höchste akzeptierte Manifest-Sequenz zur
Discovery bereit. Eine Ankündigung mit höherer Manifest-Sequenz ersetzt die
ältere Routengruppe aus Ankündigung, Status und Widerrufen. Hat die Node
Zwischenstände verpasst, ersetzt damit auch jede größere
Manifest-Sequenz den kleineren Cache-Stand. Eine kleinere Sequenz wird
abgelehnt. Ohne vorhandenen Cache-Stand kann jede Sequenz ab 1 angenommen
werden. Innerhalb der aktuellen Manifest-Sequenz speichert die Node die neueste
`RouteAnnouncement`, den neuesten danach empfangenen `RouteStatus` und je
Teilnehmer die neueste `RouteRevocation`. Eine Meldungssequenz, die für
dieselbe unterzeichnende Identität nicht größer als die zuletzt akzeptierte
ist, wird nicht weitergeleitet. Abgelaufenes und Duplikate werden entfernt.
Ein Widerruf bleibt mindestens bis zum `valid_until` der referenzierten
Ankündigung gespeichert, sofern ihn die Cache-Grenze nicht vorher verdrängt.
`MAX_ROUTE_ANNOUNCEMENT_VALIDITY` und die lokalen `NODE_*`-Limits gelten.
Gültige Revocations umgehen das reguläre Update-Limit.

`NODE_NEW_MESSAGE_RATE` zählt alle eingehenden MWixnet-Hüllen einschließlich
`GetMwixnetRoutes`, `NODE_NEW_ROUTE_RATE` erstmals gesehene Route-IDs. Für
die Foreign-API eingereichte Meldungen und Seitenabfragen gelten dieselben
Arbeitsgrenzen je Quelladresse. Das bestehende Foreign-API-Secret ist ein
gemeinsames Secret und identifiziert keinen einzelnen Aufrufer; alle Prozesse
derselben Quelladresse teilen sich daher ein Budget.
Gültige Revocations umgehen weiterhin nur das reguläre Update-Limit, nicht
das eigene Limit je Route und Teilnehmer sowie Größen-, Signatur- oder globale
Arbeitsgrenzen.

Bei `MwixnetRoutes` bindet die Byte-Grenze vor der Eintragsgrenze. Der
serialisierte Nachrichtenbody einschließlich Zähler und Einträge bleibt
innerhalb von `P2P_BATCH_MAX_BYTES`. Ein Batch enthält daher weniger als
`P2P_BATCH_MAX_ROUTES`, sobald der nächste Eintrag die Byte-Grenze
überschreiten würde. Passt die nächste vollständige Routengruppe nicht mehr,
beginnt sie im folgenden Batch.
Die binäre Liste enthält höchstens
`P2P_BATCH_MAX_ROUTES * (MAX_ROUTE_HOPS + 2)` einzelne Relay-Einträge; die
Routen-ID-Grenze bleibt davon unberührt.

Jeder neue Typ erhält einen expliziten `max_msg_size()`-Zweig mit seinem
`P2P_*_MAX_BYTES`. `default_max_msg_size()` kommt dabei nicht zum Einsatz.
Da die Header-Prüfung das Vierfache toleriert, wird die exakte Grenze vor der
Body-Deserialisierung zusätzlich erzwungen.

Ist der Cache voll, entfernt der Node zuerst ungültige und abgelaufene
Routengruppen. Reicht das nicht, behält er aus vorhandenem Cache und neuen
Kandidaten die `NODE_ROUTE_CACHE_LIMIT` größten Tupel
`(revoked, last_verified, route_id)`. Ein noch gültiger Widerruf bleibt damit
vor einer verwendbaren Route erhalten. Innerhalb derselben Klasse wird zuerst
der älteste signierte Health-Zeitpunkt verdrängt. Die Route-ID entscheidet
Gleichstände deterministisch.

Ein Node lehnt eine Revocation ab, wenn der Unterzeichner nicht in
`participant_identities` der zuletzt gültigen, vom Swap-Server signierten
Ankündigung enthalten ist. Die Wallet prüft zusätzlich die zugehörige
Acceptance aus dem vollständigen Manifest.

Eine Node nimmt `OfferAnnouncement` nur von Peers mit
`MWIXNET_OFFER_RELAY` an. `offer_id` ist `offer.hash()`. Der Cache enthält je
Kombination aus Offer-Typ und Identität nur die höchste akzeptierte Sequenz.
Eine identische Wiederholung ist zulässig; dieselbe Sequenz mit anderem Hash
und kleinere Sequenzen werden abgelehnt. Abgelaufene Einträge werden entfernt.
Ist der Cache danach voll, bleiben deterministisch die Offers mit dem spätesten
`valid_until`; `offer_id` entscheidet Gleichstände. Diese Auswahl ist keine
Qualitätsbewertung.

`GetMwixnetOffers` und `MwixnetOffers` verwenden dieselben Regeln für
Request-ID, Best-Effort-Pagination und Byte-vor-Item-Grenze wie das
Routen-Relay. Sortiert wird lexikografisch nach `offer_id`, und `limit` liegt
zwischen 1 und `P2P_OFFER_BATCH_MAX_ITEMS`. Push, Duplikaterkennung und der
periodische Pull-Zyklus entsprechen dem Routen-Relay, verwenden aber die
Offer-Capability, Offer-Grenzen und `OFFER_RELAY_SYNC_INTERVAL`.

Das Offer-Relay ist im Mainnet und Testnet permissionless. Proof-of-Work und
lokale Grenzen schützen Rechenzeit und Speicher, sind aber kein Nachweis für
Vertrauenswürdigkeit, Kapazität oder einen unabhängigen Betreiber.

Im Mainnet nimmt eine Node nur mit einer nichtleeren
`route_relay_allowlist` am Routen-Relay teil. Sie akzeptiert dort nur
eingetragene Swap-Identitäten. Im Testnet kann eine Node ohne Allowlist am
Routen-Relay teilnehmen. Diese Allowlist gilt nicht für Offers; ein gefundenes
Offer umgeht sie nicht, weil eine daraus entstehende Route weiterhin die
normalen Routen-Relay-Regeln erfüllen muss.

### RPC-Schnittstellen

Alle Schnittstellen verwenden JSON-RPC 2.0. Die Grin-Node stellt Discovery
über ihre bestehende Foreign-API unter `/v2/foreign` bereit. MWixnet-Server
verwenden wie bisher `/v1`, erreichbar über ihre jeweilige Onion-Adresse. Die
Wallet erweitert ihre verschlüsselte Owner-API unter `/v3/owner`.
Ein MWixnet-Server lehnt einen empfangenen HTTP-Body oberhalb
`MWIXNET_RPC_MAX_BYTES` vor der JSON-Deserialisierung ab und erzeugt keine
größere Antwort. Für P2P und Health-Hüllen gelten zusätzlich ihre kleineren
spezifischen Grenzen.

IDs, Hashes, Signaturen und öffentliche Schlüssel werden in JSON als
kleingeschriebene Hex-Zeichenketten dargestellt. Pedersen-Commitments folgen
der vorhandenen Grin-Hexdarstellung. Onion-Adressen erscheinen vollständig
mit `.onion`. `u64`-Werte werden wie Beträge in den bestehenden Grin-APIs als
dezimale Zeichenketten ausgegeben. Beim Einlesen werden eine dezimale
Zeichenkette und eine ohne Genauigkeitsverlust darstellbare JSON-Zahl
akzeptiert. Kleinere Integer und boolesche Werte sind JSON-Zahlen
beziehungsweise JSON-Boolesche Werte. Rollen und Zustände verwenden die in
diesem RFC geschriebenen Enum-Namen als Zeichenketten. Diese
JSON-Darstellung wird weder gehasht noch signiert. Dafür gilt ausschließlich
die zuvor definierte Binärdarstellung.

Jeder neue MWixnet-Datensatz enthält in JSON `version: 1` und den Namen seines
`MwixnetType` als `type`-Zeichenkette. Dieses Feld unterscheidet auch die
Varianten von `MwixnetOffer` und `RouteRelayItem`. `Option::None` ist `null`,
`Option::Some` ist der enthaltene Wert und Listen sind JSON-Arrays. Unbekannte
Felder werden beim Einlesen abgelehnt, damit Tippfehler nicht unbemerkt
bleiben. Die Deserialisierung darf Varianten zunächst anhand ihrer Feldform
zuordnen; die anschließende Validierung des `type`-Felds entscheidet endgültig
über die Variante.

Die neu eingeführten Methoden verwenden ein JSON-Objekt mit den genannten
Feldnamen als `params`. Die bestehenden Methoden `swap` und `mix` behalten
ihre bisherige Form mit genau einem positionalen Parameter, also
`params: [SwapReq]` beziehungsweise `params: [MixReq]`. Die verschlüsselte
Wallet-Owner-API verwendet weiterhin benannte Parameter einschließlich
`token`.

#### Grin-Node

Die Foreign-API erhält vier Methoden:

```text
submit_mwixnet_route(item: RouteRelayItem) -> ()

get_mwixnet_routes(
  cursor: Option<route_id>,
  limit: u16
) -> NodeRoutePage

NodeRoutePage = (
  next_cursor: Option<route_id>,
  items: RouteRelayItem[]
)

submit_mwixnet_offer(item: OfferAnnouncement) -> ()

get_mwixnet_offers(
  cursor: Option<offer_id>,
  limit: u16
) -> NodeOfferPage

NodeOfferPage = (
  next_cursor: Option<offer_id>,
  items: OfferAnnouncement[]
)
```

`submit_mwixnet_route` nimmt genau eine signierte `RouteAnnouncement`, einen
`RouteStatus` oder eine `RouteRevocation` entgegen. Das JSON-RPC-Ergebnis ist
bei Annahme `null`. Vor Speicherung und Weiterleitung gelten dieselben
Prüfungen wie für eine über P2P empfangene Routenmeldung.

`get_mwixnet_routes` verwendet dieselbe Sortierung, Gruppierung und
Best-Effort-Pagination wie `GetMwixnetRoutes`. `limit` zählt Route-IDs und
liegt zwischen 1 und `P2P_BATCH_MAX_ROUTES`. Alle zu einer ausgelieferten
Route gehörenden Items werden gemeinsam zurückgegeben.

`submit_mwixnet_offer` prüft Hülle, Proof-of-Work und signiertes Offer wie
eine über P2P empfangene Meldung. `get_mwixnet_offers` verwendet die
Offer-Sortierung und -Grenzen des P2P-Relays. Beide Methoden sind für
MWixnet-Server bestimmt; Wallets benötigen sie nicht.

Die Grin-Owner-API erhält keine MWixnet-Methode. Relay-Capability,
Cache-Grenzen und `route_relay_allowlist` sind Node-Konfiguration. Ein
konfiguriertes Foreign-API-Secret schützt auch diese vier Methoden, ersetzt
aber nicht die Prüfung der Signaturen in den Routenmeldungen.

#### MWixnet-Server

Die öffentliche API des Swap-Servers ist über Tor erreichbar:

```text
swap(request: SwapReq) -> SwapSubmission
get_mwixnet_offer() -> SwapOffer
get_route(route_id) -> RouteManifest
get_route_health(route_id, manifest_sequence) -> RouteHealthProof
cancel_mwixnet_request(request: CancelSwapReq) -> CancelAck

SwapSubmission = (
  route_id, wallet_request_id, swap_req_hash, status,
  kernel_excess: Option<commitment>
)
```

`swap` ist die bereits vorhandene Methode und nimmt weiterhin genau einen
`SwapReq` entgegen. `status` ist nach erfolgreicher erstmaliger Annahme
`Accepted`. Eine Wiederholung mit demselben `swap_req_hash` gibt den bereits
erreichten Zustand `Accepted`, `Batched`, `Posting`, `Posted`, `Confirmed`,
`Rejected`, `Cancelled` oder `Expired` zurück. Die Antwort dient der
Ablaufsteuerung und ist kein kryptografischer Nachweis. Für eine Stornierung
ist nur der signierte `CancelAck` maßgeblich.
`kernel_excess` ist ab `Posting` gesetzt und erlaubt der Wallet die
unabhängige Abfrage bei ihrer Grin-Node. In früheren Zuständen sowie bei
`Rejected`, `Cancelled` und `Expired` ist es `null`.

Ein Server im `legacy`-Betrieb akzeptiert den bisherigen `SwapReq` ohne
Routenfelder und gibt wie bisher die Zeichenkette `"success"` zurück. Ein
routenbasierter `SwapReq` enthält die in diesem RFC definierten Felder und
liefert `SwapSubmission`. An den beiden Request-Formen erkennt der Server
eindeutig, welche Antwortform gilt. Ein Objekt nur mit `onion` und `comsig`
ist `legacy`. Ein Objekt mit `version`, `type`, `wallet_request_id`,
`route_id`, `manifest_sequence`, `expires_at_height`, `onion`, `onion_hash`
und `comsig` ist routenbasiert. Jede unvollständige Mischform wird als
ungültiger Parameter abgelehnt.
Der RPC-Decoder unterscheidet beide Formen vor der Deserialisierung und lässt
die zusätzlichen Routenfelder nicht durch einen permissiven Legacy-Decoder
ignorieren.

`get_mwixnet_offer` gibt das aktuelle signierte `SwapOffer` zurück. Die Wallet
prüft Signatur, Identität und Gültigkeit und entnimmt ihm insbesondere
`max_request_ttl_blocks`. `get_route` gibt das angefragte `RouteManifest`
zurück.
`get_route_health` gibt den neuesten noch gültigen `RouteHealthProof` für
dieselbe Route-ID und Manifest-Sequenz zurück. Beide Methoden verändern
keinen Serverzustand und benötigen keine zusätzliche Signatur.
`cancel_mwixnet_request` prüft die Commitment-Signatur des `CancelSwapReq`
und gibt bei erfolgreicher Stornierung den signierten `CancelAck` zurück.

Die Kommunikation zwischen MWixnet-Servern verwendet ebenfalls `/v1` über
Tor:

```text
mix(request: MixReq) -> MixResp
probe_route(request: HealthRequest) -> HealthResponse
get_mwixnet_offer() -> MixerOffer | SwapOffer
propose_route(proposal: RouteProposal, offers: MwixnetOffer[])
  -> RouteAcceptance
activate_route(manifest: RouteManifest) -> ()
revoke_route(revocation: RouteRevocation) -> ()

MwixnetOffer = MixerOffer | SwapOffer
```

`mix` ist die bereits vorhandene Batch-Methode. `probe_route` transportiert
den zuvor beschriebenen Healthcheck. Bei beiden Methoden stimmen
`sender_identity` beziehungsweise die Signatur des `MixReq` mit dem im
Manifest autorisierten Vorgänger überein.

Jeder MWixnet-Server gibt mit `get_mwixnet_offer` sein zur Rolle passendes,
signiertes Offer zurück. Die Methode dient dem direkten Austausch zwischen
Betreibern und veröffentlicht keine Route über Grin-P2P. Ein Swap-Server ruft
`propose_route` bei jedem vorgesehenen Mixer auf und übergibt den Vorschlag
zusammen mit den dazugehörigen signierten Offers. Die Offer-Liste hat dieselbe
Länge und Reihenfolge wie `ordered_hops`. Typ und Identität jedes Offers
stimmen mit dem zugehörigen Hop überein. Ein Mixer gibt nach erfolgreicher
Prüfung seine `RouteAcceptance` zurück. Der Swap-Server erzeugt seine eigene
Acceptance lokal. Sobald alle Acceptances vorliegen, erzeugt er das
`RouteManifest` und ruft `activate_route` bei jedem Mixer auf. Der Mixer prüft
Proposal-Signatur, alle Acceptances, Manifest-Signatur, seine Position und
seine gespeicherte Proposal-Bindung. Danach speichert er die Route im Zustand
`Proposed`. Eine identische Wiederholung ist erfolgreich. Ein anderer
Manifest-Hash unter derselben Route und Manifest-Sequenz ergibt
`manifest_conflict`.
Eine Wiederholung setzt einen inzwischen erreichten Zustand nicht zurück.
Bei `Draining`, `Expired` oder `Revoked` liefert sie
`route_not_accepting_requests`.

Der Swap-Server installiert sein Manifest lokal und beginnt den ersten
Healthcheck erst, nachdem alle Mixer `activate_route` bestätigt haben. Eine
nur teilweise installierte Route wird nicht angekündigt und nimmt keine
Wallet-Requests an. Verlorene Antworten werden mit demselben Manifest
wiederholt.

`revoke_route` übermittelt einen signierten Widerruf an den Swap-Server. Der
Unterzeichner gehört zu den Teilnehmern des referenzierten Manifests. Eine
erfolgreiche Annahme ergibt `null`.

Offers, Proposals, Acceptances, Widerrufe, Health-Anfragen und Mix-Batches
tragen ihre Authentisierung in der jeweiligen signierten Nachricht. Die
Server prüfen zusätzlich Rolle, Route, Manifest-Sequenz und den erwarteten
Vorgänger. Eine Onion-Verbindung allein gilt nicht als Authentisierung.

#### grin-wallet

Die verschlüsselte Owner-API erhält folgende Methoden:

```text
get_mwixnet_routes(
  token,
  include_unusable: bool
) -> WalletRoute[]

create_mwixnet_route_req(
  token,
  commitment,
  route_id,
  request_ttl_blocks: Option<u16>,
  max_total_fee: Option<u64>
) -> MwixnetRouteReqCreationResult

get_mwixnet_requests(
  token,
  wallet_request_id: Option<wallet_request_id>,
  refresh: bool
) -> WalletMwixnetRequest[]

cancel_mwixnet_request(
  token,
  wallet_request_id
) -> WalletMwixnetRequest
```

```text
WalletRoute = (
  route_id, manifest_sequence, status, usable,
  unusable_reason: Option<string>, hop_count,
  fee_per_hop, total_fee, last_verified, valid_until
)

MwixnetRouteReqCreationResult = (
  request: SwapReq,
  tx_id: u32,
  swap_onion_address
)

WalletMwixnetRequest = (
  wallet_request_id, route_id, tx_id: Option<u32>,
  input_commitment, swap_req_hash,
  status, expires_at_height,
  kernel_excess: Option<commitment>
)
```

In `WalletRoute` sind `manifest_sequence`, `fee_per_hop`, `total_fee`,
`last_verified` und `valid_until` `u64`-Werte und werden nach der allgemeinen
JSON-Regel dieses RFC als Dezimalstrings übertragen.

`get_mwixnet_routes` aktualisiert den Wallet-Cache über die konfigurierte
Grin-Node und liefert die lokale Bewertung der gefundenen Routen. Der
Parameter `include_unusable = false` beschränkt das Ergebnis auf aktuell
verwendbare Routen. Eine neue oder geänderte Ankündigung bleibt lokal
unverwendbar, bis Manifest, Swap-Offer und Health-Nachweis über Tor geladen
und geprüft wurden.

`create_mwixnet_route_req` ergänzt die vorhandene Owner-Methode
`create_mwixnet_req`, deren manuelle Parameter `fee_per_hop` und
`server_keys` während der Einführung unverändert bleiben. Der neue Name
vermeidet eine nicht kompatible Änderung ihrer JSON-RPC-Positionsparameter.

Bei `create_mwixnet_route_req` führt die Wallet zuerst den vollständigen
Preflight aus. `max_total_fee` begrenzt die vom Aufrufer akzeptierte Gebühr.
Bei `None` gilt weiterhin das konfigurierte lokale Wallet-Maximum und nicht
eine unbegrenzte Gebühr.
`request_ttl_blocks = None` verwendet den lokalen Standardwert, begrenzt
durch das `SwapOffer`. Erst danach erzeugt die Wallet den `SwapReq` und sperrt
den Output atomar mit dem lokalen Request-Datensatz. Das Ergebnis enthält
neben `request` und `tx_id` die Onion-Adresse, an die der Client den Request
mit der MWixnet-Methode `swap` sendet. Anders als die bestehende manuelle
Methode besitzt die routebasierte Methode keinen `lock_output`-Schalter und
gibt keinen versandbereiten Request ohne Output-Lock zurück.
Wie beim vorhandenen `MwixnetReqCreationResult` werden die Felder des
eingebetteten `SwapReq` in der JSON-Antwort auf die oberste Objektebene
abgebildet. `tx_id` und `swap_onion_address` stehen daneben.

`get_mwixnet_requests` gibt lokal gespeicherte Wallet-Zustände zurück. Ohne
`wallet_request_id` werden alle noch nicht archivierten Einträge geliefert.
Bei `refresh = true` wiederholt die Wallet für jeden ausgewählten
nichtterminalen Eintrag denselben gespeicherten `SwapReq` und übernimmt den
gemeldeten `SwapSubmission.status`. Dadurch ist der idempotente `swap`-Aufruf
zugleich die Statusabfrage und benötigt keine weitere signierte
Protokollnachricht. Eine nicht erreichbare Route verändert den lokalen
Zustand nicht.

`cancel_mwixnet_request` erstellt den
signierten `CancelSwapReq`, ruft die gleichnamige Methode des Swap-Servers auf,
prüft den `CancelAck` und beginnt anschließend den beschriebenen
Recovery-Ablauf. Die beiden gleichnamigen Methoden liegen damit auf
verschiedenen Endpunkten. Die Owner-Methode steuert den Wallet-Ablauf, die
MWixnet-Methode verarbeitet die signierte Nachricht.

`WalletMwixnetRequest.status` verwendet die Serverzustände `Accepted`,
`Batched`, `Posting`, `Posted`, `Confirmed`, `Rejected`, `Cancelled` und
`Expired`. Während der lokalen Wiederherstellung kommen `ReclaimPending`,
`ConflictObserved`, `ReclaimConfirmed` und `ConflictConfirmed` hinzu. Der
Wallet-Zustand ist eine lokale Anzeige und kein zusätzlicher signierter
Protokolldatensatz. Eine unsignierte Statusantwort kann eine Recovery
anstoßen, beendet sie aber nicht. Maßgeblich ist die bestätigte Chain.

Die grin-wallet-Foreign-API erhält keine MWixnet-Methode. Sie verarbeitet
eingehende Wallet-Protokolle und besitzt weder die Berechtigung zum Sperren
eines Outputs noch zum Auslesen des MWixnet-Caches. Zugriff auf die neuen
Owner-Methoden setzt wie bei den bestehenden Owner-Aufrufen das Wallet-Token,
die verschlüsselte `/v3/owner`-Sitzung und gegebenenfalls das konfigurierte
Owner-API-Secret voraus.

Das Protokoll definiert folgende maschinenlesbare Fehlercodes:

```text
unsupported_mwixnet_version, invalid_mwixnet_message, limit_exceeded,
offer_stale, proposal_conflict, manifest_conflict,
route_unknown, route_unhealthy, route_not_accepting_requests,
manifest_expired,
unauthorized_predecessor, health_challenge_replayed,
health_layer_authentication_failed,
request_expired, request_already_processing,
request_posted, request_rejected, request_conflict,
input_already_registered,
batch_conflict, server_busy
```

Ein protokollspezifischer Fehler hat die Form:

```text
ProtocolRpcError = (code, retryable, message)
```

MWixnet-Server verwenden dafür den JSON-RPC-Serverfehler `-32010` und legen
`ProtocolRpcError` in `error.data` ab. Syntax- oder Typfehler in `params`
verwenden `-32602`, unbekannte Methoden `-32601` und unerwartete interne
Fehler `-32603`.

Die Grin-Node- und grin-wallet-APIs behalten die vorhandene
`result: {"Ok": value}`- beziehungsweise `result: {"Err": error}`-Hülle.
Ihre `Err`-Variante enthält bei einem MWixnet-Protokollfehler denselben
`ProtocolRpcError`. Die Methodensignaturen in diesem RFC zeigen jeweils den
inneren `value`-Typ.

`retryable = true` gilt für `server_busy`, `route_unknown` und
`route_unhealthy`, weil derselbe Inhalt zu einem späteren Zeitpunkt
angenommen werden kann. Bei allen übrigen aufgeführten Codes ist der Wert
`false`. Ein lokaler Transportfehler kann
ebenfalls als wiederholbar behandelt werden, ist aber kein vom Gegenüber
gelieferter `ProtocolRpcError`.

`unsupported_mwixnet_version`, `invalid_mwixnet_message` und
`limit_exceeded` bezeichnen Version, Struktur beziehungsweise Größen- oder
Zählergrenze. `offer_stale` bezeichnet ein abgelaufenes oder zurückgesetztes
Offer. `proposal_conflict` bezeichnet einen anderen Proposal-Hash unter
derselben Route und Manifest-Sequenz. `manifest_conflict` bezeichnet unter
demselben Schlüssel ein anderes endgültiges Manifest. `route_unknown`
bezeichnet einen fehlenden Routeneintrag, `route_unhealthy` einen
vorübergehend nicht ausreichenden Health-Zustand und
`route_not_accepting_requests` die Zustände `Draining`, `Expired` oder
`Revoked`. `manifest_expired` bezeichnet eine abgelaufene oder ersetzte
Manifest-Sequenz.

Die Health- und Request-Codes entsprechen den zuvor beschriebenen
Prüfschritten. `request_conflict` und `batch_conflict` werden ausschließlich
bei gleichem Idempotenzschlüssel und abweichendem Hash verwendet.
`input_already_registered` bezeichnet dasselbe Input-Commitment unter einer
anderen noch gespeicherten Wallet-Request-ID.
`server_busy` wird nur vor einer Nebenwirkung ausgegeben. Nach einer
gespeicherten Nebenwirkung liefert ein Retry den gespeicherten Zustand oder
die gespeicherte Antwort.

Die Wallet kann nach Hop-Anzahl, Gesamtgebühr, Aktualität und lokalen
Vertrauensregeln filtern.

#### Anzeige pro Route

Die Wallet führt für jede bekannte Route einen Cache-Eintrag mit Route-ID,
Zustand, Hop-Anzahl, Gesamtgebühr, `last_verified` und `valid_until`. Die
Anzeige unterscheidet den signierten Zustand der Route vom lokalen
Entry-Preflight:

```bash
grin-wallet --testnet mwixnet routes
```

```text
Route        Route Health  Entry-Preflight   Hops   Gesamtgebühr   Zuletzt geprüft
<route-id>   Healthy       bestanden         3      <fee>          <Zeitpunkt>
<route-id>   Healthy       Tor-Timeout        3      <fee>          <Zeitpunkt>
<route-id>   Unavailable   nicht geprüft      2      <fee>          <Zeitpunkt>
<route-id>   Draining      nicht geprüft      4      <fee>          <Zeitpunkt>
```

`Route Health` stammt aus der neuesten gültigen, signierten Routenmeldung.
`Entry-Preflight` ist das Ergebnis der lokalen Wallet-Prüfung und damit keine
vom Swap-Server behauptete Netzwerkeigenschaft. Dabei zählen Erreichbarkeit,
Ablauf von Ankündigung, Manifest und Health-Nachweis, Gesamtgebühr sowie die
lokale Allowlist. Die Wallet zeigt den Grund an, wenn der Preflight scheitert.
Bei einem terminalen Routenzustand unterbleibt die Tor-Verbindung und die
Anzeige lautet `nicht geprüft`. Ein abgelaufener Cache-Eintrag bleibt als
`Expired` sichtbar, wird aber nicht mehr für neue Anfragen angeboten.

Eine Route verwendet einheitlich `fee_per_hop`:

```text
total_fee = fee_per_hop * hop_count
fee_per_hop >= max(
  swap_offer.minimum_fee,
  mixer_offer[0].minimum_fee,
  ...,
  mixer_offer[n].minimum_fee
)
```

Das Swap-Minimum deckt das Gewicht von Input, Output und Kernel. Das
Mixer-Minimum deckt das jeweilige Kernelgewicht. Jeder Teilnehmer lehnt den
Proposal ab, wenn `fee_per_hop` unter seinem eigenen Minimum liegt.
Die Wallet berechnet `total_fee` mit geprüfter Multiplikation, prüft die
Darstellbarkeit in `FeeFields` und lehnt eine Gebühr ab, die den Output-Wert
erreicht oder überschreitet.

Eine Gebührenänderung erzeugt eine neue Route-ID. Individuelle Hop-Gebühren
sind nicht Teil des Protokolls. `capacity` erscheint weder in
Routenankündigungen noch als Sicherheitsmerkmal.

Vor dem Output-Lock führt die Wallet diese Prüfungen aus:

1. Manifest und aktuelles Swap-Offer über Tor laden,
2. Route-ID, Hop-Reihenfolge, Signaturen und Acceptances prüfen,
3. Swap-Identität, Offer-Gültigkeit und Request-TTL prüfen,
4. Manifest-Hash und Health-Hash mit der Routenankündigung vergleichen,
5. einen frischen Health-Nachweis und seine Attestation-Kette prüfen,
6. die Gesamtgebühr gegen ihr lokales Maximum prüfen.

Das Protokoll trifft keine automatische Auswahl aus nicht vertrauenswürdigen
P2P-Daten. Der Benutzer wählt die Route ausdrücklich oder konfiguriert eine
lokale Standardroute beziehungsweise Allowlist. Die Wallet sperrt den Output
erst nach erfolgreichem Preflight.

### Request-Ablauf, Stornierung und Recovery

```text
SwapReq = (
  version, type=SwapReq, wallet_request_id[32], route_id,
  manifest_sequence, expires_at_height, onion, onion_hash, comsig
)

onion_hash = HASH(MwixnetType::SwapReqOnion, onion)
swap_req_hash = HASH(MwixnetType::SwapReq, payload_without_comsig)
```

Der bestehende `SwapReq` mit `onion` und `comsig` wird um die davor
aufgeführten Felder erweitert. `wallet_request_id` ist zufällig und 32 Byte
lang. `comsig` signiert den 32-Byte-Wert `swap_req_hash`. Der Swap-Server prüft
zusätzlich, dass die empfangene Onion zu `onion_hash` passt, und verarbeitet
`(route_id, wallet_request_id)` idempotent. Eine Wiederholung mit demselben
`swap_req_hash` liefert denselben Zustand. Ein abweichender Hash unter
derselben ID ergibt `request_conflict`. Wallet-ID und Ablaufhöhe bleiben am
Swap-Server und gelangen weder in die Onion noch in `MixReq`. Mixer können
die Ablaufregel daher nicht prüfen.

Der Swap-Server führt diese Idempotenzsuche vor der Prüfung des aktuellen
Routenzustands aus. Ein bereits gespeicherter Request bleibt dadurch auch
nach Manifestablauf, Draining oder Revocation abfragbar. Nur ein bisher
unbekannter Request durchläuft die anschließenden Annahmeprüfungen.

Bei der ersten Annahme stimmen Route-ID und Manifest-Sequenz mit einem lokal
gespeicherten Manifest überein. Die Route ist `Healthy` oder noch
verwendbares `Degraded`, ihr Health-Zertifikat ist nicht abgelaufen und sie
nimmt neue Requests an. Onion-Länge, Commitment-Signatur, Input-UTXO,
`onion_hash`, Gebühr und erste Onion-Schicht werden geprüft, bevor der Zustand
`Accepted` dauerhaft gespeichert wird.

Erhält die Wallet vor dieser Speicherung einen nicht wiederholbaren
Protokollfehler, speichert sie den lokalen Request als `Rejected`; bei
`request_expired` speichert sie `Expired`. Bei einem Timeout, einem
Transportfehler oder einem als wiederholbar markierten Protokollfehler bleibt
der lokale Zustand `Accepted`, bis eine idempotente Statusabfrage einen
eindeutigen Serverzustand liefert.

Der Swap-Server führt zusätzlich einen eindeutigen Index über das
Input-Commitment. Solange ein gespeicherter Request oder Tombstone für diesen
Input aufbewahrt wird, ergibt eine andere `wallet_request_id`
`input_already_registered`. Damit gelangt derselbe Input am selben
Swap-Server nicht in zwei Runden. Verschiedene Swap-Server können dies nicht
koordinieren. Dort entscheidet wie bei jedem Double-Spend die Chain.

Der Swap-Server lehnt erstmalige Verarbeitung ab `expires_at_height` ab.
Seine lokale Einstellung `max_request_ttl_blocks` liegt zwischen
`MIN_REQUEST_TTL_BLOCKS` und `MAX_REQUEST_TTL_BLOCKS`. Die Wallet verwendet
`WALLET_REQUEST_TTL_BLOCKS`, solange der Server keinen kleineren Wert
veröffentlicht. Bei Wallet-Chain-Tip `H` wählt sie eine TTL innerhalb dieser
Grenzen und setzt `expires_at_height = H + ttl_blocks` mit geprüfter Addition.
Der Swap-Server nimmt einen neuen Request nur an, wenn sein eigener aktueller
Chain-Tip kleiner als `expires_at_height` ist. Eine abweichende Tip-Höhe
innerhalb dieser Frist ändert die signierte Ablaufhöhe nicht.

Der Swap-Server speichert den Request-Zustand persistent:

```text
Accepted -> Batched -> Posting -> Posted <-> Confirmed
    |
    +-> Cancelled
    +-> Expired

Batched -> Rejected
```

`Accepted` bezeichnet einen gespeicherten, aber noch keiner Runde zugeordneten
Request. Bei `Batched` sind `batch_id`, Batchposition und `mix_req_hash`
dauerhaft festgelegt. Ein transienter Fehler wiederholt genau diesen Batch
bis `expires_at_height`. Drainende Mixer behalten dafür die Konfiguration.
Ein Batch enthält nur Requests derselben Route und Manifest-Sequenz, deren
Ablaufhöhe beim Übergang noch nicht erreicht ist. Der Swap-Server wählt
höchstens `MAX_MIX_BATCH_SIZE` Einträge und verändert ihre Reihenfolge nach
der dauerhaften Zuweisung nicht mehr.

Eine vollständige `MixResp` teilt den Batch. Enthaltene Indizes werden in die
zu bauende Transaktion übernommen. Nicht enthaltene Indizes wechseln zu
`Rejected` und werden nicht in einer späteren Runde erneut verwendet. Bei
einer leeren Indexliste werden alle Requests abgelehnt und keine Transaktion
gebaut. Erreicht ein noch nicht vollständig beantworteter Batch seine
Ablaufhöhe, wechselt er ebenfalls zu `Rejected` und wird nicht erneut
weitergeleitet.

Vor dem ersten Veröffentlichungsversuch speichert der Swap-Server die
vollständig gebaute Transaktion und setzt alle enthaltenen Requests atomar
auf `Posting`. Nach einem Timeout wird genau diese Transaktion erneut
veröffentlicht und nicht aus den Batchdaten neu gebaut. Eine Annahme durch die
Node oder das Auffinden der Transaktion im Txpool beziehungsweise auf der
Chain setzt `Posted`. Eine ausreichende Chain-Bestätigung setzt `Confirmed`.
Nach einem Reorg fällt `Confirmed` auf `Posted` zurück und dieselbe
Transaktion wird erneut veröffentlicht.

```text
CancelSwapReq = (
  version, type=CancelSwapReq, route_id, manifest_sequence,
  wallet_request_id[32], swap_req_hash, input_commitment,
  created_at, comsig
)
CancelAck = (
  version, type=CancelAck, route_id, manifest_sequence,
  wallet_request_id, cancel_swap_req_hash, input_commitment,
  status=Cancelled, tombstone_created_at,
  swap_identity, swap_signature
)

cancel_swap_req_hash = HASH(
  MwixnetType::CancelSwapReq,
  CancelSwapReq.payload_without_comsig
)
```

`comsig` signiert `cancel_swap_req_hash`. Der Swap-Server prüft Route,
Manifest-Sequenz, `swap_req_hash`, Commitment und `MAX_CLOCK_SKEW`.
Die Swap-Signatur bindet die Ack-Felder mit
`HASH(MwixnetType::CancelAck, payload_without_signature)`.
`Cancelled` wird im Ack als `0:u8` codiert. Stornierung ist nur in `Accepted`
erlaubt und erzeugt einen persistenten Tombstone. Eine identische
Wiederholung gibt denselben gespeicherten `CancelAck` zurück. `Batched` oder
`Posting` liefern `request_already_processing`, `Posted` oder `Confirmed`
liefern `request_posted`, `Rejected` liefert `request_rejected` und `Expired`
liefert `request_expired`. Route und Manifest-Sequenz verhindern Replay in
späteren Manifestgenerationen.

Der Tombstone bleibt mindestens bis `expires_at_height` erhalten. Die Wallet
speichert den empfangenen `CancelAck` selbst, da der Swap-Server das Ende
ihrer Recovery nicht zuverlässig beobachten kann. Nach der Ablaufhöhe kann
der Server Tombstone und Request gemäß den späteren Persistenzregeln
archivieren. Eine erneute Einreichung bleibt wegen der bereits erreichten
Ablaufhöhe ungültig.

`expires_at_height` ist Server-Policy und keine Grin-Kernel-Eigenschaft. Ein
bereits erzeugter oder veröffentlichter Kernel bleibt nach dieser Höhe
gültig.
Weder Ablaufhöhe noch signierte Stornierungsbestätigung beweisen daher
kryptografisch, dass ein bösartiger oder fehlerhafter Swap-Server die
Transaktion nicht mehr veröffentlicht.

Die Wallet entsperrt einen stornierten, abgelaufenen oder abgelehnten Input
deshalb nicht einfach. Nach einem letzten Chain- und Txpool-Abgleich erzeugt
sie einen Reclaim-Self-Spend auf einen neuen eigenen Wallet-Output. Sie
speichert die vollständige Reclaim-Transaktion vor dem ersten Sendeversuch
und hält den Request in `ReclaimPending`, bis Reclaim, MWixnet-Transaktion
oder ein anderer Spend die lokale Bestätigungstiefe erreicht.
Die Wallet speichert ihre konfigurierte `mwixnet_confirmation_depth` beim
Erstellen im Request-Datensatz und verwendet denselben Wert für Input,
MWixnet-Transaktion, Reclaim und konkurrierende Spends.

Beim Wallet-Start und bei jedem neuen Chain-Tip prüft die Wallet alle nicht
archivierten Requests. Ab `expires_at_height` beginnt sie für jeden noch
nicht auf der Chain aufgelösten Request den Reclaim-Ablauf, auch wenn der
Swap-Server nicht erreichbar ist oder zuletzt `Batched`, `Posting` oder
`Posted` gemeldet hat. Reclaim und MWixnet-Transaktion konkurrieren dann um
denselben Input. Keine bloße Servermeldung entscheidet diesen Konflikt.

Grins Txpool akzeptiert keine zwei Spends desselben Inputs und bietet kein
RBF. Eine Konfliktablehnung setzt `ConflictObserved`, ist aber nicht terminal.
Die Wallet hält gesperrt und sendet dieselbe gespeicherte Reclaim-Transaktion
nach Chain-Tips, Reconnects oder Pooländerungen erneut. Sie baut nur dann eine
neue Reclaim-Transaktion, wenn die gespeicherte Transaktion nach einer
Chain-Änderung endgültig ungültig ist und der Input weiterhin unspent ist.

Für den Reclaim empfiehlt sich, begrenzt durch die Wallet-Maximalgebühr, eine
Fee-Rate deutlich über dem lokalen Minimum. Die unbekannte Fee-Rate der
aggregierten Runde kann nicht verglichen werden. Grin bietet hier kein RBF.
Eine höhere Gebühr senkt lediglich das Verdrängungsrisiko. Ohne Bestätigung
ist der Input weder zurückgewonnen noch geswappt.

Ein noch nicht gebatchter Request bleibt nach beobachtetem Ablauf dauerhaft
`Expired`. Bereits veröffentlichte oder bestätigte MWixnet-Transaktionen
können nach einem Reorg auch jenseits der Ablaufhöhe erneut veröffentlicht
werden.

Bestätigt sich der eigene Reclaim, setzt die Wallet `ReclaimConfirmed` und
führt den neuen Output wie bei einem normalen Self-Spend. Bestätigt sich die
MWixnet-Transaktion, setzt sie `Confirmed`. Ein anderer bestätigter Spend
setzt `ConflictConfirmed`. Erst einer dieser drei Zustände beendet die
Recovery und erlaubt die Archivierung. Fällt die auslösende Bestätigung durch
einen Reorg unter die lokale Bestätigungstiefe, kehrt die Wallet zu
`ReclaimPending` beziehungsweise `ConflictObserved` zurück. Der ursprüngliche
Output wird nie lediglich durch Entfernen eines Wallet-Locks freigegeben.

Bei einem fehlgeschlagenen Cancel-Aufruf bleibt der lokale Zustand
unverändert. `request_already_processing` übernimmt `Batched`,
`request_posted` übernimmt `Posted`, `request_rejected` beginnt
`ReclaimPending` und `request_expired` beginnt nach dem Chain-Abgleich
ebenfalls `ReclaimPending`. Nach einem verlorenen Cancel-Response wiederholt
die Wallet denselben `CancelSwapReq` und erhält den gespeicherten `CancelAck`.
Transportfehler lösen für sich keinen Reclaim aus.

### Route-Lebenszyklus

Die Zustandsübergänge sind:

| Ausgangszustand | Ereignis | Neuer Zustand |
| --- | --- | --- |
| `Proposed` | erster vollständiger Healthcheck erfolgreich | `Healthy` |
| `Proposed` | Healthcheck fehlgeschlagen | `Degraded` |
| `Healthy` | Healthcheck fehlgeschlagen | `Degraded` |
| `Degraded` | weiterer Fehlschlag unterhalb der Fehlergrenze | `Degraded` |
| `Degraded` | vollständiger Healthcheck erfolgreich | `Healthy` |
| `Degraded` | dritter aufeinanderfolgender Fehlschlag | `Unavailable` |
| `Unavailable` | vollständiger Healthcheck erfolgreich | `Healthy` |
| `Unavailable` | Healthcheck fehlgeschlagen | `Unavailable` |
| `Healthy`, `Degraded` oder `Unavailable` | geplante Außerbetriebnahme | `Draining` |
| `Healthy`, `Degraded` oder `Unavailable` | Manifest abgelaufen, Anfragen offen | `Draining` |
| `Proposed`, `Healthy`, `Degraded` oder `Unavailable` | Manifest abgelaufen, keine Anfrage offen | `Expired` |
| `Draining` | laufende Anfragen abgeschlossen oder abgelaufen | `Expired` |
| jeder nichtterminale Zustand | gültige `RouteRevocation` | `Revoked` |

Diese Zustandsmaschine bewertet die Server-zu-Server-Route. Ein erfolgreicher
Wallet-Entry-Preflight ist eine zusätzliche lokale Voraussetzung für eine neue
Anfrage und erzeugt keinen Routenzustandsübergang.

Ein Healthcheck darf sein Ergebnis nur speichern, wenn der nach Abschluss des
Checks erneut gelesene Zustand weiterhin `Proposed`, `Healthy`, `Degraded`
oder `Unavailable` ist. Er darf `Draining`, `Expired` oder `Revoked` weder bei
Erfolg noch bei Fehlschlag überschreiben. Eine geplante Außerbetriebnahme aus
`Unavailable` ist wie in der Tabelle ein wirksamer Übergang nach `Draining`
und kein stiller No-op.

Jeder Teilnehmer kann seine Acceptance für zukünftige Runden mit einem
signierten `RouteRevocation` widerrufen. Geplantes `Draining` verhindert neue
Anfragen, erlaubt aber, bereits als `Accepted` gespeicherte Anfragen zu batchen
und abzuschließen. Nach einer Revocation gilt dagegen die strengere folgende
Regel.

Der Teilnehmer sendet die Revocation an den Swap-Server und kann sie
zusätzlich unmittelbar mit `submit_mwixnet_route` an seine Grin-Node geben.
Ist der Swap-Server nicht erreichbar, genügt die direkte Einreichung bei
einer Node für die P2P-Verbreitung. Der Swap-Server synchronisiert seinerseits
Routenmeldungen über seine konfigurierte Node und übernimmt eine gültige
Revocation. Bis dahin bleibt die signierte Revocation auch ohne ergänzenden
`RouteStatus` für Nodes und Wallets maßgeblich.

Jede Teilnehmerimplementierung stellt dafür einen durch den Betreiber
auslösbaren Erzeugungspfad bereit. Ob dieser als CLI, administrative API oder
Teil eines geordneten Herunterfahrens angeboten wird, ist lokale
Implementierungspolitik. Vor der ersten Übertragung erhöht und speichert der
Teilnehmer seinen eigenen Revocation-Sequenzzähler, erzeugt die Signatur und
verwendet bei Wiederholungen byteidentisch dieselbe Revocation. Ein reiner
Empfangs- und Relay-Pfad erfüllt diese Anforderung nicht.

Nach einer Revocation nimmt kein Teilnehmer neue `SwapReq`- oder noch nicht
begonnene Batcharbeit für das referenzierte Manifest an. Bereits als
`Batched` oder `Posting` gespeicherte Arbeit wird mit der dauerhaft
gespeicherten Routenkonfiguration abgeschlossen. Noch in `Accepted`
befindliche Requests werden nicht mehr gebatcht und können storniert werden
oder ablaufen.

Beim Wechsel zu `Draining` wird die größte akzeptierte Ablaufhöhe als
`drain_until_height` gespeichert. Routenkonfiguration und Idempotenzdaten
bleiben erhalten, bis kein Request des Manifests mehr in `Accepted`,
`Batched` oder `Posting` steht. Für bereits veröffentlichte Transaktionen
bleiben Transaktion und Reorg-Daten bis zur terminalen Bestätigung erhalten.
Eine Revocation hebt diese Pflichten nicht auf.

### Persistenz und Nebenläufigkeit

Eine erfolgreiche RPC-Antwort wird erst gesendet, nachdem der Zustand, auf
den sie sich bezieht, dauerhaft geschrieben wurde. Zusammengehörige
Datensätze und ihr Zustandsübergang werden atomar gespeichert. Nach einem
Neustart wird die Verarbeitung aus dem letzten vollständig geschriebenen
Zustand fortgesetzt.

Jeder MWixnet-Server speichert dauerhaft:

- sein Server-Secret sowie die zuletzt verwendeten Offer- und
  Meldungssequenzen,
- Proposal-Hash und eigene Acceptance je offener
  `(route_id, manifest_sequence)`-Kombination,
- vollständige Manifeste, Routenzustand, Nachbarn, Fehlerzähler und
  `drain_until_height`,
- Swap-Requests, Cancel-Tombstones, gebaute Transaktionen und deren Zustand,
- vollständigen `MixReq`, `mix_req_hash`, `InFlight`-Markierung und
  abgeschlossene `MixResp` je Batch,
- vollständige `HealthRequest`, ihren Digest und eine abgeschlossene
  `HealthResponse` für die bereits festgelegte Replay-Frist.

Eine beim Start gefundene `InFlight`-Markierung ohne abgeschlossene Antwort
wird wiederholbar. Bei einem Batch wird derselbe gespeicherte `MixReq`
weiterverwendet, bei einem Healthcheck dieselbe byteidentische
`HealthRequest`. `Completed`, `Cancelled`, `Rejected`, `Posting` und
`Posted` werden niemals auf einen Zustand vor ihrer dauerhaft gespeicherten
Nebenwirkung zurückgesetzt.

Proposal- und Acceptance-Daten bleiben mindestens bis zum Ablauf des
zugehörigen Manifests erhalten. Routenkonfiguration und Batchantworten bleiben
darüber hinaus erhalten, solange ein Request oder Nachbar sie für Retry,
Draining oder Reorg-Behandlung referenziert. Ein Swap-Request und sein
Tombstone bleiben mindestens bis `expires_at_height` erhalten. Daten zu einer
gebauten oder veröffentlichten Transaktion bleiben bis zu ihrer terminalen
Bestätigung zuzüglich des lokal verwendeten Reorg-Horizonts erhalten. Danach
können sie archiviert werden. Eine Löschung ändert keinen noch nicht
terminalen Zustand.

Die Grin-Node speichert ihren Route-Cache, die jeweils höchsten akzeptierten
Sequenzen und die Duplikatschlüssel dauerhaft. Diese Metadaten unterliegen
derselben `NODE_ROUTE_CACHE_LIMIT` wie die Routengruppen und werden erst mit
dem zugehörigen abgelaufenen oder verdrängten Eintrag entfernt. Ein normaler
Neustart setzt Sequenzprüfung und Relay daher ohne Rollback fort. Nach einem
erstmaligen Start oder einem ausdrücklich gelöschten Cache wird der zuvor
beschriebene Pull-Zyklus ausgeführt.

Die Wallet schreibt Route, Manifest-Sequenz, vollständigen `SwapReq`,
`swap_req_hash`, Commitment, Ablaufhöhe, Transaktionslog-ID und lokalen
Request-Zustand atomar mit dem Output-Lock. Vor dem ersten Reclaim-Versuch
speichert sie zusätzlich die vollständige Reclaim-Transaktion. Ein Neustart
setzt Preflight oder Request-Erzeugung nicht stillschweigend fort, sondern
nimmt nur bereits vollständig gespeicherte Requests und Recovery-Vorgänge
wieder auf.

Pro Route läuft am Swap-Server höchstens eine Manifestbildung für die nächste
Sequenz. Pro `(route_id, manifest_sequence)` läuft höchstens ein Healthcheck.
Pro `(route_id, wallet_request_id)` läuft höchstens ein
Request-Zustandsübergang. Pro `(route_id, batch_id)` läuft an jedem Hop
höchstens eine Batchverarbeitung. Diese Sperren gelten nur lokal. Die
dauerhaften Idempotenzschlüssel entscheiden nach einem Neustart, nicht die
Lebensdauer einer Prozesssperre.

Das konkrete Datenbankformat, Tabellenpräfixe und die Wahl zwischen LMDB und
einem anderen transaktionalen Speicher sind nicht Teil des Protokolls.

### Aufteilung auf die drei Projekte und Rust-Crates

Die Grin-Node implementiert Capability, P2P-Nachrichten, Discovery-Cache und
die beiden Foreign-API-Methoden. Sie benötigt die Binärtypen
`RouteAnnouncement`, `RouteStatus`, `RouteRevocation` und deren eingebettete
Grundtypen. Sie lädt weder Manifeste noch Health-Nachweise und führt keine
Tor-Verbindung aus.

MWixnet implementiert Offers, Proposal und Acceptance, Manifest- und
Routenspeicher, Healthcheck, routebasierte `SwapReq`- und `MixReq`-Abläufe,
Stornierung, Serverzustände sowie die Clients für Grin-Node und
Nachbarserver. Nur der Swap-Server veröffentlicht Ankündigungen und
Transaktionen. Jeder Mixer prüft und speichert ausschließlich die für seine
Routen und Idempotenzpflichten benötigten Daten.

grin-wallet implementiert Discovery- und Tor-Clients, Manifest- und
Health-Prüfung, Route-Cache, Preflight, routebasierte Request-Erzeugung,
Owner-API, Statusanzeige und Recovery. Die Foreign-API und eingehende
Slate-Protokolle bleiben davon getrennt.

Das vorhandene MWixnet-Repository enthält bereits die Rust-Crate `mwixnet`.
Sie ist Bibliothek und ausführbares Programm, bindet aber neben Grin auch
mehrere grin-wallet-Crates ein. Grin oder grin-wallet können diese Crate daher
nicht als gemeinsame Protokollbibliothek verwenden. Eine umgekehrte
Abhängigkeit würde die Projekte zyklisch koppeln und außerdem Tor-, Server-
und Datenbankcode in die Grin-Node ziehen.

Das MWixnet-Repository wird deshalb als Cargo-Workspace mit zwei Paketen
organisiert:

```text
mwixnet/
├── protocol/          Paket mwixnet-protocol, Crate mwixnet_protocol
├── src/               Serverbibliothek und Programm mwixnet
└── Cargo.toml         Workspace- und Serverpaket
```

`mwixnet-protocol` enthält ausschließlich gemeinsam benötigten
Protokollcode:

- Offers, Proposals, Acceptances und Manifeste,
- Routenankündigungen, Statusmeldungen und Widerrufe,
- Health-Nachrichten und Attestations,
- Protokollkonstanten und Fehlercodes,
- kanonische Binärserialisierung,
- Hash- und Signaturbildung,
- zustandslose Prüfung einzelner Datensätze.

Die Crate öffnet keine Netzwerkverbindungen, greift nicht auf eine Datenbank
zu und enthält weder Wallet- noch Serverzustände. Sie darf `grin_core` für
vorhandene Grin-Typen, `Writeable` und die Grin-Hashfunktion verwenden. Sie
hängt nicht von `grin_p2p`, `grin_api`, grin-wallet oder der Server-Crate
`mwixnet` ab.

Die bestehenden Typen `Onion`, `ComSignature`, `Hop` und `SwapReq` sowie die
Onion-Erzeugung verbleiben zunächst in `grin_wallet_libwallet::mwixnet`.
Ihre Verschiebung ist für Route Discovery nicht erforderlich. Die im RFC
beschriebenen Erweiterungen dieser Typen werden dort implementiert. Die
Server-Crate `mwixnet` verwendet deshalb sowohl `mwixnet_protocol` als auch
`grin_wallet_libwallet`.

Die Abhängigkeiten verlaufen damit nur in eine Richtung:

```text
grin_core
    ↓
mwixnet_protocol
    ├──→ grin_p2p und grin_api
    ├──→ grin_wallet_libwallet und grin_wallet_api
    └──→ mwixnet

grin_wallet_libwallet ──→ mwixnet
```

Die Pfeile zeigen jeweils von einer Abhängigkeit zu ihrem Benutzer. Grin
erhält keine Abhängigkeit auf grin-wallet oder die MWixnet-Server-Crate.
grin-wallet erhält keine Abhängigkeit auf Tor-, Mixer- oder Swap-Servercode.

In Grin verwenden P2P und Foreign API die Discovery-Datensätze aus
`mwixnet_protocol`. In grin-wallet verwenden Libwallet und Owner API dieselben
Datensätze für Auswahl, Prüfung und Anzeige. Der MWixnet-Server verwendet sie
für Routenbildung, Healthchecks und seine RPC-Schnittstellen. Dadurch werden
Wire-Typen, Hashbildung und Signaturprüfung nicht in drei Repositories
unabhängig nachgebaut.

Alle drei Repositories binden dieselbe veröffentlichte Version oder denselben
festgelegten Commit von `mwixnet-protocol` ein. Eine Änderung der kanonischen
Serialisierung erfordert eine Änderung der MWixnet-Protokollversion und der
Konformitätsvektoren. Interne Servermodule, Datenbanktabellen und
Benutzeroberflächen können unabhängig davon geändert werden.

### Konformitätsvektoren

Zum Implementierungspaket gehört eine maschinenlesbare Vektordatei mit
vollständigen Eingabefeldern, erwarteten Binärbytes, Hashes und Signaturen.
Sie umfasst mindestens:

- beide Offer-Typen, Proposal, Acceptance, Route-ID und Manifest,
- `OfferAnnouncement`, gültigen Proof-of-Work sowie `GetMwixnetOffers` und
  `MwixnetOffers`,
- alle drei P2P-Routenmeldungen sowie `GetMwixnetRoutes` und
  `MwixnetRoutes`,
- `onion_hash`, `swap_req_hash`, `cancel_swap_req_hash` und `CancelAck`,
- `mix_req_hash`, Indexabbildung und eine leere `MixResp`,
- X25519-Shared-Secret, HKDF-Zwischenwerte, AAD, Ciphertext und Tag jeder
  Health-Schicht,
- Health-Request-Hash, Attestation-Kette, Zertifikat und vollständigen
  `RouteHealthProof`.

Negative Vektoren decken falsche Version und Typkennung, abgeschnittene
Listen, Grenzwertüberschreitungen, Low-Order-X25519, ungültigen AEAD-Tag,
abweichenden Idempotenzhash, falsche Sequenz und Signatur sowie vertauschte
Hop-Positionen ab. MWixnet, Grin und grin-wallet verwenden dieselben
Vektordaten in ihren Tests. Eine Integration gilt erst als vollständig, wenn
alle drei Projekte die für sie relevanten Vektoren unabhängig bestehen.

### Rückwärtskompatibilität und Einführung

Die Einführung erfolgt in Phasen:

1. **MWixnet-intern:** Routentabelle, Route-ID, Manifest, Acceptances,
   Healthcheck sowie konfigurierbare `fee_base` und daraus abgeleitete
   `minimum_fee`.
2. **Wallet:** Manifestprüfung, Preflight, Route-Cache und `--route`.
3. **Grin-Node:** ausgehandelte P2P-Capability und Foreign-API für
   Route-Discovery.
4. **Offer-Discovery:** Veröffentlichung signierter Offers, Proof-of-Work,
   Offer-Cache und optionale Mixer-Auswahl durch Swap-Server.
5. **Testnet-Aktivierung:** gemeinsame Konformitätsvektoren, kontrollierte
   Routenbildung und Messung von Health-, Relay- und Retry-Verhalten.

Die manuellen Parameter bleiben während der Einführung erhalten. Alte
Grin-Nodes erhalten ohne Capability keine MWixnet-P2P-Nachrichten.
Empfängt ein alter Node dennoch einen unbekannten Typ, behandelt der
Staging-Decoder ihn als `MsgHeaderWrapper::Unknown`, konsumiert den begrenzten
Body und bannt den Peer nicht allein deshalb.

Eine Konfiguration nur mit `prev_server` und `next_server` kann als `legacy`
weiterlaufen. Über `MWIXNET_ROUTE_RELAY` wird sie nicht angekündigt.
Es gibt keine automatische Migration.

### Sicherheitsgrenzen

Signaturen verhindern Manipulation, aber weder Sybil-Angriffe noch
Betreiber-Kollusion. Die Vertraulichkeit der Zuordnung setzt mindestens einen
ehrlichen und unabhängigen Mixnode voraus. Öffentliche Manifeste legen die
Routentopologie offen. Ein Health-Nachweis belegt nur vergangene
Erreichbarkeit.

`batch_id` macht dieselbe Runde an mehreren Hops erkennbar, identifiziert aber
keine einzelne Onion. Die Anonymitätsmenge ist der Batch. Kleine
Batches verringern sie entsprechend.

Eine Stornierungsbestätigung ist nur eine signierte Zusage des Swap-Servers,
kein kryptografischer Ausschluss einer späteren Veröffentlichung. Nur ein
bestätigter konkurrierender Spend macht eine bereits signierte
MWixnet-Transaktion ungültig. Reorganisationen können beide Transaktionen
erneut in Konkurrenz bringen. Da ein einzelner Grin-Txpool konkurrierende
Spends nicht gleichzeitig hält, garantiert auch das Absenden eines Reclaims
keine aktive Verdrängung. Die Wallet beobachtet und wiederholt bis zu einer
Auflösung auf der Chain weiter.

## Drawbacks
[drawbacks]: #drawbacks

- Der Entwurf erweitert Grin-P2P und Foreign-API um nicht konsensrelevanten
  Zustand. Nodes speichern und begrenzen ihn und schützen ihn gegen Spam.
- Öffentliche Manifeste legen Routen und gemeinsam verwendete Mixer offen.
- Mehrere Routen erhöhen Implementierungs- und Nebenläufigkeitskomplexität.
- Ein häufig eingesetzter Mixer kann mehrere Routen gleichzeitig ausfallen
  lassen. Healthchecks erkennen den Ausfall nur nachträglich und erzeugen
  selbst Tor-Verkehr.
- Acceptances, Widerrufe, Draining und Recovery erhöhen den betrieblichen
  Aufwand, ohne Sybil-Angriffe oder Betreiber-Kollusion zu lösen.

## Rationale and alternatives
[rationale-and-alternatives]: #rationale-and-alternatives

### Warum feste, veröffentlichte Routen?

Feste Routen erhalten das Nachbarschaftsmodell von MWixnet. Die Route-ID macht
Änderungen an Hop-Liste, Schlüsseln oder Gebühren sichtbar.

### Warum eine einheitliche Gebühr?

Eine einheitliche `fee_per_hop` hält Manifest, Wallet-Berechnung und
Routenvergleich einfach. Sie deckt das höchste Teilnehmerminimum ab.
Ändert sich ein Minimum, etwa durch einen neuen `accept_fee_base`, entsteht
wegen der Gebührenbindung in der Route-ID eine neue Route mit neuen
Acceptances. Die Gebührenänderung ist dadurch sichtbar. Der Preis dafür ist
eine zusätzliche Routenrotation. Eine lange Manifestgültigkeit hilft in
diesem Fall nicht.

### Warum Grin-P2P nur für Discovery?

P2P verteilt nur signierte, kurzlebige Metadaten. Manifest, Health-Nachweis und
MWixnet-Verkehr bleiben auf Tor. Grin-Nodes benötigen keinen Tor-Client.

### Alternativen

Ohne diesen RFC bleibt MWixnet auf manuell koordinierte Einzelrouten
beschränkt. Das wäre die kleinste Änderung, ließe aber Discovery, Widerruf
und eine überprüfbare Routengesundheit ungelöst. Eine zentrale Liste würde
Discovery vereinfachen, schüfe jedoch einen zensierbaren
Kompromittierungspunkt. Lokale Allowlists sind deshalb nur als
Bootstrap-Policy vorgesehen.

Frei pro Swap gebaute Routen wurden verworfen, weil sie dynamische
Nachbarschaftsautorisierung benötigen und damit das bestehende
MWixnet-Sicherheitsmodell ändern. Auch aktive Onion-Prüfungen durch
Grin-Nodes sind nicht vorgesehen. Jeder teilnehmende Node müsste Tor betreiben,
und derselbe Prüfverkehr würde unnötig vervielfacht.

## Prior art
[prior-art]: #prior-art

John Tromps Mimblewimble-CoinSwap-Vorschlag beschreibt eine geordnete Menge
bekannter Mixnodes. Die Wallet verschlüsselt die Daten für alle Nodes als
Onion-Bundle und sendet dieses nur an den ersten Node. Dieser RFC ändert nicht
das CoinSwap-Verfahren, sondern ergänzt die betriebliche Bildung,
Veröffentlichung und Prüfung solcher festen Knotensätze.

Bitcoin-CoinJoin-Systeme verwenden andere Koordinationsmodelle:

- WabiSabi verwendet einen Koordinator, bei dem mehrere Wallets gemeinsam
  eine CoinJoin-Transaktion bilden.
- JoinMarket verwendet einen Markt aus Maker-Angeboten, aus denen ein Taker
  Gegenparteien auswählt.

Diese Systeme zeigen, dass Dienst-Discovery, kurzlebige Angebote,
Teilnehmerauswahl und DoS-Schutz eigenständige Protokollprobleme sind. Ihre
Transaktionsmodelle lassen sich jedoch nicht direkt auf MWixnet übertragen.

Tor-v3-Onion-Adressen liefern einen selbstauthentifizierenden
Transport-Endpunkt. Sie beweisen die Identität des Onion-Service-Schlüssels,
aber nicht die Ehrlichkeit oder Unabhängigkeit des Betreibers.

## Resolved constraints and validation
[resolved-constraints-and-validation]: #resolved-constraints-and-validation

`fee_per_hop` bleibt Bestandteil der Route-ID. Eine Gebührenänderung erzeugt
damit bewusst eine neue Route und neue Acceptances. Ohne diese Bindung könnte
dieselbe Route-ID zu unterschiedlichen Wallet-Kosten angeboten werden.

Die maximale Manifestgültigkeit von 30 Tagen sowie fünf Minuten
Health-Intervall und 15 Minuten Zertifikatsalter gelten für die beschriebene
Implementierung. Für diese Werte liegen noch keine Testnet-Messreihen vor.
Messungen können später eine Änderung begründen, erzeugen aber keine
unterschiedliche Auslegung der hier festgelegten Werte.

Zwei weitere Grenzen sind beabsichtigt:

1. Permissionless Mainnet-Relay gilt nur für Offers und verwendet den hier
   festgelegten Proof-of-Work. Für fertige Wallet-Routen gilt im Mainnet
   weiterhin die lokale `route_relay_allowlist`.
2. Der RFC behauptet keine Betreiber-Unabhängigkeit. Unterschiedliche
   Ed25519-Schlüssel beweisen nicht, dass unterschiedliche Personen oder
   Organisationen dahinterstehen. Die Hop-Anzahl gilt deshalb nicht als
   garantierte Anzahl unabhängiger Betreiber.

Konkrete Datenbankschemata, Rust-Module und Bedienoberflächen werden während
der Implementierung gewählt. Die zuvor festgelegten Persistenzinvarianten,
Grenzen und Konformitätsvektoren bleiben davon unberührt.

Außerhalb dieses RFCs bleiben:

- permissionless Mainnet-Relay für fertige Wallet-Routen,
- automatische Erkennung oder Attestierung unabhängiger Betreiber,
- freie, pro Swap zusammengestellte Routen,
- Ersetzung von Tor und Veröffentlichung detaillierter Erfolgsstatistiken.

## Future possibilities
[future-possibilities]: #future-possibilities

Später kann der bereits definierte Ablauf aus neuer Manifest-Sequenz und
Draining automatisch vor dem Gültigkeitsende ausgelöst werden. Wallets
könnten außerdem mehrere parallele Routen anhand lokaler Vertrauensregeln
verwenden und für wiederholte Self-Spends wechseln.

Eine spätere Änderung der Offer-Schwierigkeit oder ein stärkerer Sybil-Schutz
durch Bonds oder Reputation benötigt eine neue Protokollversion.
Datenschutzfreundliche Uptime-Nachweise, Betreiber-Attestierungen und externe
Route-Verzeichnisse sind mögliche Ergänzungen, aber keine Voraussetzung für
den hier beschriebenen Ablauf.

## References
[references]: #references

- [Grin-RFC-Vorlage](https://github.com/mimblewimble/grin-rfcs/blob/master/0000-template.md)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 8439: ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [John Tromp: Mimblewimble CoinSwap proposal](https://forum.grin.mw/t/mimblewimble-coinswap-proposal/8322)
- [MWixnet-Implementierung](https://github.com/mimblewimble/mwixnet)
- [Grin-Referenzstand `857254b`](https://github.com/mimblewimble/grin/commit/857254bb1e98fdb039a4e2579a024835e1bd20cb)
- [grin-wallet-Referenzstand `fed6733`](https://github.com/wiesche89/grin-wallet/commit/fed6733a2209aec2ed963a5691d91c6f00b4261d)
- [Wasabi: WabiSabi CoinJoin](https://docs.wasabiwallet.io/using-wasabi/CoinJoin.html)
- [JoinMarket-Dokumentation](https://github.com/JoinMarket-Org/joinmarket-clientserver)
