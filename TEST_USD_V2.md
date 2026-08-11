# Test USD v2 deployment contract

Date: 2026-08-11

Test USD v2 is a clean, valueless Signal demo deployment on Bitcoin Signet.
It replaces the application state called Test USD v1; it does not replace or
fork Signet, and it does not change OpenCSV's protocol wire format.

## Exact reset boundary

| Surface | Test USD v2 value |
| --- | --- |
| Account config generation | `2` |
| Deployment id | `opencsv-test-usd-v2` |
| Secure Backup checkpoint | `4` |
| HKDF and account branches | version 2 domains |
| Bitcoin fee wallet | fresh BIP84 Signet tree |
| OpenCSV owner and issuer-tool identities | fresh version 2 branches |
| Instrument | new exact Test USD v2 manifest and asset id |
| Database and backup namespace | fresh; no v1 import |
| Bitcoin network | existing public Signet, unchanged |
| Wire unit code | `USD`, unchanged |

The app must treat Test USD v1 databases and checkpoints as archived. Opening
them through the generation-2 account boundary returns
`testnet_reset_required`. It must never reinterpret v1 bytes as v2, silently
normalize non-canonical field encodings, or show an old asset as current USD.

## Why the clean boundary exists

Historical coin randomness was generated as unrestricted 32-byte data. The
current proof serialization requires each of the eight BabyBear limbs to be
the unique canonical integer below `2,013,265,921`. Reinterpreting arbitrary
legacy bytes by modular reduction would create two encodings for one field
element and make identities depend on which layer performed the decoding.
Global permissive decoding would retain that ambiguity forever.

V2 instead makes canonical encoding a launch invariant. Every new opening
uses rejection sampling for eight uniform canonical field limbs (not biased
`u32 % p` reduction), and non-canonical input is rejected before it can become
wallet state. The Lean model states the uniqueness theorem separately
from the asset state-machine theorems so the public audit distinguishes
mathematical conservation from byte-level representation.

## Product policy

Signal exposes one reviewed Test USD product and cannot mint. Exact issuer
manifests are compiled/configured as an allowlist. Unknown or removed assets
remain visible and inspectable but fail spending as `asset_not_reviewed`.
Privileged issuance remains in the feature-gated headless `opencsv-issuer`
tool. Test USD v2 has no monetary value and no redemption promise.

## Evidence policy

All August 2026 Bob/Carol transaction ids, screenshots, and video produced by
Test USD v1 remain published only as **archived v1 evidence**. They are not
evidence that v2 has passed live acceptance. V2 publication requires a fresh
Bob/Carol run with exact source commit, asset id, transaction ids, observer
receipts, proof timings, CI links, and screenshots/video captured from the
real run. No fabricated or relabeled state is acceptable.

## Remaining launch gates

- hosted Rust CI at the exact reviewed canonical-encoding/reset tip;
- a formal build and public axiom audit including canonical BabyBear encoding;
- a Signal build pinned to the merged Rust revision and fresh v2 namespaces;
- fresh Signet sats and headless Test USD v2 issuance for Bob and Carol;
- send, zero-confirmation forward, two-recipient batch, RBF, crash recovery,
  and confirmed settlement receipts;
- new screenshots and real simulator video before v2 replaces the archived
  v1 film on the homepage.
