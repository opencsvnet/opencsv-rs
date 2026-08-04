# OpenCSV instrument manifest v1

Status: implementation draft. This document freezes the product and trust
boundary before the Signal USD preview UI is enabled.

## Scope

OpenCSV v1 can represent issuer-backed, redeemable claims, but the preview
Signal wallet does not expose a generic instrument creator. It originates one
fixed signet/regtest definition: **OpenCSV USD Preview** (`USD`, 6 decimals),
issued by the OpenCSV preview issuer. These preview units have no monetary
value and are not redeemable for dollars or USDT.

The protocol identifier remains:

`asset_id = H("OpenCSV-asset" || issuer_pk || unit_code || terms_hash || nonce)`

`unit_code` is display metadata. Exact identity is always `asset_id`. Wallets
must never merge instruments merely because their unit codes match.

## Terms committed by genesis

`InstrumentTermsV1` contains:

- `version = 1`
- Bitcoin network (`mainnet`, `signet`, or `regtest`)
- human display name
- three-letter uppercase ASCII unit code
- base-unit decimal precision
- human issuer name
- HTTPS terms-document URI
- short redemption summary
- `test_only`

The terms are encoded by the field order above with length-prefixed UTF-8
strings and hashed under the `OpenCSV-instrument-terms-v1` Poseidon2 domain.
That digest is the genesis `terms_hash`. Material term changes therefore
produce a different `asset_id`; they cannot silently mutate an existing
instrument.

The genesis issuer key is a Poseidon2 commitment to the issuer seed. A valid
mint PCD proves knowledge of that seed and binds the exact genesis, including
the terms hash. There is deliberately no second reusable off-circuit issuer
signature that could disagree with the AIR-native authorization.

## Trust states

Protocol validity and issuer trust are separate:

- `prototype`: legacy zero-terms asset; retained without upgrade or implied
  backing.
- `unknown`: proof-valid instrument not reviewed by this account.
- `reviewed`: the account pinned the exact manifest and asset id.
- `verified`: an optional external issuer-attestation layer accepted by the
  account. This is never inferred from a valid proof.
- `deprecated` or `revoked`: locally or externally flagged; existing evidence
  remains readable while new writes are blocked by policy.

An unknown incoming instrument is quarantined until the recipient reviews its
issuer, terms, redemption statement, network, and exact asset id.

## Preview issuer lifecycle

Definition and issuance remain distinct protocol actions even though Signal
presents one guided “Issue USD” flow:

1. Create and validate an instrument definition.
2. Review the derived issuer fingerprint, terms hash, and asset id.
3. Persist the definition and refresh Signal Secure Backup.
4. Activate issuer writes only after the backup acknowledges the new state.
5. Issue units against the exact existing asset id.

The issuance call accepts no unit code, terms, Bitcoin key, Bitcoin input,
change address, or coin-selection result. Rust owns issuer authorization,
fee-input reservation, change, transaction construction, and the durable
operation journal.

The production FFI accepts no arbitrary instrument definition. It exposes an
idempotent `opencsv_preview_usd_ensure(handle)` action whose terms are compiled
into Rust and which is rejected on mainnet.

## Future Tether boundary

The preview definition is not Tether, USDT, a promise of redemption, or a
claim of affiliation. A future Tether-issued OpenCSV instrument must have a
separately authenticated issuer identity, terms, asset id, and version. The
wallet must never silently relabel or convert preview balances. Any migration
or redemption requires an explicit, auditable issuer-authorized operation.

## Migration

Assets without a valid v1 manifest are prototype assets. They remain
recoverable and auditable but are labelled unverified, never represented as a
real currency solely from their old three-letter code, and cannot receive new
issuance through the Signal account API.
