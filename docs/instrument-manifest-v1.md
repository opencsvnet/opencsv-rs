# OpenCSV instrument manifest v1

Status: implementation draft. This document freezes the product and trust
boundary before the Signal USD wallet is enabled.

## Scope

OpenCSV v1 can represent issuer-backed claims, but Signal is an owner wallet,
not an issuer console. It exposes one **USD** product backed by zero or more
reviewed issuer-specific instruments. An OpenCSV test issuer may supply the
temporary signet/regtest instrument; Tether or another issuer may later supply
a separate instrument under independently authenticated terms and keys.

The protocol identifier remains:

`asset_id = H("OpenCSV-asset" || issuer_pk || unit_code || terms_hash || nonce)`

`unit_code` is display metadata. Exact identity is always `asset_id`. Signal
may total reviewed six-decimal USD instruments for presentation, but it must
retain the issuer breakdown and must never treat matching unit codes as proof
of equal backing or redemption rights.

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
- `reviewed`: the app configuration pinned the exact manifest and asset id.
- `verified`: an optional external issuer-attestation layer accepted by the
  account. This is never inferred from a valid proof.
- `deprecated` or `revoked`: locally or externally flagged; existing evidence
  remains readable while new writes are blocked by policy.

An unknown incoming instrument is quarantined until the recipient reviews its
issuer, terms, redemption statement, network, and exact asset id.

## Issuer lifecycle

Definition and issuance occur outside Signal:

1. A privileged issuer tool creates and validates an instrument definition.
2. Review the derived issuer fingerprint, terms hash, and asset id.
3. Publish the exact public manifest through the reviewed wallet policy.
4. Keep the issuer key outside Signal and its Secure Backup.
5. Issue units from the separate issuer workflow against the exact asset id.

Signal's production FFI exposes no definition, issuer-key, or mint-preparation
call. It accepts public reviewed manifests in `usd_issuers`, validates their
network/genesis/terms binding and unique asset ids, and returns each as a
`trusted_usd_v1` tranche with deterministic priority.

Normal sends select one issuer tranche that can cover the amount and disclose
that issuer at review. V1 must reject rather than silently split across issuer
claims; a grouped multi-instrument payment needs an explicit protocol and
receipt boundary.

## Future Tether boundary

The OpenCSV test issuer is not Tether, USDT, a promise of redemption, or a
claim of affiliation. A future Tether-issued OpenCSV instrument has its own
authenticated issuer identity, terms, and asset id. Signal may present both
under USD while preserving their separate source and receipt lineage; it must
never silently convert one issuer claim into another.

## Migration

Assets without a valid v1 manifest are prototype assets. They remain
recoverable and auditable but are labelled unverified, never represented as a
real currency solely from their old three-letter code, and cannot receive new
issuance through the Signal account API.
