# OpenCSV batching v2 protocol and threat model (C0)

Status: **frozen and implemented by C1**

Protocol version: `2`

Date: 2026-08-02

This document is the normative C0 specification for co-funded OpenCSV batch
anchors. The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are requirements on conforming implementations.

The existing Rust batching implementation is batching v1. It is useful
prototype evidence, but its coordinator-funded, anyone-can-spend funding stock
is not the v2 protocol. V1 remains readable during migration; new batch
creation MUST use v2 after C1 lands.

C1 implementation map: `opencsv-core::batch` owns versioned envelope and
occurrence semantics; `opencsv-bitcoin::batch_v2` owns canonical transcripts,
transaction construction, PSBT material, signatures, fees, and replacement;
`opencsv-cbf` scans and persists both fail-closed witness versions. The real
`batch_v2_e2e` regtest uses separate stock and participant keys, rejects a
mutated output, replaces the signed transaction unanimously, mines it, and
recovers both payload occurrences over BIP158/P2P scanning.

## 1. Goals and non-goals

Batching v2 has five goals:

1. Put multiple context-bound OpenCSV payloads in one Bitcoin transaction.
2. Split the marker and miner fee among the participants without trusting a
   coordinator with their bitcoin.
3. Preserve the existing OpenCSV context rule: input 0's outpoint is fixed
   before proof generation and is the transaction context for every payload.
4. Make the transaction and every charge deterministic before any participant
   signs.
5. Fail safely under coordinator failure, participant failure, replay, output
   mutation, crashes, and replacement attempts.

V2 does not provide coordinator liveness, guaranteed confirmation, amount or
graph privacy, arbitrary input types, silent membership changes, or unilateral
fee replacement. It does not introduce an OpenCSV server. A coordinator is an
ephemeral assembler; any participant can perform that role and any peer can
combine signatures or broadcast.

## 2. Roles and trust boundary

- The **stock owner** controls input 0, a count-specific P2WSH funding stock.
  Input 0 fixes the OpenCSV context. The stock principal is returned unchanged.
- Each of `N` **participants** contributes exactly one OpenCSV payload, one
  native-segwit P2WPKH fee input, and one fresh P2WPKH change script.
- The **coordinator** collects commitments, constructs the canonical manifest,
  and relays it. The coordinator MAY be the stock owner and MAY be one of the
  participants, but those are separate roles. If it participates, it still
  contributes a separate fee input.
- **Peers** relay proposals, commitments, manifests, signatures, and the fully
  signed transaction. Transport authentication limits spam and impersonation;
  Bitcoin signatures enforce custody and transaction integrity.

The coordinator is untrusted. It can delay, censor, equivocate, or abort. It
MUST NOT receive private keys, raw nullifiers, unsigned proofs, or authority to
select participant inputs or change addresses. Every signer independently
reconstructs and validates the complete transaction.

C1 deliberately has a one-to-one participant/payload shape. An operation that
needs multiple independent envelope payloads MUST use a solo anchor until a
later, explicitly versioned batching amendment defines its fee and ordering
semantics.

## 3. Protocol constants

| Name | Value | Meaning |
|---|---:|---|
| `VERSION` | `2` | Batching protocol version |
| `MIN_PARTICIPANTS` | `1` | Smallest valid v2 batch |
| `MAX_PARTICIPANTS` | `64` | Consensus-independent protocol/DoS cap |
| `ENVELOPE_MAGIC` | ASCII `OCS2` | First input-0 witness item |
| `TX_VERSION` | `2` | Bitcoin transaction version |
| `SEQUENCE` | `0xfffffffd` | Opt-in replacement, no relative lock |
| `LOCK_TIME` | `0` | Initial C1 lock time |
| `SIGHASH` | `SIGHASH_ALL` (`0x01`) | Required for every input |
| `MARKER_VALUE` | `546` sats | OpenCSV marker value |
| `MARKER_SCRIPT` | `OP_0 PUSH32(SHA256(OP_RETURN))` | BIP158-visible, unspendable marker scriptPubKey |
| `MIN_CHANGE` | `546` sats | Conservative v2 change floor |
| `MIN_STOCK_VALUE` | `546` sats | Conservative reusable-stock floor |

The participant cap is intentionally below Bitcoin Core's current standard
P2WSH limits. At `N = 64`, input 0 has 66 witness stack items excluding the
witness script; the standard-policy limit is 100. Its witness script is 101
bytes and has 66 counted non-push opcodes, below the 3,600-byte and 201-opcode
limits. These are relay-policy checks, not new consensus rules.

References: [Bitcoin Core P2WSH policy limits][core-policy],
[Bitcoin Core script limits][core-script], [BIP 143 signature hashing][bip143],
[BIP 174 PSBT][bip174], [BIP 125 replacement][bip125].

## 4. Canonical primitives

### 4.1 Integer and byte encoding

Canonical OpenCSV transcript messages use:

- unsigned integers in little-endian form;
- booleans as one byte, `0x00` or `0x01` only;
- Bitcoin outpoints as the 32 txid bytes in Bitcoin transaction serialization
  order followed by `vout:u32_le`;
- scripts as `length:u16_le || bytes`, with the shortest valid Bitcoin push
  encodings inside each script;
- arrays as `count:u16_le || elements`, except where an enclosing fixed field
  is explicitly the array count; the manifest's `participant_count:u8` counts
  both its commitment and charge arrays;
- no maps, floating-point values, locale-dependent strings, JSON, or
  serializer-dependent enum encodings in a hashed transcript.

Each wire message is:

```text
magic       8 bytes  ASCII "OCSVB2\0\0"
kind        u8
body_length u32_le
body        body_length bytes
```

Message kinds are fixed: proposal `0x01`, participant commitment `0x02`,
manifest `0x03`, and signature share `0x04`. No other kind is valid in C1.

Unknown kinds, trailing bytes, non-canonical scripts, incorrect lengths, and
integer overflow MUST be rejected. `body_length` is bounded by the receiving
implementation before allocation. Hashes below are ordinary SHA-256 over the
literal ASCII domain (including its terminating zero byte) followed by the
canonical body:

```text
batch_id      = SHA256("OpenCSV/batch-v2/proposal\0"   || proposal_body)
commitment_id = SHA256("OpenCSV/batch-v2/commitment\0" || commitment_body)
manifest_id   = SHA256("OpenCSV/batch-v2/manifest\0"   || manifest_body)
```

The `chain_id` field is the 32-byte genesis block hash in Bitcoin transaction
serialization order. It makes cross-network replay invalid without relying on
human-readable network names.

### 4.2 OpenCSV context and batch commitment

The context is unchanged from solo anchors and batching v1:

```text
ctx = SHA256(input_0.txid_wire || input_0.vout_u32_le)
P_i = H("bind" || raw_nullifier_or_commitment_i || ctx)
```

Only the 24-byte anchor prefix of `P_i` is put in the envelope. Raw nullifiers
never appear on chain or in coordinator messages.

V2 uses a distinct field-hash domain:

```text
batch_commit_v2 = H("batch-v2" || P_0 || ... || P_(N-1) || ctx)
```

Here `H` is the existing OpenCSV `hash_felts` construction: concatenate the
24-byte payload encodings, convert that byte string and the 32-byte context to
field elements with `bytes_to_felts`, and hash the two segments under the
literal domain `batch-v2`. Golden vectors fix this encoding in C1.

The 24-byte anchor prefix of that digest is placed in the existing 64-byte
batch-header record:

```text
[0x05][N:u8][batch_commit_v2:24][zero padding:38]
```

The `OCS2` witness magic selects v2 validation and the `batch-v2` hash domain.
The v1 magic `OCSV` continues to select v1 validation and its `batch` domain.
A decoder MUST NOT silently try one domain after the selected version fails.

## 5. Funding stock and input-0 witness

V1's anyone-can-spend stock is forbidden for v2 creation. For a compressed
secp256k1 stock-owner public key `K` and participant count `N`, the v2 witness
script is:

```text
PUSH33(K) OP_CHECKSIGVERIFY OP_DROP repeated (N + 1) times OP_TRUE
```

Its scriptPubKey is native P2WSH:

```text
OP_0 PUSH32(SHA256(witness_script))
```

The complete input-0 witness stack is, from first serialized item to last:

```text
OCS2, P_0, P_1, ..., P_(N-1), stock_signature_01, witness_script
```

`stock_signature_01` is a strict-DER, low-S ECDSA signature with the trailing
`SIGHASH_ALL` byte. `OP_CHECKSIGVERIFY` consumes the signature and embedded
public key. The `N + 1` drops consume the payloads and magic, and `OP_TRUE`
leaves exactly one true value for CLEANSTACK.

The funding outpoint MUST already exist before a proposal is made. Its value,
script, public key, and participant count MUST match the proposal and available
chain data. Output 2 returns exactly the same value and script, so the funding
stock neither subsidizes the batch nor leaks principal. It can be reused only
for a later batch with the same owner key and participant count. Its value MUST
be at least `MIN_STOCK_VALUE`, and C1 requires it to be confirmed before use.

The header commits to the envelope and every `SIGHASH_ALL` signature commits to
the header output. Although witness arguments are not directly part of the
BIP 143 signature digest, substituting an envelope requires finding a collision
in `batch_commit_v2`; a mismatch MUST be rejected by OpenCSV validation.

## 6. Participant commitment

Exactly one commitment is accepted per participant operation and per fee
outpoint. The canonical proposal body is:

```text
version                 u16 = 2
chain_id                [u8; 32]
stock_outpoint          [u8; 36]
stock_value             u64 sats
stock_owner_pubkey      [u8; 33], compressed and valid
participant_count       u8, 1..=64
proposal_nonce          [u8; 32], random
observed_tip_height     u32
expiry_height           u32, greater than observed_tip_height
target_feerate_sat_vb   u32, nonzero
max_feerate_sat_vb      u32, >= target
```

The stock script is derived from the key and count; it is not caller-selected.
Local policy MUST bound the expiry window and both feerates before accepting a
proposal.

The canonical participant commitment body is:

```text
batch_id          [u8; 32]
operation_id      [u8; 32], stable local OpenCSV operation identifier
commit_nonce      [u8; 32], random
payload           [u8; 24], already bound to the proposal's ctx
fee_outpoint      [u8; 36]
fee_value         u64 sats
fee_pubkey        [u8; 33], compressed and valid
fee_prevout_spk   script<22>, canonical P2WPKH for fee_pubkey
change_spk        script<22>, canonical P2WPKH
max_charge        u64 sats
```

The fee input and change script are selected and reserved by the participant's
wallet, never by Swift, a coordinator, or another peer. The participant MUST
verify the fee prevout independently from chain data, reject an unconfirmed or
already reserved input under C1 policy, and persist the reservation before
sending the commitment. Duplicate outpoints, operation IDs, commitment IDs,
payloads, or change scripts MUST be rejected within one manifest.

A transport-level authenticated signature SHOULD cover each proposal and
commitment, but it is not part of Bitcoin consensus and MUST NOT be confused
with input ownership. Fee-input ownership is proven only by the round-two
Bitcoin signature.

## 7. Canonical ordering and transaction

The coordinator selects exactly `N` valid commitments for one `batch_id` and
sorts them lexicographically by the 36 serialized bytes of `fee_outpoint`.
This order is the participant order for every later structure.

The unsigned Bitcoin transaction is uniquely determined:

```text
version: 2
lock_time: 0

inputs:
  0       stock_outpoint, sequence 0xfffffffd
  1..=N   participant fee outpoints in canonical participant order,
          each sequence 0xfffffffd

outputs:
  0       value 0, OP_RETURN <64-byte v2 batch-header record>
  1       value 546, the constant unspendable OpenCSV marker scriptPubKey
  2       stock_value, the exact input-0 P2WSH scriptPubKey
  3..N+2  participant P2WPKH change outputs in participant order
```

The payload envelope and change outputs use the same participant order. There
are no extra inputs or outputs, no merged or omitted change, and no coordinator
output. Input 0 and protocol outputs intentionally override general-purpose
lexicographic transaction ordering; the remaining outpoints use the same
determinism principle as [BIP 69][bip69].

Pre-readiness prototypes used `OP_0 PUSH32(SHA256(OP_TRUE))` at output 1.
That output was anyone-can-spend: a signet observer immediately attached a
child transaction and pinned ordinary BIP125 replacement. New manifests use
the unspendable `OP_RETURN` witness-script hash above. Readers and canonical
manifest validation recognize the exact historical script for old receipts,
but builders never create it and historical manifests cannot enter a new
replacement epoch. There is no heuristic script fallback.

Before signing, every participant MUST verify:

- the proposal, all commitments, hashes, count, network, expiry, and ordering;
- the input-0 outpoint, value, derived P2WSH script, and context;
- every participant prevout's existence, value, P2WPKH script, and lack of a
  known conflicting spend;
- every bound payload, header byte, envelope item, output value, and script;
- the exact fee calculation below and its own `max_charge`;
- transaction standardness and the pessimistic signed weight;
- `SIGHASH_ALL` with neither `ANYONECANPAY`, `NONE`, nor `SINGLE`.

A failure rejects the manifest before releasing a signature.

## 8. Fees and change

C1 supports only the fixed input/output shapes above so every participant has
the same marginal transaction shape. The maximum signed weight for `N` is:

```text
max_weight(N) = 968 + 423*N weight units
max_vbytes(N) = ceil(max_weight(N) / 4)
miner_fee     = target_feerate_sat_vb * max_vbytes(N)
total_charge  = 546 + miner_fee
```

The bound assumes a 73-byte ECDSA signature for input 0 and for each P2WPKH
input. It includes the marker/flag, input-0 envelope and script, one 24-byte
payload per participant, all base input/output bytes, the 64-byte header, the
marker, stock return, and all P2WPKH changes. C1 MUST implement an independent
serialization-based weight check and golden vectors; the formula is not a
license to skip measuring the constructed transaction.

Charges use integer quotient/remainder allocation in canonical participant
order:

```text
base      = total_charge / N
remainder = total_charge % N
charge_i  = base + (i < remainder ? 1 : 0)
change_i  = fee_value_i - charge_i
```

Thus the first `remainder` participants pay one additional satoshi. Each
`charge_i` MUST be at most that commitment's `max_charge`, and each `change_i`
MUST be at least `MIN_CHANGE`. Checked arithmetic is mandatory. A low-S DER
signature shorter than 73 bytes merely raises the realized feerate slightly;
outputs are never mutated or refunded after signing.

The transaction conservation invariant is:

```text
sum(inputs) - sum(outputs) = miner_fee
stock_output_value         = stock_input_value
sum(participant charges)   = marker_value + miner_fee
```

New fee-input or change-output types require a new protocol version or an
explicitly frozen weight/allocation amendment. C1 MUST NOT estimate arbitrary
scripts under the v2 identifier.

## 9. Two-round flow

PSBT v0 is the C1 multi-signer transport. A PSBT's map order is not the
OpenCSV transcript: `manifest_id` commits to the canonical OpenCSV structures
and the exact unsigned Bitcoin transaction. Proprietary PSBT fields MAY carry
the IDs and envelope, but losing them MUST NOT change the transaction or hash.

### Round 0: proposal

The stock owner or coordinator publishes the proposal and `batch_id`. Each
participant validates the stock and chain/fee bounds before generating or
reusing a proof bound to `ctx`.

### Round 1: commitments and manifest

Participants reserve their fee inputs and gossip authenticated commitments.
The coordinator selects exactly `N`, sorts them, calculates charges, constructs
the header, exact unsigned transaction, and manifest body:

```text
batch_id             [u8; 32]
replacement_epoch    u32, initially 0
participant_count    u8
commitment_ids       N * [u8; 32], ordered
max_weight           u32
feerate_sat_vb       u32
miner_fee             u64
total_charge          u64
charges               N * u64, ordered
unsigned_tx_length    u32
unsigned_tx           canonical witness-free Bitcoin transaction bytes
```

The manifest, proposal, and complete commitment bodies are gossiped to every
participant. A hash without the source bodies is insufficient for validation.

### Round 2: signatures and broadcast

Every participant reconstructs the manifest and validates section 7. It signs
only its fee input using native-segwit P2WPKH `SIGHASH_ALL`. The stock owner
independently performs the same validation and signs input 0 against the exact
P2WSH script and value. A signature relay message identifies `manifest_id`,
input index, signer public key, and the DER signature plus sighash byte.

Signatures are gossiped to all participants, not returned only to the
coordinator. Any peer can verify, combine, persist, and broadcast the fully
signed transaction. A wallet MUST persist the final transaction and its
`manifest_id` before its first broadcast attempt. Re-broadcasting the same
transaction is idempotent.

The canonical signature-share body is:

```text
manifest_id       [u8; 32]
input_index       u16, 0 for stock or 1..=N for participants
signer_pubkey     [u8; 33], compressed and valid
signature_length u16, at most 73
signature_01      strict-DER low-S ECDSA plus SIGHASH_ALL byte
```

The share is accepted only if the public key and input index match the
proposal/ordered commitment and the Bitcoin signature verifies against the
manifest transaction and independently verified prevout.

The protocol state machine is:

```text
proposed -> committed -> manifest_ready -> signed_persisted
          -> broadcast -> mempool -> confirmed
          -> payload_delivered
```

Terminal side states are `aborted_before_signature`, `invalidated_on_chain`,
and `expired_unsigned`. Every transition and rejection reason is journaled so
a crash resumes from persisted state rather than rebuilding by guesswork.

## 10. Abort, retry, and replacement

Before a participant releases a round-two signature, expiry or membership
failure permits a clean abort: its fee reservation is released and a new
proposal nonce creates a new `batch_id`. If input 0 remains unspent, proofs and
payloads MAY be reused because `ctx` is unchanged, but commitments and manifest
signatures MUST be regenerated for the new batch ID.

After any round-two signature is released, timeout alone is not a safe unlock:
the signature may still be held by another peer. The signer MUST keep its input
reserved until one of these conditions holds:

1. the batch or a conforming replacement confirms;
2. another transaction spending a required input confirms, making the batch
   permanently invalid; or
3. the signer deliberately creates and confirms a conflicting self-spend to
   cancel its own fee input.

The third action is an explicit Bitcoin operation, not an in-memory cancel.
Other participants can release their reservations only after observing the
confirmed invalidation. The protocol cannot force a malicious participant or
coordinator to make progress.

All inputs opt in to BIP 125 replacement. A conforming replacement:

- increments `replacement_epoch` and has a new `manifest_id`;
- sets `feerate_sat_vb` above the prior signed epoch and no higher than the
  proposal's maximum, then recomputes the formula in section 8;
- spends the exact same stock and participant inputs in the exact same order;
- preserves the payloads, header, marker, scripts, stock principal, and all
  output positions;
- increases only `miner_fee` and the ordered participant charges, reducing
  only the corresponding change values;
- remains within the proposal's max feerate, every `max_charge`, dust floor,
  local policy, and current relay replacement rules; and
- receives fresh `SIGHASH_ALL` signatures from the stock owner and every
  participant.

There is no unilateral coordinator fee bump and no silent fallback. A withheld
fully signed older transaction can still race a replacement, so wallets MUST
track every signed epoch and accept whichever valid conflict confirms. BIP 125
is relay policy and does not guarantee that a replacement propagates or wins.
Reservations and signed-conflict metadata survive until the wallet's finality
policy is met and remain recoverable across a reorg.

## 11. Stable rejection reasons

C1/C2 return stable machine-readable reasons, with human detail kept separate:

```text
invalid_version              wrong_chain
invalid_serialization        invalid_stock
stale_chain_state            expired_proposal
invalid_commitment           duplicate_commitment
conflicting_operation        unavailable_fee_input
noncanonical_order           payload_context_mismatch
header_mismatch              protocol_layout_violation
fee_policy_violation         insufficient_change
arithmetic_overflow          signature_policy_violation
invalid_signature            replacement_violation
storage_failure
```

Unknown internal failures map to `storage_failure` only when persistence is the
cause; they MUST NOT be mislabeled as a protocol rejection. Adding or changing
a stable reason is an API compatibility decision.

## 12. Replay and equivocation

- `chain_id` rejects cross-network replay.
- The stock outpoint, nonce, expiry, count, and fee policy make `batch_id`
  proposal-specific.
- `operation_id`, commitment nonce, payload, fee input, and change script make
  each `commitment_id` operation-specific.
- Ordered commitment IDs, charges, epoch, and exact unsigned transaction make
  `manifest_id` transaction-specific.
- `SIGHASH_ALL` commits each signature to all prevouts, sequences, and outputs.
- The v2 header commits to the ordered payload envelope and input-0 context.
- Exact transaction rebroadcast is deliberately idempotent; a distinct
  transcript reusing an operation or reserved input is rejected.

A participant MUST persist every manifest it signs. It MUST NOT sign two
different manifests at the same replacement epoch or a lower epoch. Conflicting
manifests from one coordinator are evidence of equivocation and SHOULD be
gossiped as such without revealing raw nullifiers.

## 13. Threat model

| Threat | Required response | Residual risk |
|---|---|---|
| Coordinator changes a fee, output, order, payload, or recipient | Recompute the canonical transaction; reject before `SIGHASH_ALL` signing | Coordinator can stall |
| Coordinator takes the stock | Input 0 requires the stock-owner signature and returns exact principal | Owner can refuse or double-spend its own stock |
| Coordinator takes participant funds | Each P2WPKH input requires its owner's signature over every output | A signer can still sign a bad tx if its client skips validation |
| Coordinator withholds signatures or broadcast | Gossip signatures to all peers; anyone can combine/broadcast | One missing signature prevents progress |
| Participant contributes a spent, conflicting, or false-value UTXO | Verify prevout independently before commit and again before sign | A race can invalidate the batch before confirmation |
| Participant aborts before signing | Expire and form a new batch | Proof/coordination time is lost |
| Participant aborts after another signature exists | Retain locks; exact rebroadcast, unanimous replacement, or confirmed conflict-cancel | No guaranteed liveness |
| Replay or cross-network substitution | Domain hashes, `chain_id`, nonces, stable operation IDs, and persisted signed manifests | Exact rebroadcast is allowed |
| Fee or marker tampering | Fixed formula, values, positions, max charges, and signer-side validation | Fee estimates can become stale |
| Replacement steals principal or shifts fees | Preserve inputs/scripts/positions/stock and require unanimous fresh signatures | Old signed conflict can race |
| Malformed or ambiguous serialization | Fixed-width canonical encoding, explicit lengths, checked bounds, golden vectors | Implementations can still contain parser bugs |
| Public explorer lies | Use it only as a hint; verify spend-critical state through independent node/header/block paths | Eclipse and network partition remain operational risks |
| Bitcoin reorg | Keep reservations and operation journal through the confirmation policy; roll back state and rebroadcast/re-evaluate | Deep reorg can delay finality |
| Crash at any state | Persist proposal, commitment, reservation, signed manifests, and final transaction before outward effects | Corrupt storage requires wallet recovery procedure |
| Coordinator/peer flood | `N <= 64`, bounded messages, proof/UTXO checks, per-peer quotas, deadlines, and no signature before full validation | Public P2P remains DoS-exposed |

## 14. Privacy

The coordinator sees each 24-byte context-bound payload, fee outpoint, fee
value, change script, charge, and the final participant order. All participants
who receive the full manifest can correlate the same data, and the Bitcoin
network sees the final inputs and outputs. V2 therefore makes no anonymity-set
claim.

Implementations SHOULD use fresh change scripts, authenticated encrypted
transport, peer rotation or privacy transport where available, and minimal log
retention. They MUST NOT transmit raw nullifiers, private keys, WIFs, wallet
descriptors with private material, or proofs not required by the recipient.
Payload position is evidence and remains aligned with participant order.

## 15. Migration from v1

1. V1 chain scanning and receipt acceptance remain supported under `OCSV` and
   the `batch` hash domain.
2. V2 creation uses `OCS2`, `batch-v2`, signed stock, participant inputs, and
   this canonical transaction only.
3. V1 stock outputs MUST NOT be treated as v2 stock. Their scripts, ownership,
   and domain are different.
4. Existing `batch ctx` and `batch anchor` CLI paths are marked legacy when C1
   lands. C2 introduces the v2 proposal/commit/sign gossip flow.
5. No decoder may silently reinterpret an invalid version as the other
   version.

## 16. Required implementation evidence

### C1: Rust and regtest

- golden byte vectors for every transcript and hash;
- exact script, stack-item, opcode, weight, fee, and dust boundary tests for
  `N = 1` and `N = 64`;
- canonical multi-party transaction construction and full signature validation;
- generated mutation tests for every input, output, payload, order, fee, count,
  context, network, commitment, manifest, and sighash field;
- duplicate input, spent input, conflicting input, stale tip, expiry, insufficient
  change, and arithmetic overflow rejection;
- participant abort, coordinator equivocation/withholding, replay, crash-state,
  unanimous replacement, and confirmed conflict-cancel tests;
- multi-party regtest evidence from proposal through confirmation and payload
  occurrence; and
- a test proving the coordinator cannot spend stock or participant inputs
  unilaterally.

### C3: Lean model

The Lean batch model is updated only after C1 semantics are frozen in code. It
models the fixed input/output positions, canonical participant permutation,
one-to-one payload/input/change alignment, equal quotient/remainder charges,
conservation and stock-principal invariants, header/envelope occurrence, replay
domains, and replacement monotonicity. The axiom audit and public honesty table
MUST include the new batch claims.

### C2: CLI/P2P

C2 implements proposal, commitment, manifest, signature, resume, and broadcast
gossip without introducing a required server. It persists the state machine,
relays signatures to all participants, treats public transaction relay as a
fallback only, and exposes stable rejection reasons. iOS integration is
explicitly deferred to the final execution phase.

The reference implementation is `opencsv_cli::batch_gossip` and the
`opencsv batch v2` command family. Relay frames are versioned, bounded to 4
MiB, content-addressed, authenticated by a separate secp256k1 relay identity,
and persisted only after the C1 body passes protocol validation. Relay
authentication does not provide confidentiality; deployments requiring
transport privacy wrap the peer connection in an authenticated encrypted or
privacy-preserving channel. C1 `SIGHASH_ALL` input signatures—not the relay
identity—remain the authorization for the Bitcoin transaction.

## 17. Decision log

| Decision | Accepted rationale | Superseded alternative |
|---|---|---|
| Signed, count-specific P2WSH stock | Preserves input-0 context while preventing theft | V1 anyone-can-spend stock |
| Stock principal returned unchanged | Makes participant fee allocation explicit and auditable | Coordinator subsidy from stock |
| One P2WPKH fee input and change per payload | Freezes a deterministic weight and equal marginal shape for C1 | Arbitrary inputs, merged change |
| Equal quotient/remainder allocation | Exact, deterministic, and fair for identical marginal shapes | Coordinator-selected or proportional hidden fees |
| Canonical outpoint order with fixed protocol positions | Stable payload/input/change evidence while preserving input 0 and marker layout | Arrival order or global BIP 69 ordering |
| Full `SIGHASH_ALL` for every input | Prevents unilateral membership/output mutation | `ANYONECANPAY`, `NONE`, or `SINGLE` |
| Signature gossip to every participant | Removes the coordinator as the sole broadcaster | Return signatures only to coordinator |
| Unanimous invariant-preserving replacement | Allows fee recovery without changing OpenCSV evidence | Unilateral RBF or silent fallback |
| New magic and hash domain | Fail-closed separation from v1 | Heuristic version detection |
| Maximum 64 participants | Bounded coordination/DoS cost with ample Bitcoin policy margin | The v1 `u8` maximum of 255 |

Changes to these frozen decisions require an explicit protocol amendment,
updated vectors, threat review, and a journaled compatibility decision. Failed
approaches and benchmark results are recorded with the implementation receipt;
published claims require reproducible tests or chain evidence.

[bip69]: https://bips.dev/69/
[bip125]: https://bips.dev/125/
[bip143]: https://bips.dev/143/
[bip174]: https://bips.dev/174/
[core-policy]: https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.h
[core-script]: https://github.com/bitcoin/bitcoin/blob/master/src/script/script.h
