# opencsv-pcd

> Mainnet note: predecessor verification-key binding is complete, but root
> verification-key authentication is still the D5 production gate. See
> [D5 root verification-key authentication](D5_ROOT_VK_AUTHENTICATION.md).

Proof-carrying data (PCD) circuits for **OpenCSV** (client-side verified
RWAs on Bitcoin, see `paper/opencsv.md` §4), built on the Plonky3
circuit/recursion stack.

**Stage 1:** a non-recursive circuit proving knowledge of an opening of an
OpenCSV coin commitment (paper §4.3):

```
C = H("coin" ∥ asset_id ∥ v ∥ owner ∥ r)
```

**Stage 2:** the mint and transfer predicate circuits (paper
§4.4–4.5), still **non-recursive** (recursion is stage 3):

- **Mint** (`src/mint.rs`): with public statement `x = (asset_id, V,
  mint_commit)` — each output commitment recomputes, values in range,
  `Σ v_i = V`, and `mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce)`.
- **Transfer** (`src/transfer.rs`): 2 inputs / 2 outputs, **single asset**
  (restriction, see below) — input commitments recompute, ownership
  `owner_i = H(osk_i)`, nullifiers `nf_i = H("null" ∥ osk_i ∥ C_i)`, values
  in range, conservation `Σ v_in = Σ v_out`, output commitments recompute.

Both reuse the opening circuit's sponge pattern (now factored into
`src/hash.rs`), and share proving plumbing (`src/prove.rs`) and the u64
value gadget (`src/value.rs`).

## Prover setup cache (D1)

Expensive AIR/preprocessed `CircuitProverData` is cached process-wide for
both the standalone and recursive circuits. The cache key is a SHA-256
identity over the full canonical circuit structure, table packing, AIR and
constraint-profile identity, FRI parameters, crate version, and the pinned
Plonky3-recursion revision. Recursive entries additionally include each
predecessor's verification-key identity: proof metadata, table manifest,
lookup description, preprocessed commitment, and commitment metadata. Proof
witnesses and proof bytes are deliberately not part of that identity.

The cache is bounded to eight least-recently-used entries per configuration
family. Circuit executors at the pinned upstream revision are neither `Send`
nor `Sync`, so circuits remain local to each caller. Only preprocessed prover
data is shared, behind a mutex because its upstream ALU schedule cache is
internally mutable. Witness generation remains concurrent; proving calls that
reuse one setup serialize only while accessing that setup data. Poisoned
locks are recovered because setup data is deterministic and contains no
transactional application state.

Tests cover cold/warm reuse, identity invalidation (circuit, setup parameters,
and predecessor verification keys), bounded eviction, and concurrent cold
access with exactly one construction. D4 additionally constrains that cached
predecessor-key identity in-circuit, independently of cache selection or
call-site discipline.

**Stage 3:** real PCD recursion (paper §4.5 item 4). The
`src/node.rs` module adds:

- **Mint circuit** (genesis): the stage-2 mint predicate plus a statement
  table. No predecessors.
- **Node (transfer) circuit**: the stage-2 transfer predicate plus a
  statement table plus **two in-circuit batch-STARK verifications of the
  predecessor proofs** (one per consumed coin), built per proof from the
  predecessors' proof metadata (the upstream `prove_next_layer` pattern). A
  predecessor may be a mint proof or another node proof.
- **One-input transfer circuit (v4)**: verifies one authenticated predecessor
  and creates two outputs (recipient plus optional change). It retains the
  53-element statement width with `nf_1` real and `nf_2 = 0`; no fake padding
  coin is introduced and value conservation remains exact.
- **Statement table** (`src/statement.rs`): a custom non-primitive table
  that exposes the circuit's full public statement as **STARK instance
  public values** — the binding channel the pinned upstream stack lacks for
  circuit-level public inputs (see "Public-input binding" below).
- **Chaining**: the node circuit `connect`s (via NPO relays) the
  predecessor's bound statement — `asset_id` and the selected output
  commitment `select(k_i, out_1, out_0)` — to its own recomputed input
  commitment `C_i` and asset. This is what chains the PCD: every transfer
  attests its inputs' full ancestry back to genesis mints, and the root
  verifier only checks the final proof.

**Stage 4 (current): redeem + accept-driver integration** (paper §4.6, §4.8):

- **Redeem circuit** (`src/node.rs`): burns one coin, verifying **one**
  predecessor proof in-circuit (mint or node — the coin's ancestry) with the
  same chaining constraints as the node circuit. It is a separate circuit,
  not the node circuit with `N_IN = 1`: the circuit shape is fixed by the
  number of in-circuit verifier sub-circuits, and a redeem needs exactly
  one. The shared statement layout is reused with `mode = 2` (REDEEM):
  `asset_id` and `V` (the coin's committed value *is* the public burn
  amount — the value limbs go straight into the statement), `nf_1 =
  H("null" ∥ osk ∥ C)`, and `mint_commit` / `nf_2` / both outputs zero.
  Constraints: input commitment recomputes, ownership `owner = H(osk)`,
  nullifier recomputes. API: `prove_redeem` / `verify_redeem`
  (`RedeemProof = CoinProof` with `NodeMode::Redeem`).
- **Accept-driver integration** (`src/accept.rs`): `CoinProofVerifier`
  implements `opencsv-core`'s `ProofVerifier` trait — **no trait change and
  no `opencsv-core` dependency cycle** (the integration lives in this
  crate). The trait's `proof: &[u8]` blob carries a magic-prefixed,
  versioned postcard envelope of `(mode, full statement, batch-STARK proof)`
  (`encode_coin_proof`); the
  adapter decodes it, checks the statement *projects* onto the driver's
  reconstructed public input
  `x = ctx(32) ∥ anchor_bytes(64) ∥ openings` (anchor tag
  ↔ mode, truncated anchor digests are 24-byte prefixes of the statement's
  full digests, `V` matches, openings recompute to the statement's output
  commitments), then runs `verify_coin_proof` (statement-table comparison +
  native batch-STARK verification). The full statement must ride in the
  proof bytes because anchors carry only truncated digests and openings do
  not carry nullifiers — this is sound because the statement-table values
  are transcript-bound. `vk` must equal the v4 verifier-set tag
  `opencsv-pcd-coin-v4-with-v3-fri94`; foreign tags fail before decoding.
  Version 4 is emitted for every new proof and required at the production
  receiver boundary. Version-3 proofs remain low-level-verifiable for explicit
  migration inspection, but only ancestor-free v3 mints may seed a v4
  recursive proof. V3 transfer/redeem roots are not accepted and cannot act as
  recursive predecessors; versions 1/2 are inspectable but cannot verify.
  Recursive predecessor keys are pinned inside every transfer/redeem
  circuit. Registering the exact self-described *root-circuit commitments*
  remains a separate trust-distribution boundary (below). The proof lineage
  version is bound inside the statement table as well as the outer envelope.
- **Acceptance test** (`tests/acceptance.rs`, `#[ignore]`d): the full
  protocol flow end-to-end — issuer keygen → mint → anchor → `accept()`
  with the real verifier → 2-in/2-out transfer → anchor → `accept()` →
  double-spend rejected by nullifier first-occurrence → redeem → anchor →
  `audit::supply` = mint − redeem at every height.
- **Benchmarks**: `tests/bench.rs` (`#[ignore]`d) measures prove/verify/
  proof-size for mint, transfer, 2-hop transfer, redeem; `tests/node.rs`
  carries the v4 one-input release receipt — see
  `BENCHMARKS.md`.

## Stage-3 architecture notes

**Why two circuits, not one unified circuit.** The stage-2 recommendation
was a single circuit with a mode selector (mint = degenerate transfer) so
every PCD node shares one vk. That cannot bootstrap at this pin: the
unified circuit must *genuinely* verify 2 predecessors of the same shape in
every mode (the circuit shape is fixed; a STARK verification cannot be
masked off by a selector), so a MINT node would also need 2 valid
predecessor proofs of that same circuit — a circular witness dependency
with no base case. The standard escape (a trivial "void" vk verified in
MINT mode) still needs the void circuit's table metadata to match the
unified circuit's exactly — strictly more machinery than keeping the
stage-2 mint circuit as the base case. This is the task's documented
fallback (i); the statement layout and statement-table binding are shared,
so the vk *set* is small: the mint vk plus the node vks (one per
predecessor-shape variant — node circuits are built per proof from their
two predecessors' shapes, fibonacci-style, and shapes converge at a fixed
point after a few recursion depths).

**Statement layout** (53 base elements, shared by all three circuits):

```
[version(1) | mode(1) | asset_id(8) | V(3) | mint_commit(8) | nf_1(8) |
 nf_2(8) | out_1(8) | out_2(8)]
```

New proofs have transcript-bound `version = 4`; authenticated version-3
proofs retain their original bound version and are never relabeled. Mints:
`mode = 1`, nullifiers zero. Transfers: `mode = 0`, `V` and
`mint_commit` zero. Two-input transfers use both nullifier slots; one-input
v4 transfers constrain `nf_2 = 0`. Redeems (stage 4): `mode = 2`, `V` = burned value,
`nf_1` the coin's nullifier, `mint_commit` / `nf_2` / outputs zero. The
statement elements are *computed* in-circuit (hash
outputs / selected values), so they are pinned to the witness by the
circuit's own constraints; the statement table then binds them into the
proof (see below).

**STARK config.** Authenticated proof lineages v3 and v4 use the frozen
`CoinFriParams::production()` profile:
`log_blowup = 3` (8× LDE), maximum folding arity 4,
`log_final_poly_len = 2`, 64 queries, 16 commit-grinding bits per FRI round,
and 16 query-grinding bits. The lookup-expanded batch shapes contain at most
707 constraints at maximum degree 3; setup rejects drift beyond the audited
budgets of 1024 constraints / degree 3. The Plonky3 0.6.3 proven-security
calculator is evaluated against every proof's actual extended trace degrees.
The calculator uses conservative `floor(log2(|BabyBear^4|)) = 123`, then
OpenCSV subtracts 2 bits for its four soundness components and 3 bits for
seven batch instances, publishing and enforcing a 94-bit floor. The random-words
conjectured estimate is capped at 123 bits and is not used as the deployment
claim. `CoinFriParams::testing()` remains explicit and is used only by the
recursion feasibility spike. See `src/security.rs` and `BENCHMARKS.md` for
the executable receipt and references.

## Public-input binding (stage 3)

At the pinned commit, circuit "public inputs" ride the witness bus: the
Public table sends them but no AIR constrains them and no table exposes
STARK instance public values, so a batch-STARK circuit proof attests only
satisfiability for *some* public inputs. Stage 3 closes this for the
recursive proofs with the **statement table** (`src/statement.rs`):

- The op reads the 53 statement witnesses; the trace holds their 4 base
  coefficients each in one row.
- The AIR **receives** each `(witness_index, value)` from the
  `WitnessChecks` bus (tying the row to the circuit's actual witness
  values) and constrains every cell against the instance public values
  (`mult · (cell − pv) = 0`).
- Non-primitive table `public_values` are observed into the Fiat-Shamir
  transcript by both the native and the in-circuit verifier, so the
  statement is **cryptographically bound** to the proof.

In-circuit, the predecessor's statement public values become parent-circuit
targets (`BatchStarkVerifierInputsBuilder.air_public_targets`), which the
node circuit constrains to its recomputed input commitments / asset — the
PCD chain link. At the root, `verify_coin_proof` compares the proof's
statement-table public values against the expected statement and natively
verifies the proof — the carried-and-compared limitation of stages 1–2 is
gone for coin proofs (the stage-1/2 standalone circuits keep it).

**Verification-key binding and remaining gaps (honest):**

- *Predecessor keys are hard-bound.* The parent circuit extracts each
  recursive verifier's preprocessed-commitment targets and constrains every
  element to the native predecessor key selected at circuit construction.
  The relay uses the `recompose/coeff` WitnessChecks table, which also forces
  every commitment element to be base-field embedded; changing coefficient
  zero or injecting non-zero extension coefficients fails witness
  generation. Circuits without this table (genesis) retain their original
  table manifest, while transfer/redeem proofs advertise it explicitly.
- *Duplicate two-input ancestry is constrained in the AIR.* Three private
  boolean selector bits point to one unequal input-commitment limb and the
  selected difference must be invertible. Equal inputs make every selector
  unsatisfiable. The Rust wrapper and receiver retain their independent
  duplicate checks as defense in depth.
- *Legacy recursion is narrowed.* V3 transfer circuits predate the preceding
  AIR constraint, so v3 transfers and redeems are inspection-only. Only v3
  mints, which have no ancestors, may be recursive migration roots. Production
  acceptance requires a v4 root.
- *Root key authorization remains external.* `verify_coin_proof` verifies
  the proof-carried root common data. A production verifier must map the
  accepted proof-format/circuit version to an allowlisted root identity; D4
  prevents a fixed parent circuit from accepting a foreign predecessor, but
  does not authorize an arbitrary custom root circuit.
- *Statement elements are EF-embedded base values by construction;* a
  custom prover injecting non-base EF private inputs is not ruled out
  in-circuit (same caveat as stage 2).
- The mode field of a predecessor is unconstrained by the successor (a
  transfer may spend mint or transfer outputs; only `asset_id` and the
  selected output commitment are chained).

**Bus-safety rules discovered at this pin** (relevant to future circuit
work):

- Never `connect` a public input to a constant or another expression — the
  Public table is an unconditional bus creator, so aliasing double-sends
  the slot (empirically: `connect` to the pooled zero constant, or to
  private inputs, unbalances `WitnessChecks`).
- Using verifier-allocated public targets as ALU operands trips an
  optimizer slot-rewrite bug when two verifier sub-circuits share a
  circuit. Relay public targets through an NPO read
  (`recompose_base_coeffs_to_ext([t, 0, 0, 0])`) and constrain the relay
  output instead.
- Hint outputs (hash decompose coefficients) whose only use is an NPO read
  have no bus creator — they must be claimed by a trivial ALU op
  (`push_statement_op` does this for all statement elements).

## Dependencies and pinning

- Proving stack: published Plonky3 crates **0.6.3** (`p3-baby-bear`,
  `p3-field`, `p3-batch-stark`, …) — shared with `opencsv-core`, single
  version in `Cargo.lock`.
- Circuit/recursion crates: the
  [`opencsvnet/Plonky3-recursion`](https://github.com/opencsvnet/Plonky3-recursion)
  fork, pinned to
  **`d6510eb629097d733d631e8e833fc962025f25f5`**. It is exactly one narrow
  read-only accessor commit over official Plonky3-recursion
  `b36339709a7a67ee9760fb578b3d4339fd983709` (main @ 2026-07-06, tracks p3
  0.6); the accessor exposes only the allocated preprocessed-commitment
  target and keeps its metadata private. Used crates: `p3-circuit`,
  `p3-circuit-prover`, `p3-poseidon2-circuit-air`, and `p3-recursion` (all
  version 0.1.0, unaudited upstream PoC — expect API churn; do not bump the
  pin blindly).
- The crates.io `p3-recursion 0.1.0` is a **stub** — do not use it.

## Field and hash configuration

- Base field: BabyBear (`p = 2^31 − 2^27 + 1`), same as `opencsv-core`.
- Hash: Poseidon2 width 16 / rate 8 / digest 8, `RF = 8`, `RP = 13`, the
  Plonky3 parameter set (`default_babybear_poseidon2_16()`), same as
  `opencsv-core::field`.
- STARK config: `p3_circuit_prover::config::baby_bear()` — FRI over
  BabyBear with quartic extension challenges, Poseidon2-based MMCS and
  challenger. **Note:** this preset uses
  `FriParameters::new_benchmark_high_arity` (benchmark-grade); production
  parameters must be chosen before anything relies on these proofs.
- **Circuit field: `BinomialExtensionField<BabyBear, 4>` (D = 4).** The
  upstream prover at the pinned commit only supports Poseidon2 tables for
  extension degrees D ∈ {2, 4, 5} — there is no `RegisterPoseidon2ForExt<1>`
  impl and BabyBear has no binomial quadratic extension, so a base-field
  (D = 1) circuit with Poseidon2 ops cannot be proven. With
  `Poseidon2Config::BABY_BEAR_D4_W16` the 16-element BabyBear state is packed
  into 4 extension limbs (limb `i` ↔ state elements `4i..4i+4`), and the AIR
  constrains exactly the native BabyBear permutation.

## How the circuit mirrors `opencsv-core`'s hash semantics

`opencsv-core::field::hash_felts` computes
`Sponge([N] ∥ domain_felts ∥ parts…)` with `N` = number of elements after
the prefix, using `PaddingFreeSponge` (overwrite mode: each rate-sized chunk
*overwrites* state `0..8`, a trailing partial chunk leaves the stale elements
untouched, capacity is preserved between chunks; digest = final state
`0..8`).

For the coin commitment the absorbed vector is 30 BabyBear elements:
`[29] ∥ "coin" (2) ∥ asset_id (8) ∥ v (3 LE 24-bit limbs) ∥ owner (8) ∥ r (8)`.

The circuit (`src/opening.rs`, sponge factored into `src/hash.rs`) reproduces
this exactly:

- **Inputs:** 8 public inputs (commitment `C`, base elements embedded in the
  extension field) and 27 private inputs (the opening, same embedding).
  `[29]` and the two `"coin"` domain elements are circuit constants.
- **Sponge:** 4 chained `add_poseidon2_perm` rows (rate 8 = 2 extension
  limbs per row; `new_start` on the first row chains the rest, matching the
  native capacity preservation). Absorbed elements are packed 4-per-limb via
  `recompose_base_coeffs_to_ext(_via_alu)`. The final chunk is partial
  (6 elements): the second limb mixes the 2 absorbed elements with the 2
  leftover coefficients of the previous row's output via
  `decompose_ext_to_base_coeffs` — exactly the native overwrite semantics
  (this is the same absorption pattern as upstream's
  `recursion/src/pcs/mmcs.rs`). `absorb_len = 0` on all rows: the AIR's
  optional prefix-free duplex length tag is a different construction
  (native `DuplexChallenger`), not `PaddingFreeSponge`.
- **Constraint:** the final state rate limbs are `connect`ed to the
  recomposed public-input limbs, so `C = H("coin" ∥ …)` is enforced.

## Stage-2 hash chains

`src/hash.rs` generalizes the sponge into `hash_felts_limbs` /
`hash_felts_base` helpers (any domain, any parts). The stage-2 circuits add
three more `opencsv-core` hash shapes, all with the same packing pattern:

- **Ownership** `owner = H(osk)` — note: **no domain tag** (matching
  `OwnerSecret::owner`), and the 32-byte secret absorbs as **11** elements
  (`bytes_to_felts`, 3 bytes/element — *not* the 8-element digest encoding),
  so the input is `[11] ∥ osk` (12 elements, 2 rows).
- **Nullifier** `nf = H("null" ∥ osk ∥ C)` — 22 elements (3 rows); `C` is the
  in-circuit output of the commitment chain, decomposed to base elements and
  absorbed directly, which is what binds the nullifier to the recomputed
  commitment.
- **Mint commit** `H("mint" ∥ asset_id ∥ V ∥ mint_nonce)` — 22 elements
  (3 rows), matching `opencsv_core::mint_commit`.
- **Issuer authorization** first derives
  `ipk = H("issuer-key-v1" ∥ issuer_seed)` and then reproduces
  `H("OpenCSV-asset" ∥ genesis)` exactly. The digest-to-byte-to-felt
  conversion is constrained in-circuit so the result matches the existing
  `AssetGenesis::asset_id` wire encoding, rather than defining a second asset
  identifier.

Circuit composition (Poseidon2 permutation rows): mint = 3 (issuer key) +
4 (asset id) + 2×4 (output commitments) + 3 (mint commit) = **18 rows**;
transfer = 2×4 (input
commitments) + 2×2 (ownership) + 2×3 (nullifiers) + 2×4 (output
commitments) = **26 rows**, plus on the order of 10³ ALU/witness rows for
limb range checks, carries and recompose-via-ALU packing.

## Deviations from the paper

- **Issuer authorization is a PCD signature of knowledge.** A recursive
  version-3 mint proves knowledge of the seed committed by
  `genesis.issuer_pk`, derives the claimed asset id from the full genesis,
  and transcript-binds the exact mint statement in the same circuit. That
  coin proof is the authorization artifact; this is not an independently
  verifiable conventional signature. The standalone stage-2 `MintProof`
  still has the public-input limitation documented below and is not a
  production authorization boundary. Legacy Ed25519 records remain
  inspectable/exportable but cannot create version-3 mints.
- **Single-asset transfers.** All inputs/outputs of a transfer share one
  public `asset_id`. Paper §4.5 allows mixed assets with per-asset
  conservation and *hidden* transferred asset ids; that needs per-coin asset
  witnesses plus per-asset sum constraints, left for later stages.
- **Output commitments are not public inputs** (they match the paper's
  public statements `x`); they are carried in the proof structs as
  witness-derived data until recursion chains them to successor proofs.
- **Consignment proof bytes carry the full statement** (stage 4). The
  paper's `x` for the accept driver is reconstructed from the anchor and
  openings, but anchors hold only 24-byte truncated digests, so
  `CoinProofVerifier`'s magic-prefixed version-3 envelope carries
  `(mode, statement, proof)` and
  checks the statement projects onto `x` (truncation- and tag-wise) before
  verifying. Legacy unprefixed envelopes decode for inspection as version 1
  but fail verification and cannot be recursive predecessors. Version 3 is
  also the first transcript-bound statement element, so an older proof
  cannot be promoted by relabeling its outer envelope. Soundness is
  unaffected: the whole statement is transcript-bound via the statement
  table.

## u64 value gadget (`src/value.rs`)

Paper §4.4–4.5 require `0 ≤ v < 2^64` and exact (wrap-around-free) sums.
There is no off-the-shelf u64 gadget in `p3-circuit`, so values are handled
as **three little-endian limbs (24, 24, 16 bits)** — exactly
`opencsv-core`'s `u64_to_felts` encoding, with the top limb narrowed to 16
bits so a checked triple encodes *exactly* `[0, 2^64)`:

- **Range check:** `decompose_to_bits(limb, n_bits)` per limb. The hint
  truncates to `n_bits`, so an out-of-range limb conflicts with its
  reconstruction at witness generation.
- **Sum constraint** (`enforce_sum_eq`): per-limb carry propagation
  `lhs_0 + lhs_1 + c_i = rhs_0 + rhs_1 + 2^24 · c_{i+1}` with
  `c ∈ {0, 1}` (1-bit decomposition) and the final carry pinned to zero.
  All per-limb differences lie in `(-2^26, 2^26) ⊂ (-p/2, p/2)`, so the
  field equality holds iff the integer equality does — no mod-`p`
  wrap-around can fake balance, and a sum overflowing `u64` fails proving.
- All balance/overflow failures surface as `CircuitError` at witness
  generation (slot conflicts), never as STARK constraint failures — this is
  deliberate (`assert_bool` on a non-boolean would abort debug proving via
  `check_constraints` instead of returning an `Err`).

## Public API

```rust
// Stage 1 — commitment opening.
pub fn prove_opening(coin: &Coin) -> Result<OpeningProof, OpeningError>;
pub fn verify_opening(expected: &Digest, proof: &OpeningProof)
    -> Result<(), OpeningError>;

// Stage 2 — mint (N_OUT = 2 outputs).
pub fn prove_mint(genesis: &AssetGenesis, issuer_secret: &[u8; 32],
                  mint_nonce: &Digest,
                  outputs: &[Coin; MINT_OUTPUTS]) -> Result<MintProof, MintError>;
pub fn verify_mint(expected: &MintStatement, proof: &MintProof)
    -> Result<(), MintError>;

// Stage 2 — transfer (2 inputs / 2 outputs, single asset).
pub fn prove_transfer(asset_id: &AssetId,
                      inputs: &[(Coin, OwnerSecret); TRANSFER_INPUTS],
                      outputs: &[Coin; TRANSFER_OUTPUTS])
    -> Result<TransferProof, TransferError>;
pub fn verify_transfer(expected: &TransferStatement, proof: &TransferProof)
    -> Result<(), TransferError>;

// Stage 3 — PCD coin proofs.
pub fn prove_genesis_mint(genesis: &AssetGenesis, issuer_secret: &[u8; 32],
                          mint_nonce: &Digest,
                          outputs: &[Coin; NODE_OUTPUTS]) -> Result<CoinProof, NodeError>;
pub fn prove_coin_transfer(asset_id: &AssetId,
                           inputs: &[(Coin, OwnerSecret); NODE_INPUTS],
                           outputs: &[Coin; NODE_OUTPUTS],
                           predecessors: [&CoinProof; 2], selectors: [usize; 2])
    -> Result<CoinProof, NodeError>;
pub fn verify_coin_proof(expected: &NodeStatement, coin: &CoinProof)
    -> Result<(), NodeError>;

// Stage 4 — redeem (burn one coin, 1 in-circuit predecessor verification;
// RedeemProof = CoinProof with NodeMode::Redeem).
pub fn prove_redeem(asset_id: &AssetId, input: &(Coin, OwnerSecret),
                    predecessor: &CoinProof, selector: usize)
    -> Result<RedeemProof, NodeError>;
pub fn verify_redeem(expected: &NodeStatement, proof: &RedeemProof)
    -> Result<(), NodeError>;

// Stage 4 — accept-driver integration (opencsv-core's ProofVerifier seam).
pub struct CoinProofVerifier; // impl opencsv_core::accept::ProofVerifier
pub fn encode_coin_proof(proof: &CoinProof) -> Vec<u8>;

// Low-level: explicit public data + witness (negative tests / later stages).
pub fn prove_opening_raw(commitment: &[BabyBear; 8], witness: &CoinWitness)
    -> Result<OpeningProof, OpeningError>;
pub fn prove_mint_raw(asset_id: &AssetId, genesis: &AssetGenesis,
                      issuer_secret: &[u8; 32], value: u64,
                      mint_commit: &Digest, mint_nonce: &Digest,
                      outputs: &[Coin; MINT_OUTPUTS])
    -> Result<MintProof, MintError>;
```

Proof structs carry their public data (`OpeningProof { commitment, proof }`,
`MintProof { statement: MintStatement { asset_id, value, mint_commit },
output_commitments, proof }`, `TransferProof { statement: TransferStatement {
asset_id, nullifiers }, output_commitments, proof }`), and the `verify_*`
functions compare it before verifying the batch-STARK proof — see the
binding limitation below. `output_commitments` are recomputed in-circuit
from the witness openings but are *not* public inputs (matching the paper's
public statements); they are carried for the consignment and will be chained
to successor proofs at the recursion stage.

## Known limitation: public-input binding (stages 1–2)

At the pinned commit, `BatchStarkProver::verify_all_tables` proves
**satisfiability of the circuit for some public inputs**: circuit "public
inputs" are sent on the witness bus but no table exposes STARK instance
public values (`NonPrimitiveTableEntry.public_values` is empty for the
primitive and built-in non-primitive tables), so a raw proof does not
cryptographically bind its public data. The stage-1/2 circuits store the
public data in each proof struct and the `verify_*` functions compare it
against the expected values. **Stage 3 closes this gap for coin proofs**
with the statement table — see "Public-input binding (stage 3)" above; the
stage-1/2 standalone circuits remain carried-and-compared.

## Tests and timings

```
cargo test -p opencsv-pcd -- --nocapture
```

The D2 production-profile receipt is in `BENCHMARKS.md`. On an Apple M4,
release proving is 0.10–0.12 s for mint, 7.8–12.2 s for recursive transfer,
and 4.7–5.9 s for redeem (warm/cold); verification is 15–22 ms. Proofs are
0.54–0.85 MB. The benchmark reports every proof's actual trace degrees and
raw/union-adjusted proven-security estimate alongside timings and sizes.
On a physical iPhone 16e (A18), the same cold sequence measured 0.181 s for
mint, 11.253 s and 14.469 s for the two transfer shapes, and 7.283 s for
redeem, with 18–23 ms verification. The four-step Horner packing in the
frozen profile is required to stay below the phone's process-memory ceiling;
the rejected candidates and kernel receipt are in `BENCHMARKS.md`.

The ignored acceptance test remains the full real-proof protocol check:
mint → accept → transfer → accept → later double-spend rejected → redeem →
supply audit. Run it with `cargo test -p opencsv-pcd --release --test
acceptance -- --ignored --nocapture`. The node and redeem suites cover
wrong predecessors, public-data tampering, issuer forgery, wrong owner
secrets, legacy proof versions, and history-independent proof size.

All negative proving tests fail with `*Error::Circuit` at witness
generation (witness-slot conflicts on the aliased `connect` slots), never as
STARK constraint failures — see the value-gadget note above.

Confidence check for the pinned upstream dependency (run in a clone of the
recursion repo at the pinned commit — the same sources Cargo fetches):

```
git clone https://github.com/opencsvnet/Plonky3-recursion.git
cd Plonky3-recursion && git checkout d6510eb629097d733d631e8e833fc962025f25f5
cargo run --release --example poseidon2_perm_chain -p p3-circuit-prover 3
```

(proves and verifies a 3-permutation chain; also the heavier
`cargo run --release --example recursive_fibonacci -p p3-recursion --
--field baby-bear --n 100 --num-recursive-layers 2` from the feasibility
spike.)

## What's next

1. **Root-circuit commitment registry:** the accept adapter already pins the
   v4 lineage/profile tag and recursive predecessor keys are hard-bound, but
   deployments must distribute the accepted self-described root circuit
   commitments as shapes converge.
2. **Paper gap carried from stage 2:** single-asset transfers (§4.5).
3. **Shipped in stage 4:** the redeem circuit (§4.6), accept-driver
   integration with the real recursive verifier, the end-to-end acceptance
   test, and benchmarks (`BENCHMARKS.md`).

## What's next (superseded stage-3 plan, kept for reference)

1. **Recursion (stage 3, shipped — see above):**
   - Upstream machinery: `p3-recursion`'s
     `verifier::batch_stark::verify_p3_batch_proof_circuit` builds an
     in-circuit verifier for a concrete `BatchStarkProof` and returns a
     `BatchStarkVerifierInputsBuilder` (proof/common-data targets for the
     parent circuit); the `recursive_aggregation` example shows the full
     2-to-1 flow (`examples/common::prove_next_layer`) — exactly the shape
     of a 2-input transfer verifying 2 predecessor proofs.
   - **vk unification (mint vs transfer predecessors).** A transfer input's
     predecessor can be a `π_mint` or a `π_transfer` — two different
     circuits with different AIR sets/`CommonData`, and the in-circuit
     verifier needs the matching `CommonData` targets per proof. Options:
     (a) verify *both* candidate proofs per input and select on a witness
     flag (simple, but pays both verifier circuits per input);
     (b) **unify mint and transfer into one circuit** with a mode selector
     (mint = degenerate transfer: no inputs, `V` public; transfer = no
     `V`/`mint_commit`), so all ancestors share one vk/`CommonData` —
     recommended, since every PCD node then verifies predecessors of a
     single shape, and the selector gadgets are cheap next to the hash
     chains; (c) carry a vk commitment in each proof's public data and check
     it against a hard-coded registry (needs in-circuit vk hashing; the
     least mature at this pin).
   - **Public-input binding (fixes the standalone limitation).** The
     in-circuit verifier allocates the inner proof's public inputs as
     targets in the parent circuit (`construct_batch_stark_verifier_inputs`
     in `recursion/src/public_inputs.rs`, and
     `CircuitBuilder::build_with_public_mapping` which exposes the
     `ExprId → WitnessId` map of the inner circuit's public rows), so the
     parent constrains them directly: the transfer circuit's computed input
     commitment `C_i` gets `connect`ed to the predecessor proof's public
     slots (for a transfer predecessor: its `output_commitments`, which
     stage 3 must therefore promote to public inputs; for a mint
     predecessor: likewise). The *root* verifier still needs explicit
     public-value exposure (upstream may add it; otherwise check the Public
     table's trace openings against claimed values).
2. **Parameters/keys:** benchmark-grade FRI parameters and per-circuit
   `ProverData` setup (currently rebuilt per proof in `setup()`) need to be
   revisited for production.
