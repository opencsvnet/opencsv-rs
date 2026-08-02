# opencsv-pcd

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
access with exactly one construction. This cache-key binding does not close
the predecessor-vk soundness gap described below; D4 must still enforce that
identity independently of call-site discipline.

**Stage 3:** real PCD recursion (paper §4.5 item 4). The
`src/node.rs` module adds:

- **Mint circuit** (genesis): the stage-2 mint predicate plus a statement
  table. No predecessors.
- **Node (transfer) circuit**: the stage-2 transfer predicate plus a
  statement table plus **two in-circuit batch-STARK verifications of the
  predecessor proofs** (one per consumed coin), built per proof from the
  predecessors' proof metadata (the upstream `prove_next_layer` pattern). A
  predecessor may be a mint proof or another node proof.
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
  crate). The trait's `proof: &[u8]` blob carries a postcard envelope of
  `(mode, full statement, batch-STARK proof)` (`encode_coin_proof`); the
  adapter decodes it, checks the statement *projects* onto the driver's
  reconstructed public input `x = anchor_bytes(64) ∥ openings` (anchor tag
  ↔ mode, truncated anchor digests are 24-byte prefixes of the statement's
  full digests, `V` matches, openings recompute to the statement's output
  commitments), then runs `verify_coin_proof` (statement-table comparison +
  native batch-STARK verification). The full statement must ride in the
  proof bytes because anchors carry only truncated digests and openings do
  not carry nullifiers — this is sound because the statement-table values
  are transcript-bound. `vk` is ignored (fixed circuit shapes; the proof
  self-describes its common data — same caveat as predecessor vk binding).
- **Acceptance test** (`tests/acceptance.rs`, `#[ignore]`d): the full
  protocol flow end-to-end — issuer keygen → mint → anchor → `accept()`
  with the real verifier → 2-in/2-out transfer → anchor → `accept()` →
  double-spend rejected by nullifier first-occurrence → redeem → anchor →
  `audit::supply` = mint − redeem at every height.
- **Benchmarks**: `tests/bench.rs` (`#[ignore]`d) measures prove/verify/
  proof-size for mint, transfer, 2-hop transfer, redeem — see
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

**Statement layout** (52 base elements, shared by both circuits):

```
[mode(1) | asset_id(8) | V(3) | mint_commit(8) | nf_1(8) | nf_2(8) |
 out_1(8) | out_2(8)]
```

Mints: `mode = 1`, nullifiers zero. Transfers: `mode = 0`, `V` and
`mint_commit` zero. Redeems (stage 4): `mode = 2`, `V` = burned value,
`nf_1` the coin's nullifier, `mint_commit` / `nf_2` / outputs zero. The
statement elements are *computed* in-circuit (hash
outputs / selected values), so they are pinned to the witness by the
circuit's own constraints; the statement table then binds them into the
proof (see below).

**STARK config.** The stage-3 circuits prove under a custom config
(`src/recursion_config.rs`) instead of `baby_bear()`: the benchmark FRI
parameters (100 queries, 16 PoW bits) are far too expensive to verify
in-circuit. `CoinFriParams::testing()` (log_blowup 2, arity 4, 2 queries,
no PoW, final poly 2²) is **test-grade — a few bits of conjectured
soundness, not a security claim**; production parameters must be re-chosen
and the in-circuit verifier cost re-measured.

## Public-input binding (stage 3)

At the pinned commit, circuit "public inputs" ride the witness bus: the
Public table sends them but no AIR constrains them and no table exposes
STARK instance public values, so a batch-STARK circuit proof attests only
satisfiability for *some* public inputs. Stage 3 closes this for the
recursive proofs with the **statement table** (`src/statement.rs`):

- The op reads the 52 statement witnesses; the trace holds their 4 base
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

**Remaining binding gaps (honest):**

- *Predecessor vk is bound by call-site discipline.* In-circuit
  verification runs against the predecessor's own `stark_common` (the
  self-describing common data carried in each proof — upstream's
  `RecursionOutput::into_recursion_input` discipline). Hard-binding the
  predecessor vk against an in-circuit constant needs the
  preprocessed-commitment *targets*, which are `pub(crate)` in
  `p3-recursion` at this pin (`CommonDataTargets.preprocessed`); a custom
  prover could substitute foreign common data for a predecessor slot.
  Closing this needs an upstream patch (expose those targets) or
  primitive-table public-value exposure.
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
- Circuit/recursion crates: the official
  [`Plonky3/Plonky3-recursion`](https://github.com/Plonky3/Plonky3-recursion)
  repo, pinned to commit
  **`b36339709a7a67ee9760fb578b3d4339fd983709`** (main @ 2026-07-06, tracks
  p3 0.6). Used crates: `p3-circuit`, `p3-circuit-prover`,
  `p3-poseidon2-circuit-air`, and (stage 3) `p3-recursion` (all version
  0.1.0, unaudited upstream PoC — expect API churn; do not bump the pin
  blindly).
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

Circuit composition (Poseidon2 permutation rows): mint = 2×4 (output
commitments) + 3 (mint commit) = **11 rows**; transfer = 2×4 (input
commitments) + 2×2 (ownership) + 2×3 (nullifiers) + 2×4 (output
commitments) = **26 rows**, plus on the order of 10³ ALU/witness rows for
limb range checks, carries and recompose-via-ALU packing.

## Deviations from the paper

- **Issuer signature stays OFF-circuit.** Paper §4.4 item 1 (Ed25519
  verification of `(asset_id, V, mint_nonce)`, `ipk` bound to `asset_id`
  through genesis) is verified by `opencsv-core`'s accept driver; the paper
  names an AIR-native signature as the production target.
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
  `CoinProofVerifier`'s envelope carries `(mode, statement, proof)` and
  checks the statement projects onto `x` (truncation- and tag-wise) before
  verifying. Soundness is unaffected: the statement is transcript-bound via
  the statement table.

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
pub fn prove_mint(asset_id: &AssetId, mint_nonce: &Digest,
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
pub fn prove_genesis_mint(asset_id: &AssetId, mint_nonce: &Digest,
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
pub fn prove_mint_raw(asset_id: &AssetId, value: u64, mint_commit: &Digest,
                      mint_nonce: &Digest, outputs: &[Coin; MINT_OUTPUTS])
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

Default run (~3.5 min on a 64-core Xeon, debug profile): the twelve stage-1/2
tests (~13 s — see below), the recursion spike (`src/spike.rs`, ~9 s), the
statement-envelope round trip (`src/accept.rs`, ~2 s), the stage-3
`tests/node.rs` suite (~90 s), and the stage-4 `tests/redeem.rs` suite
(~40 s: mint→redeem round trip with wrong-`V`/tampered-statement negatives,
plus a wrong-`osk` proving failure):

- `genesis_mint_verifies` (a): prove ≈ 1.6 s, verify ≈ 57 ms, proof ≈ 46 KB.
- `transfer_spending_mint_outputs_verifies` (b, the money test — two
  in-circuit predecessor verifications): prove ≈ 71 s, verify ≈ 46 ms,
  proof ≈ 56 KB.
- `wrong_predecessor_fails` (d): off-circuit pre-check rejects a coin the
  predecessor never created; a predecessor whose *carried* statement is
  tampered to pass the pre-check fails in-circuit at witness generation
  (witness conflict on the chaining constraint).
- `tampered_public_data_fails` (e): wrong expected statement, wrong asset,
  wrong mode — all rejected with `NodeError::StatementMismatch` before STARK
  verification (the statement table's bound values are compared).
- Stage 4 (`tests/redeem.rs`): `mint_to_redeem_round_trip` (prove ≈ 35 s,
  verify ≈ 46 ms, proof ≈ 54 KB), `wrong_osk_fails` (witness conflict at
  proving time). `transfer_then_redeem` is `#[ignore]`d (~2 min); run it
  with `cargo test -p opencsv-pcd --test redeem -- --ignored --nocapture`.
- The **acceptance test** (`tests/acceptance.rs`, the project's end-to-end
  protocol check — mint → accept → transfer → accept → double-spend
  rejected → redeem → supply audit, all with real proofs) is `#[ignore]`d
  (~3 min); run it with
  `cargo test -p opencsv-pcd --test acceptance -- --ignored --nocapture`.
- Benchmarks (`tests/bench.rs`, `#[ignore]`d; debug and release numbers):
  see `BENCHMARKS.md`.
- `two_hop_chain_verifies` (c) is `#[ignore]`d (~2.5 min); run it with
  `cargo test -p opencsv-pcd --test node -- --ignored --nocapture`:
  hop 1 (mint predecessors) prove ≈ 71 s / verify ≈ 45 ms / 56,041 B;
  hop 2 (node predecessors) prove ≈ 69 s / verify ≈ 45 ms / 56,041 B —
  **proof size and verification time are constant in history length**, as
  PCD requires.

Stage-1/2 tests (unchanged, ~13 s): `opening.rs` (~2.2 s), `mint.rs`
(~2.8 s), `transfer.rs` (~7 s) — see git history for the per-test
breakdown.

All negative proving tests fail with `*Error::Circuit` at witness
generation (witness-slot conflicts on the aliased `connect` slots), never as
STARK constraint failures — see the value-gadget note above.

Confidence check for the pinned upstream dependency (run in a clone of the
recursion repo at the pinned commit — the same sources Cargo fetches):

```
git clone https://github.com/Plonky3/Plonky3-recursion.git
cd Plonky3-recursion && git checkout b36339709a7a67ee9760fb578b3d4339fd983709
cargo run --release --example poseidon2_perm_chain -p p3-circuit-prover 3
```

(proves and verifies a 3-permutation chain; also the heavier
`cargo run --release --example recursive_fibonacci -p p3-recursion --
--field baby-bear --n 100 --num-recursive-layers 2` from the feasibility
spike.)

## What's next

1. **Production parameters:** `CoinFriParams::testing()` is test-grade (a
   few bits of conjectured soundness); choose real FRI parameters and
   re-measure the in-circuit verifier cost. Per-circuit `ProverData` setup
   is currently rebuilt per proof — cache per (circuit-shape) vk.
2. **vk hard-binding:** patch upstream (or wrap) to expose the predecessor's
   preprocessed-commitment targets so the node circuit can pin the
   predecessor vk to a constant instead of trusting the proof-carried
   `stark_common` (see "Public-input binding").
3. **Paper gaps carried from stage 2:** issuer signature off-circuit
   (§4.4 item 1), single-asset transfers (§4.5), test-grade FRI parameters.
4. **Shipped in stage 4:** the redeem circuit (§4.6), accept-driver
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
