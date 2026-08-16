# OpenCSV D5 — root verification-key identity and v5 root-authentication design

Design-only deliverable for issue #32 steps 2–3. Head:
`3036359290be03b2fb32a7391d85dd1e36dedc82` (branch `codex/d5-root-vk-auth`).
No production code is changed here; this is the decision record that the
implementation must satisfy. Line citations are against that tree.

---

## 0. TL;DR / recommendation

**Recommended construction: a frozen, finite canonical *key-set commitment*
(KS) carried in the transcript-bound statement, verified against a
deployment-pinned constant — a disciplined hybrid of Candidate A (VK-lineage)
and Candidate B (fixed key), *not* the O(depth) certificate/DAG of A as
written.** Candidate A as literally specified (a per-lineage certificate that
reconstructs each ancestor's canonical child setup) is **succinct only while it
is unsound**, and becomes O(depth) the moment it is made sound. Candidate B (a
genuinely universal/cyclic recursive verifier key) is the theoretically right
end state but is **not reachable at the pinned `plonky3-recursion` revision**
without a new upstream primitive that does not exist there. The frozen finite
key-set is the construction that is both sound and succinct *today*, needs only
a narrow, auditable upstream change, and fails closed on mainnet until present.

Two findings gate everything below:

- **F1 (upstream, structural).** At the pinned revision the `Const` table's
  *preprocessed* columns commit only `(multiplicity, witness_index)` — **not the
  constant value**. Constant values live in the *main* (witness) trace, and
  `ConstAir` "has no constraints" (`circuit-prover/src/air/const_air.rs:17`).
  The native verifier rebuilds the const AIR with `ConstAir::new(proof.rows[Const])`
  and **no values** (`circuit-prover/src/batch_stark_prover.rs:1757`). D4's
  predecessor-key binding constrains the *predecessor's* preprocessed commitment
  in-circuit, but the **parent circuit's own** `version`, `mode`, and every
  hash-domain / key-set constant it hardcodes are const-table outputs whose
  values are not in the preprocessed commitment. This is a *source-level
  structural finding*, not a demonstrated end-to-end forgery (see §7, receipt
  `d5_const_value_binding_is_required`). The v5 design is robust to either
  outcome: if exploitable, the upstream fix is mandatory; if not, it is cheap
  hardening — and **KS soundness is conditioned on the fix either way**, because
  the in-circuit KS-hash domain tags are themselves const-table values.

- **F2 (root-verifier self-description, the known D5 gap).** `verify_coin_proof`
  (`crates/opencsv-pcd/src/node.rs:1558`) reconstructs the verifier from the
  proof's own `table_packing`, `non_primitives`, `rows`, and `stark_common`. The
  single line that *is* the gap is `let common = &proof.stark_common;`
  (`circuit-prover/src/batch_stark_prover.rs:1319`, inside `verify_all_tables`):
  the verifier trusts the proof-carried preprocessed commitment as its own root
  of trust. Nothing compares that commitment to an independently authenticated
  OpenCSV identity. `COIN_VK_TAG` (`security.rs:21`) is a byte-string label
  checked in `CoinProofVerifier::verify` (`accept.rs:256`), not a cryptographic
  key check.

The rest of this document: §1 the canonical root-VK identity (step 2); §2
Candidate A fully specified and then killed; §3 Candidate B evaluated and
deferred; §4 the recommended frozen key-set (step 3); §5 the four review
questions answered concretely; §6 cost model; §7 threat matrix; §8
serialization + size cap; §9 `verify_coin_proof` call-graph changes; §10
migration rule; §11 what could not be decided and the measurements that decide
it.

---

## 1. Step 2 — canonical, domain-separated root-VK identity

### 1.1 What must be committed

The identity must cover **every component the native verifier consumes when it
reconstructs the root verifier**, because any component the identity omits is a
component an attacker may vary while keeping the identity fixed. From
`verify_coin_proof` → `new_prover` → `verify_all_tables` → `verify::<D>`
(`circuit-prover/src/batch_stark_prover.rs:1737`), the verifier-relevant inputs
are exactly:

| Component | Source field | Why it is verifier-relevant |
|---|---|---|
| Preprocessed commitment | `proof.stark_common.preprocessed.commitment` | The Merkle cap the STARK opens against; the circuit's actual "vk". |
| Per-instance preprocessed meta | `preprocessed.instances[i] = {matrix_index, width, degree_bits}` | Selects which committed matrices bind which AIR; a re-indexing changes the circuit. |
| `matrix_to_instance` | `preprocessed.matrix_to_instance` | Same. |
| Table packing | `proof.table_packing` | Lane counts, Horner steps, min height, FRI params — all re-derived by the verifier. |
| Row counts | `proof.rows` (`RowCounts`) | `ConstAir::new(rows[Const])` etc.; raw counts (not just padded degrees) drive the rebuilt AIRs. |
| Non-primitive manifest | `proof.non_primitives[*] = {op_type, rows, lanes, public_values, air_variant}` | Which dynamic tables exist, in which order, and their exposed public values. |
| ALU shape flags | `proof.alu_variant`, `proof.ext_degree`, `proof.w_binomial`, `proof.alu_quintic_trinomial` | Field/reduction identity of the ALU AIR. |
| FRI profile | `CoinFriParams::production()` | Query count, blowup, grinding — the security profile. |
| Lineage version / mode | statement elements 0–1 | Bound in the statement table, but part of *which circuit* is canonical. |

### 1.2 The identity function (replaces the current Debug-string hash)

The current `verification_key_identity` (`node.rs:273-333`) hashes several of
these via **`format!("{:?}", …)` Debug strings** (`proof_metadata`, `lookups`)
and stringly-typed `preprocessed_metadata`. That is explicitly the "debug-only
or textual identity" the issue forbids for the *root* identity. Step 2 defines a
byte-canonical replacement, `RootVkIdentity`, that the v5 root check uses (the
existing `verification_key_identity` may remain as the *cache/D1* key, but the
*authentication* identity below must be structural, not Debug-derived).

```
DOMAIN         = "opencsv/pcd/root-vk-identity/v5"        (ASCII, length-prefixed)
UPSTREAM_REV   = "opencsvnet/plonky3-recursion/d6510eb…"  (the pinned rev)
PROFILE_ID     = COIN_PROOF_PROFILE_ID                     (security.rs:15)

RootVkIdentity(proof) = SHA256(
    LP(DOMAIN) ‖ LP(UPSTREAM_REV) ‖ LP(PROFILE_ID) ‖
    LP( canonical_le(version) ‖ canonical_le(mode) ) ‖
    LP( postcard(proof.table_packing) ) ‖
    LP( canonical_rowcounts(proof.rows) ) ‖
    LP( canonical_alu(proof.alu_variant, proof.ext_degree,
                      proof.w_binomial, proof.alu_quintic_trinomial) ) ‖
    LP( canonical_manifest(proof.non_primitives) ) ‖
    LP( canonical_preprocessed(proof.stark_common.preprocessed) )
)
```

- `LP(x)` = 8-byte little-endian length prefix ‖ `x` (the existing `hash_part`
  discipline, `setup_cache.rs:90`). Domain separation is mandatory and every
  variable-length field is length-prefixed so no two distinct component
  tuples can alias by concatenation.
- `canonical_le` — fixed-width little-endian integers, never Debug.
- `canonical_rowcounts` — the three `usize` counts as fixed 8-byte LE each,
  **including the raw (pre-pad) count**, because the verifier consumes
  `proof.rows[…]` directly (see §11 measurement M2).
- `canonical_alu` — one tag byte per enum discriminant (a fixed match, not
  `{:?}`), `ext_degree` as 1 byte, `w_binomial` as `0x00` (None) or
  `0x01 ‖ 4-byte-LE limbs`, `alu_quintic_trinomial` as one bool byte.
- `canonical_manifest` — for each entry in **proof order**: `op_type`
  canonical bytes (a stable registry id, §11 M3), `rows` (8 LE), `lanes`
  (8 LE), `air_variant` tag, then the exposed `public_values` **only for tables
  whose public values are structural, not statement data** — in practice the
  statement table's public values are excluded here (they are authenticated by
  the statement channel, §4) and every other NPO exposes none.
- `canonical_preprocessed` — `present`/`absent` tag; instance count (8 LE); per
  instance `Some`/`None` tag and `{matrix_index, width, degree_bits}` as fixed
  LE; `matrix_to_instance` length + entries as fixed LE; then
  `postcard(commitment)`. This is the existing `preprocessed_metadata` logic
  (`node.rs:288-320`) but with the commitment bytes always length-delimited and
  no `format!`.

**Key property:** `RootVkIdentity` is a pure function of verifier-relevant proof
structure, is reproducible from a circuit build alone (no proof witness, no
proof bytes), and contains no Debug or textual channel. Two byte-identical
identities ⇒ the native verifier will reconstruct byte-identical AIRs, packing,
and preprocessed binding. This is the atom the v5 authentication check compares.

---

## 2. Candidate A — VK-lineage certificate/DAG: full spec, then why it dies

The issue names this the leading serverless candidate and requires its exact
construction even if rejected. Here it is in full, followed by the kill.

### 2.1 Byte format

An `LineageCertificate` rides in the proof envelope as a new field (§8):

```
LineageCertificate {
    frozen_mint_root:  RootVkIdentity,          // the one authenticated anchor
    nodes:             Vec<LineageNode>,         // deduplicated canonical setups
    terminal:          u32,                      // index into nodes of the presented root
}
LineageNode {
    descriptor:        KeyDescriptor,            // §2.2 — how to reconstruct this setup
    predecessors:      Vec<u32>,                 // indices into nodes (a DAG, topo-ordered)
    derived_identity:  RootVkIdentity,           // the identity this node's setup produces
}
```

Encoding: postcard, length-prefixed, size-capped before allocation (§8). The
DAG is stored in a **canonical topological order** (§2.4).

### 2.2 KeyDescriptor (the "compact proof-shape/key descriptor")

A `KeyDescriptor` is exactly the inputs `setup_circuit_with_verification_keys`
(`recursion_config.rs:339`) needs to *rebuild* a canonical child circuit's
setup, minus anything derivable from the predecessors:

```
KeyDescriptor {
    circuit_kind:  enum { Mint, OneInputTransfer, TwoInputTransfer, Redeem },
    version:       u8,                 // 3 or 4
    fri_profile:   ProfileId,          // COIN_PROOF_PROFILE_ID (frozen)
    statement_n:   u16,                // STATEMENT_ELEMS = 53
    // predecessors' identities are supplied by the DAG edges, not inlined
}
```

The reconstruction is: for each node, take its predecessors' `derived_identity`
values (as the `verification_keys: &[SetupIdentity]` argument), call
`build_<kind>_circuit(config, <predecessor stubs>)`, run
`setup_circuit_with_verification_keys`, and recompute `RootVkIdentity` from the
resulting preprocessed commitment. The descriptor is compact (≈ 8 bytes) because
the *shape* is fully determined by `(circuit_kind, version, profile,
statement_n)` **plus the predecessor identities**, and the predecessor
identities are the DAG's edges rather than inlined ancestor proofs. This
answers review question 1 affirmatively **in principle** (see §5.1 for the
crucial caveat that dooms it).

### 2.3 Hash domains

- Node identity: `RootVkIdentity` (§1.2) with `DOMAIN =
  "opencsv/pcd/root-vk-identity/v5"`.
- Certificate binding into the statement: a separate domain
  `"opencsv/pcd/lineage-cert/v5"` over the frozen mint root ‖ the terminal
  `derived_identity`, so the certificate cannot be lifted between deployments.

### 2.4 Dedup / canonicalization rules

- **Node dedup:** two nodes with equal `(descriptor, sorted predecessor
  identities)` are the same node; the builder must emit each once and edges
  reference the single index. Dedup key is the `derived_identity`, which is a
  pure function of `(descriptor, predecessor identities)`.
- **Canonical DAG order:** nodes sorted by `(topological depth, derived_identity
  bytes)` ascending; edges as ascending index lists. Any other order is
  rejected (kills "reordered DAG").
- **Terminal rule:** `nodes[terminal].derived_identity` **must equal**
  `RootVkIdentity(presented proof)`; and the DAG must be rooted only at
  `frozen_mint_root` (every source node's descriptor is `Mint` with identity ==
  `frozen_mint_root`).

### 2.5 Envelope placement

`LineageCertificate` is a new, optional, versioned field of the v5
`ProofEnvelope` (§8), *outside* the statement but bound to it by the
`"lineage-cert/v5"` hash which is itself compared to a statement-carried value.

### 2.6 Why Candidate A dies

**A is succinct only while F1 is unfixed.** Today, canonical child setups appear
to "converge to a fixed point after a few recursion depths" (README:151). But
that convergence is an artifact of the **vacuous** const binding (F1): the
parent circuit's hardcoded constants (version, mode, domain tags) are not in the
preprocessed commitment, so two circuits that differ only in those constants can
share a preprocessed commitment and therefore an identity. **Once F1 is fixed**
(const values enter the preprocessed commitment — required anyway for KS
soundness), the preprocessed commitment becomes sensitive to the full constant
set, and the "fixed point" is no longer guaranteed: each recursion depth can
produce a distinct canonical identity, because the predecessor-key constants
that the parent hardcodes differ by depth. That makes:

- **Certificate size O(depth)** — one `LineageNode` per distinct ancestor
  identity, growing without bound with lineage length.
- **Verification O(depth)** — the receiver must recompute each node's
  `derived_identity`, i.e. **rebuild each canonical child setup**. From
  BENCHMARKS.md the cold−warm setup delta is ≈ 1.0–2.4 s per recursive circuit
  (transfer cold 9.94 s vs warm 7.77 s; node-pred 12.19 vs 9.76). A depth-D
  lineage costs ≈ D × (that) in *verification*, on a phone.

This violates **required property 2** ("the final proof and verification work do
not grow with transaction history", D5_ROOT_VK_AUTHENTICATION.md:47) — not as a
performance complaint but as an invariant breach. A serverless certificate that
reconstructs ancestor setups is either (a) vacuous-and-succinct (unsound, today)
or (b) sound-and-O(depth) (violates property 2). There is no middle. **Reject
A.** Its salvageable core — a *finite, frozen* set of canonical identities that
does not depend on depth — is precisely the recommended design (§4).

---

## 3. Candidate B — upstream fixed/universal recursive verifier key

### 3.1 What it would require

A universal/cyclic verifier key is one whose identity is a fixed point of "the
circuit that verifies a proof under this very key." Property: a single
`RootVkIdentity` authenticates arbitrary depth, because every layer verifies
under the same key. This is the IVC/cycle-of-curves or accumulation approach
(Halo/Nova-style). At the pinned revision the recursion API is **not** cyclic:
`verify_p3_batch_proof_circuit` (`recursion/src/verifier/batch_stark.rs:203`)
builds an in-circuit verifier **from a concrete `BatchStarkProof`'s shape**
(`proof.rows`, `proof.non_primitives`, `proof.table_packing`,
`proof.alu_variant`). The parent circuit's shape is a function of the child
proof's shape, so parent ≠ child in general and there is no self-referential
fixed point available. `D5_ROOT_VK_AUTHENTICATION.md:57-59` records the same:
"no supported cyclic setup primitive has yet been identified."

### 3.2 Can a fixed universal key be introduced without circular key commitments?

**Not at this pin, without a new upstream primitive** (review question 3, §5.3).
A genuine universal key needs one of:

- **Shape-uniform recursion** — a verifier circuit whose shape is *independent*
  of the child proof's row counts / manifest (padded to a fixed profile), so
  parent and child converge to one shape by construction. This is a *bounded*
  version of B and is the bridge to §4: it does **not** need a cryptographic
  cycle, only a "pad every canonical proof to one frozen shape class" upstream
  affordance plus a fixed enumeration of base cases. It preserves arbitrary
  depth and succinctness and needs **no online authority**. It is reachable with
  a small, auditable upstream change (§4.4, `ShapeDescriptor`), *not* a new proof
  system.
- **Accumulation/folding** — a true universal key, but requires a different
  proof system (Nova/Protostar-class) or a cycle-of-curves. That is a
  multi-quarter proof-system swap, explicitly out of scope here and gated by the
  same six properties (D5 record:60-62).

### 3.3 Verdict on B

The *pure* universal key is the right long-term target but is **not shippable at
the pin**. The *bounded shape-uniform* form of B is exactly what makes the
recommended finite key-set both sound and depth-independent, so the
recommendation folds B's shippable half into §4 and leaves the folding-based
universal key as future work with an explicit proof-format boundary.

---

## 4. Recommended construction — frozen finite canonical key-set (KS)

A hybrid: **finite, deployment-pinned enumeration of canonical root identities
(from A's salvageable core) + shape-uniform recursion so the enumeration is
depth-independent (from B's shippable half) + a transcript-bound key-set
commitment so the receiver check is O(1)**.

### 4.1 The frozen key-set

At release, the deployment computes the finite set of canonical
`RootVkIdentity` values, one per canonical circuit shape:

```
KS_SET = { RootVkIdentity(mint),
           RootVkIdentity(one_input_transfer over each canonical pred class),
           RootVkIdentity(two_input_transfer over each canonical pred class),
           RootVkIdentity(redeem over each canonical pred class) }
KS_ROOT = MerkleRoot_sorted(KS_SET)     // domain "opencsv/pcd/ks-root/v5"
```

`KS_ROOT` is a single 32-byte constant **pinned in the production binary** (a
`const`, reproducibly regenerated by a committed build step, §6). It is the
"one immutable, deployment-bound trust anchor" the D5 record demands
(D5 record:41-44). The receiver never trusts a proof-carried root; it checks the
proof's own `RootVkIdentity` is a member of `KS_ROOT`.

The set is **finite and depth-independent** because §4.4's shape-uniform
recursion collapses every canonical circuit to one of a fixed enumeration of
shape classes, regardless of how deep the lineage is. The number of classes K is
the count of `(circuit_kind × canonical predecessor-shape class)` combinations
(redeem is never a predecessor — it has no outputs — so predecessors range over
{mint, one-input, two-input}). K is provisionally 6–9; **measurement M2/M3
freezes the exact number**, and see §6 for the `RECURSIVE_SETUP_CACHE_CAPACITY`
consequence.

### 4.2 Where the check binds — no proof-carried self-authorization

Two independent bindings, both required:

1. **Receiver-side membership (native, out of circuit).** `verify_coin_proof`
   computes `RootVkIdentity(proof)` from the proof's own structure (§1.2) and
   checks membership in the pinned `KS_ROOT`. The membership witness (a Merkle
   path) may ride the envelope — it is *not* trusted data, because the leaf it
   authenticates is recomputed from the proof and the root is the pinned const.
   A foreign root produces a `RootVkIdentity` not under `KS_ROOT`; membership
   fails. This kills F2 directly: the trust root is the pinned const, never
   `proof.stark_common`.

2. **In-circuit key-set binding (so recursion inherits it).** Each parent
   circuit already hard-binds predecessor preprocessed commitments (D4,
   `bind_predecessor_verification_key`, `node.rs:959`). v5 additionally
   constrains, in-circuit, that each predecessor's `RootVkIdentity` is a member
   of the **same** `KS_ROOT` (a `KS_ROOT` const embedded in the circuit, hashed
   against the predecessor's already-bound commitment + shape constants). This
   makes the key-set an in-circuit invariant along the whole lineage, so an
   attacker cannot smuggle a foreign circuit *inside* a lineage either. **This
   in-circuit hash uses const-table domain tags, so it is sound only if F1 is
   fixed** — hence F1 is a prerequisite, not optional.

The statement table already binds `version` and `mode` (elements 0–1). v5 adds
a transcript-bound statement element carrying `KS_ROOT` (or a hash of it with
the deployment id), so the outer receiver check and the in-circuit constant are
provably the same value and cannot be desynchronized.

### 4.3 Why this satisfies every rejected shortcut

- **Not a static string/profile tag:** `KS_ROOT` is a cryptographic commitment
  to reproducibly derived key identities; `COIN_VK_TAG` stays as a cheap
  pre-filter only.
- **Not proof-carried self-attestation:** the leaf is recomputed from proof
  structure, the root is a pinned const; the proof cannot nominate its own root.
- **Not a mutable per-tx allowlist:** `KS_ROOT` is frozen at release; ordinary
  transfers touch no registry.
- **No issuer/server cosign:** verification is fully local.
- **Not finite-depth-as-general:** depth is unbounded; the *shape* set is finite
  by construction (§4.4), which is a different thing from a depth allowlist.
- **Not app-code-signing:** nothing here signs application code.

### 4.4 The one upstream change (bounded B): `ShapeDescriptor` / pad-to-profile

For the key-set to be finite and depth-independent, canonical proofs must pad to
one frozen shape class so parent verifier circuits converge by construction. The
minimal upstream affordance is a `ShapeDescriptor` that equalizes **raw row
counts** (not only min-height padding) across a shape class — because
`verify_p3_batch_proof_circuit` reads raw `proof.rows` (`ConstAir::new(proof.rows[Const])`,
`batch_stark_prover.rs:1757`), two proofs with equal padded `degree_bits` but
different raw row counts still build different parent circuits. The upstream
change is: (a) F1 — const **values** into the preprocessed commitment; (b) an
optional API to equalize row counts to a profile via dummy ops. Both are narrow,
auditable, and within the "one narrow accessor" spirit of the existing pin. If
(b) proves infeasible, the fallback is the **dummy-same-shape bootstrap**: build
each canonical class against a fixed representative predecessor proof of that
class, so the enumeration is still finite (this is the standard "void vk"
escape, and it is a no-upstream-change fallback).

---

## 5. Review questions — concrete answers

### 5.1 Q1: Can canonical child setup be reconstructed from a compact descriptor without carrying complete ancestor proofs?

**Yes, structurally — and that is exactly why Candidate A fails and the frozen
key-set succeeds.** The descriptor is §2.2's `KeyDescriptor` (≈ 8 bytes:
`circuit_kind`, `version`, `fri_profile`, `statement_n`); the reconstruction is
`build_<kind>_circuit` + `setup_circuit_with_verification_keys` using the
predecessors' *identities* (not proofs) as the `verification_keys` argument
(`recursion_config.rs:339`). No complete ancestor proof is needed — only the
predecessor `RootVkIdentity` values. **But** reconstructing *per lineage* (A)
costs one setup rebuild per node (O(depth), §2.6). Reconstructing *once at
release into a finite frozen set* (§4) costs K rebuilds total, amortized to
zero per transaction. Same reconstruction primitive; the frozen-set framing is
what makes it succinct.

### 5.2 Q2: Does current proof metadata contain enough canonical structure, or must v5 change the upstream recursive-verifier interface?

**The metadata is sufficient to *compute* a structural identity, but not
sufficient to make it *authenticating*, and one upstream change is required for
soundness.** Concretely:

- Sufficient for identity: `BatchStarkProof` (`batch_stark_prover.rs:630`)
  carries `proof`, `table_packing`, `rows`, `alu_variant`, `ext_degree`,
  `w_binomial`, `alu_quintic_trinomial`, `non_primitives`, and `stark_common`
  (with `preprocessed = {commitment, instances[{matrix_index,width,degree_bits}],
  matrix_to_instance}`). That is the full component list of §1.1 — enough to
  build `RootVkIdentity`.
- **Not** sufficient without F1: the preprocessed commitment does not cover the
  circuit's own constant *values* (`const_air.rs:17`, `:1757`), so an identity
  built purely from current metadata can be shared by circuits differing in
  hardcoded constants. v5 **must** change the upstream interface to put const
  values into the preprocessed commitment (F1). This is the single required
  upstream interface change; the row-count equalization (§4.4b) is a second,
  optional one with a no-change fallback.

Cited structs/fields: `CoinProof {version, mode, statement, proof}`
(`node.rs:246`); `BatchStarkProof` fields (`batch_stark_prover.rs:630`);
`CommonData`/`GlobalPreprocessed`/`PreprocessedInstanceMeta`
(`batch_stark_prover.rs:~540-600`); the self-description line
`let common = &proof.stark_common;` (`batch_stark_prover.rs:1319`).

### 5.3 Q3: Can a fixed universal key be introduced without circular key commitments? If yes, bootstrap; if no, why not.

**A genuinely universal (cyclic) key: no, not at the pin — proof below. A
*bounded* fixed key-set: yes, with the §4 bootstrap.**

- *Why not cyclic:* the parent verifier circuit's shape is a strict function of
  the child proof's shape (`verify_p3_batch_proof_circuit` consumes
  `proof.rows`, `proof.non_primitives`, `proof.table_packing`), so
  `identity(parent) = f(identity(child), shape(child))`. A universal key needs
  `identity(parent) = identity(child)` for all children — a fixed point of `f`.
  The pinned API provides no accumulation/folding and no shape-uniform verifier,
  so `f` has no computable fixed point without new machinery. Introducing a
  proof-carried "universal vk" and trusting it would be exactly the circular
  self-authorization F2 forbids.
- *The non-circular bootstrap that IS reachable (§4):* pick a **finite** set of
  base shape classes; pad every canonical proof to its class (§4.4); compute
  each class's `RootVkIdentity` at release from the circuit build alone (no proof
  needed for a class's *own* identity — only its predecessor classes' identities,
  which bottom out at the mint base case that has no predecessors). This is a
  well-founded recursion with the mint circuit as base case (no predecessors,
  `build_mint_circuit`, `node.rs:570`), terminating in K identities. `KS_ROOT`
  commits to them. No circularity: identities are derived bottom-up from a base
  case, never assumed.

### 5.4 Q4: Migration rule preserving inspection of historical v3/v4 Test USD while forbidding those roots in production.

See §10 for the full rule and pseudocode. Summary: mode-gate on
`(deployment_mode, proof.version, RootVkIdentity ∈ KS_ROOT)`. Inspection paths
(read/restore/sync/evidence-export) accept v3/v4 by version alone; the
production write boundary requires `KS_ROOT` membership, which the v3/v4
profiles' identities are not in.

---

## 6. Cost model

Baseline (BENCHMARKS.md, Apple M4 release; iPhone 16e A18): proofs
0.54–0.85 MB; mint prove ≈ 0.10 s, transfer ≈ 7.8–12.2 s, redeem ≈ 4.7–5.9 s;
verify 15–22 ms; iPhone process-memory hard limit ≈ 3,376 MB; setup cold−warm
delta ≈ 1.0–2.4 s per recursive circuit.

| Dimension | Candidate A (rejected) | Frozen KS (recommended) | Candidate B pure (deferred) |
|---|---|---|---|
| Certificate / extra bytes vs depth | **O(depth)** nodes | **O(1)**: `KS_ROOT` is a compile-time const; envelope adds one 32-byte identity + a ≤ ~10-node Merkle path (`ceil(log2 K)` ≈ 3–4 hashes ⇒ ~128 B) | O(1) |
| Verification time vs depth | **O(depth)** setup rebuilds (≈ D × 1–2.4 s) | **O(1)**: existing 15–22 ms verify + one `RootVkIdentity` hash (µs) + Merkle-path check (µs) | O(1) |
| Setup-cache impact | thrash: one rebuild per node | K canonical setups at release; per-tx none. **`RECURSIVE_SETUP_CACHE_CAPACITY = 8` (`recursion_config.rs:303`) must be ≥ K; if K = 9 it is one short and must be raised**, else release-time KS derivation LRU-thrashes | K setups once |
| iPhone memory | unchanged per proof, but repeated setups risk the 3,376 MB ceiling under depth | unchanged; no per-tx setup; membership check is negligible | unchanged |
| Proving time | unchanged | +one in-circuit KS-membership hash per predecessor (small vs the hash chains already dominating; cf. F1 const cost) | new proof system: unknown |

Net: the frozen KS adds **~160 bytes to the envelope, microseconds to
verification, and no per-transaction setup**, at the cost of a one-time
release-build key-set derivation and one narrow upstream soundness fix. This is
the only candidate that keeps property 2 (history-independent verification)
while being sound.

---

## 7. Threat matrix — attack → the specific check that kills it

| Attack | Killed by | Where |
|---|---|---|
| **Foreign root circuit with expected statement** (the `foreign_statement_only_root` receipt, `node.rs:1890`) | `RootVkIdentity(proof) ∉ KS_ROOT` → membership fails | new step in `verify_coin_proof` (§9), before native verify |
| **Proof-carried root commitment self-authorizes** (F2) | Trust anchor is the pinned `KS_ROOT` const, not `proof.stark_common`; leaf recomputed from proof, root is const | §4.2 item 1 |
| **F1 const-value swap** (parent circuit with altered hardcoded version/mode/domain constants, same preprocessed commitment) | Const values enter the preprocessed commitment upstream; changed constants change `RootVkIdentity` → membership fails; **also** the in-circuit KS hash (whose domain tags are consts) becomes unforgeable | F1 fix + §4.2 item 2; receipt `d5_const_value_binding_is_required` |
| **Altered lineage descriptor** | In frozen KS there is no per-tx descriptor to alter; the receiver recomputes identity from proof structure, ignoring any carried descriptor claim | §4.2 item 1 |
| **Reordered DAG / manifest** | Recommended: `non_primitives` are hashed in **proof order** into `RootVkIdentity`; a reorder changes the identity → membership fails. (A's spec: canonical topo-order rule §2.4) | §1.2 `canonical_manifest`; §2.4 |
| **Missing ancestor** | In-circuit: each predecessor's commitment is hard-bound (D4) *and* KS-membership-checked in-circuit; a missing/foreign ancestor fails the in-circuit hash | §4.2 item 2; `node.rs:959,1012` |
| **Duplicate / conflicting identity** | KS is a sorted Merkle set; membership is by leaf value, so duplicates collapse and a conflicting (non-member) identity fails | §4.1 `MerkleRoot_sorted` |
| **Wrong mode** | `mode` is a transcript-bound statement element (0–1) *and* part of `RootVkIdentity`; the statement-projection check (`statement_matches_public_input`, `accept.rs:155`) already gates anchor-form↔mode | statement table; `accept.rs:174` |
| **Wrong proof shape** | Shape (`rows`, `packing`, `alu_*`, manifest) is in `RootVkIdentity`; off-profile shape → non-member. Upstream `proof.validate()` also rejects malformed metadata | §1.2; `batch_stark_prover.rs:validate` |
| **Cross-version replay** (v3/v4 root on mainnet) | Migration mode-gate: production requires `KS_ROOT` membership, which v3/v4 identities are not in; `root_lineage_is_current` (`accept.rs:250`) already blocks non-current outer version | §10 |
| **Cross-deployment replay** | `KS_ROOT` includes the deployment id via the statement-carried KS element; a proof for deployment X is non-member under Y's pinned const | §4.2 |

---

## 8. Serialization — canonical encoding + size cap before allocation

- **Envelope.** v5 extends `ProofEnvelope` (`accept.rs:66`) with an optional,
  versioned `root_auth: Option<RootAuth>` where `RootAuth = { identity_leaf:
  [u8;32], merkle_path: Vec<[u8;32]> }`. Postcard, as today. The v5 magic/version
  prefix distinguishes it from the v4 envelope (`decode_coin_proof`,
  `accept.rs:108`).
- **Size cap before allocation/proving.** Enforce a hard byte cap **at
  `CoinProofVerifier::verify` entry, before `decode_coin_proof`** (i.e. before
  any postcard allocation): `if proof.len() > MAX_COIN_PROOF_BYTES { return
  false; }`. Provisional `MAX_COIN_PROOF_BYTES = 1.5 MiB` (largest measured proof
  ≈ 854,105 B, doubled with margin; **finalize via M4**). The `merkle_path` is
  additionally capped at `ceil(log2(K_max))` entries (a small const, e.g. 8)
  before it is read.
- **Canonicalization check.** After decode, re-encode and require
  byte-equality (`encode(decode(bytes)) == bytes`) so a proof cannot carry
  non-canonical padding or trailing bytes that a hostile serializer might use to
  desync the identity. This is the standard decode→re-encode→compare discipline
  and belongs next to the cap check.
- The identity hashing (§1.2) is itself canonical by construction: fixed-width
  LE, length-prefixed, no Debug, no map iteration order (the existing
  `hash_sorted_debug` discipline, `setup_cache.rs:99`, is replaced by structural
  sorting where maps appear).

---

## 9. `verify_coin_proof` call-graph changes (function-level, no code)

Current path (`accept.rs:255` → `node.rs:1558`):

```
CoinProofVerifier::verify
  → vk == COIN_VK_TAG                       (accept.rs:256)
  → decode_coin_proof                       (accept.rs:108)
  → root_lineage_is_current(version)        (accept.rs:250)
  → statement_matches_public_input          (accept.rs:155)
  → verify_coin_proof                        (node.rs:1558)
       → proof_version_is_supported
       → validate_proof_security             (security.rs)
       → statement_public_values == expected
       → new_prover + verify_all_tables       (native STARK; trusts proof.stark_common)
```

v5 inserts one authentication gate and one canonicalization gate; nothing is
removed:

```
CoinProofVerifier::verify
  → [NEW] byte-cap + canonicalization check   (§8, before decode)
  → vk == COIN_VK_TAG
  → decode_coin_proof (v5 envelope)
  → [NEW] production_mode_gate                 (§10: forbids v3/v4 roots on mainnet)
  → root_lineage_is_current(version)
  → statement_matches_public_input
  → [NEW] root_identity = RootVkIdentity(coin.proof)     (§1.2, pure structural hash)
  → [NEW] assert root_identity ∈ KS_ROOT via merkle_path against the pinned const
  → [NEW] assert statement-carried KS element == pinned KS_ROOT   (desync guard)
  → verify_coin_proof (unchanged native verify)
```

New leaf functions: `root_vk_identity(&BatchStarkProof) -> [u8;32]` (owned by
`opencsv-pcd`, replacing the Debug-string body of `verification_key_identity`
for authentication purposes); `ks_member(leaf, path, KS_ROOT) -> bool`;
`production_mode_gate(mode, version, KS_ROOT_present) -> bool`. The in-circuit
side adds a `bind_predecessor_key_set` call alongside
`bind_predecessor_verification_key` (`node.rs:1075`) in `chain_predecessor`,
gated on the F1 fix.

---

## 10. Migration rule (Q4) — pseudocode

The invariant: **inspection is version-gated; production writes are
identity-gated.** v3/v4 Test USD stays fully inspectable; neither can arm a
mainnet write because their `RootVkIdentity` is not under the production
`KS_ROOT`.

```
enum DeploymentMode { Inspection, SignetTest, MainnetLimited, MainnetGeneral }

fn accept_root(mode, coin, public_input) -> Decision {
    // 1. Inspection paths (read / restore / sync / evidence-export) never gate
    //    on KS: historical v3/v4 must remain viewable.
    if is_inspection_only(mode) {
        return decode_and_low_level_verify(coin);   // version 3/4 both OK
    }

    // 2. Any production/mainnet write requires the v5 policy to be present and
    //    the proof's structural identity to be a KS member. Fail closed if the
    //    pinned KS_ROOT const is absent (D5 policy not compiled in).
    let ks_root = match pinned_ks_root() {
        Some(r) => r,
        None    => return Reject("production_root_vk_authentication_required"),
    };

    // 3. Production forbids legacy roots regardless of low-level validity.
    if coin.version != COIN_PROOF_VERSION_V5 {           // v3/v4 roots barred
        return Reject("legacy_root_not_production_authenticated");
    }

    // 4. Structural identity must be an authenticated canonical key.
    let id = root_vk_identity(&coin.proof);
    if !ks_member(id, &coin.root_auth.merkle_path, ks_root) {
        return Reject("root_vk_not_in_frozen_key_set");
    }
    // 5. Desync guard + existing statement/native checks.
    if statement_ks_element(&coin.statement) != ks_root { return Reject("ks_desync"); }
    verify_coin_proof(&coin.statement, &coin)            // unchanged native verify
}
```

- **Signet stays test-only:** `SignetTest` may accept v4 for continuity but must
  **not** be relabeled production-safe (D5 record:52-53). Only
  `MainnetLimited`/`MainnetGeneral` arm, and only through step 4.
- **No release override:** the mode gate has no test/config bypass in release
  builds — the D5 record requires "no test or configuration override exists in
  release builds" (D5 record:73). The current stable rejection
  `production_root_vk_authentication_required` (D5 record:79) is preserved as the
  fail-closed default until `pinned_ks_root()` is `Some`.
- **v3→v4 recursive migration is unchanged:** only ancestor-free v3 mints may
  seed v4 (`predecessor_lineage_is_safe`, `node.rs:239`); v5 leaves that intact
  and simply adds the KS gate at the production boundary.

---

## 11. What could not be decided here, and the measurement that decides it

- **M1 — Is F1 end-to-end exploitable?** Decided at source level (const values
  absent from the preprocessed commitment; `ConstAir` unconstrained; verifier
  rebuilds with no values). **Not** demonstrated as a full trace forgery.
  *Measurement:* build an `#[ignore]`d adversarial receipt
  `d5_const_value_binding_is_required` analogous to
  `foreign_statement_only_root` (`node.rs:1890`) that proves a circuit, swaps a
  `Const` op's value while holding the preprocessed commitment fixed, and checks
  whether native verification still accepts. Accept ⇒ F1 is a live exploit and
  the upstream fix is mandatory; reject ⇒ F1 is latent hardening but KS still
  requires the fix for its in-circuit domain tags. **The design is safe either
  way.**
- **M2 — Do canonical circuits actually converge to a finite shape set once F1
  is fixed?** The README's "fixed point after a few depths" was measured under
  the vacuous binding. *Measurement:* after the F1 fix, build parent circuits at
  increasing depth and compare their **`SetupIdentity`** (built-circuit
  equality), **not** their proofs' `degree_bits` — because
  `verify_p3_batch_proof_circuit` consumes raw `proof.rows`
  (`batch_stark_prover.rs:1757`), two proofs with equal padded degrees but
  different raw row counts still yield different parent circuits. If they do not
  converge, §4.4b (row-count equalization) or the dummy-same-shape bootstrap is
  required. This measurement also **freezes the exact K** and thus whether
  `RECURSIVE_SETUP_CACHE_CAPACITY = 8` must be raised.
- **M3 — Stable `op_type` registry bytes.** `NpoTypeId` must hash into
  `RootVkIdentity` via a stable canonical byte id, not `format!("{:?}")`.
  *Measurement/decision:* confirm each NPO type has (or is given) a stable
  numeric/byte id in the frozen manifest ordering.
- **M4 — Final `MAX_COIN_PROOF_BYTES`.** Provisional 1.5 MiB from current
  measurements. *Measurement:* the largest canonical v5 proof across all K shape
  classes plus the `root_auth` field, with margin; set the cap at
  `CoinProofVerifier::verify` entry (§8).
- **M5 — Upstream feasibility of the F1 fix and optional row-count
  equalization.** Whether const values can be moved into the preprocessed
  commitment without a wider proof-system change, and whether a `ShapeDescriptor`
  row-equalization API is small enough to stay within the "one narrow accessor"
  pin discipline. *Measurement:* a spike branch of the fork implementing (a)
  const-value preprocessing and (b) row equalization, measured for proof-size,
  proving-time, and iPhone-memory regressions against BENCHMARKS.md.

---

## 12. Scope guard

This design does **not** re-open the stage-1/2 Public-table binding (the
statement table already covers OpenCSV's needs), does not redesign the v4
transition semantics, and does not swap proof systems. The v5 delta is exactly:
(1) a structural `RootVkIdentity` replacing Debug-string identity for
authentication; (2) a pinned finite `KS_ROOT` const with receiver-side
membership + in-circuit key-set binding; (3) two fork changes — const values into
the preprocessed commitment (required) and optional row-count equalization (with
a no-change dummy-shape fallback); (4) the migration mode-gate. Everything else
in `verify_coin_proof`'s path is preserved. Lean, as the issue's "shippable v5
shape" requires, and fail-closed until the policy const is present.
