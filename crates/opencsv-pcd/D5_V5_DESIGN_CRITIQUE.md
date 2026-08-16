DESIGN-FLAWED the frozen finite key-set is not depth-independent: after the required F1 repair, D4's exact predecessor-commitment constants make successor keys depend on the exact predecessor key, while padding changes only shape; embedding `KS_ROOT` in those same circuits also creates an unresolved self-commitment fixed point.

# Scope and pins

I reviewed the complete 696-line design, the local D5 record, OpenCSV at
`3036359290be03b2fb32a7391d85dd1e36dedc82`, the pinned
`plonky3-recursion` checkout at `d6510eb629097d733d631e8e833fc962025f25f5`,
and `p3-batch-stark 0.6.3`. The dependency pin is explicit at
`crates/opencsv-pcd/Cargo.toml:28-36`.

Dependency citations below use these prefixes:

- `P3/` = `~/.cargo/git/checkouts/plonky3-recursion-e26d2146d253e9b7/d6510eb/`
- `BATCH/` = `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/p3-batch-stark-0.6.3/`

The public GitHub issue page was not retrievable in this environment. The
acceptance audit therefore uses the repository's D5 record, which explicitly
lists the closure tests at `crates/opencsv-pcd/D5_ROOT_VK_AUTHENTICATION.md:64-76`.
Any acceptance language present only on the external issue page is UNVERIFIED.

# Per-claim verdicts

## 1. F1 — CONFIRMED structurally; exploitable under stated, realistic preconditions

The central structural claim is correct, with one important wording correction:
`ConstAir` has no local polynomial constraints, but it does participate in the
global `WitnessChecks` lookup. That lookup makes all uses agree with the value
chosen in the const main trace; it does **not** make that value equal a
verifier-known circuit constant.

Exact evidence:

- Circuit preprocessing deliberately ignores `Op::Const.val` and records only
  the D-scaled output witness index: `P3/circuit/src/circuit.rs:223-237` and
  `:288-301`.
- Setup converts each const index into `[ext_mult, out_idx]`; no value is added:
  `P3/circuit-prover/src/common.rs:351-367`.
- The const main trace contains only the constant value coefficients:
  `P3/circuit-prover/src/air/const_air.rs:83-126`. The const-table test states
  that its preprocessed layout is `[ext_mult, index]` at `:186-190` and
  `:219-234`.
- The underlying `WitnessSendAir` has no local constraints and sends
  `(witness_idx, main_value)` on the lookup bus:
  `P3/circuit-prover/src/air/public_air.rs:10-21` and `:198-228`.
- Proving constructs the const AIR with preprocessed indices/multiplicities and
  separately commits the value-bearing main matrix:
  `P3/circuit-prover/src/batch_stark_prover.rs:1363-1369`.
- Native verification reconstructs `ConstAir::new(row_count)` with no values:
  `P3/circuit-prover/src/batch_stark_prover.rs:1750-1759`.
- `p3-batch-stark` commits exactly the matrices returned by
  `air.preprocessed_trace()` into `GlobalPreprocessed`:
  `BATCH/src/common.rs:184-256`. There is no second setup channel containing
  const values.

### Other possible channels

None of the suggested metadata channels repairs the omission:

- `degree_bits`, raw row counts, widths, lane packing, FRI parameters, and
  instance maps describe sizes/layout, not field values. The batch transcript
  observes instance degree/width data and then the proof's main commitment and
  the global preprocessed commitment at `BATCH/src/transcript.rs:27-69` and
  `BATCH/src/verifier/mod.rs:253-263`.
- The main trace commitment does cryptographically bind the prover to the
  constant values it chose for that proof. It is not a verification key and is
  not compared with a canonical value. Binding a malicious choice to itself is
  not circuit authentication.
- OpenCSV's `SetupIdentity::for_circuit` does hash `circuit.ops`, hence the const
  values, at `crates/opencsv-pcd/src/setup_cache.rs:41-80`. But that identity is
  only a local setup-cache key. It is absent from `BatchStarkProof` and from
  native verification, so it cannot authenticate a received proof.
- A const routed to the transcript-bound statement is independently bound by
  the statement public values. This specifically limits attacks that merely
  change the exposed version or mode. The statement table constrains its cells
  to instance public values at `crates/opencsv-pcd/src/statement.rs:270-279`, and
  `verify_coin_proof` compares those values at
  `crates/opencsv-pcd/src/node.rs:1558-1570`.

### Is the two-circuits/one-preprocessed-commitment case realizable?

Yes, at the proof-system level, under these exact preconditions:

1. The two built circuits have the same operation ordering, witness-ID layout,
   table registration/order, packing, and row/degree profile.
2. They differ only in one or more `Op::Const.val` values.
3. The replacements preserve the equality/collision partition of constants.
   Constants are deduplicated by value (`P3/circuit/src/builder/expression_builder.rs:330-381`),
   so changing a value to `0`, `1`, or another existing constant can change
   witness IDs and break the identical-layout premise. Fresh-to-fresh changes
   preserve it.
4. Any NPO preprocessor output also remains unchanged. For a constant used as
   an ordinary operand with the same witness ID, this is the expected result;
   the primitive preprocessing is provably unchanged by the code above.
5. Each altered circuit has a satisfying witness for the target statement.

Under those conditions, every preprocessed matrix and its metadata are equal,
so the global preprocessed commitment is equal. The main commitments and proofs
will normally differ, but each verifies against the same proof-carried common
data because the verifier has no expected const values.

The “same statement” condition is not exotic. A minimal pattern is a private
witness constrained to equal a hardcoded `c`, while the statement is otherwise
independent; changing `c` and the private witness preserves the statement and
the circuit topology. In OpenCSV, the high-value instance is the D4 check:
`bind_predecessor_verification_key` allocates each expected commitment element
with `builder.define_const(value)` and asserts equality at
`crates/opencsv-pcd/src/node.rs:968-997`. Replacing those expected elements with
a foreign predecessor commitment preserves the instruction pattern whenever
the commitment elements have the same ordinary dedup pattern. A foreign
predecessor with the required proof shape and statement can then satisfy the
altered parent. OpenCSV already has an executable fixture that can emit an
arbitrary statement from a foreign circuit (`crates/opencsv-pcd/src/node.rs:1685-1720`),
although that fixture does not by itself pad to every desired predecessor
shape.

What is **not** established is that every single domain-tag or mode change lets
an attacker retain an already chosen statement. Exposed version/mode changes
are caught by the statement comparison, and changing a hash domain may require
finding different openings or may make a particular fixed statement
unreachable. An end-to-end, canonical-shape OpenCSV forgery was not executed in
this review. F1 is nevertheless a real authentication collision, not merely a
theoretical metadata omission.

### Required repair is stronger than the design states

“Put const values into the preprocessed commitment” is insufficient if they are
unused extra columns. The repaired AIR must either source the bus value from
the committed preprocessed value or constrain the main value equal to that
preprocessed value. Otherwise the canonical value can be committed while the
lookup still sends an attacker-chosen main value. This changes const
preprocessed width/openings and therefore recursive-verifier cost; it is not yet
shown to be “cheap hardening.”

## 2. F2 pinning — CONFIRMED, but the design overstates one line as the whole gap

The proof-carried preprocessed commitment is indeed accepted as common data:

- `verify_coin_proof` constructs a verifier using the proof's packing and NPO
  split and calls `verify_all_tables` at
  `crates/opencsv-pcd/src/node.rs:1571-1577`.
- `verify_all_tables` validates proof metadata, checks only the verifier-chosen
  extension field parameters, then assigns
  `let common = &proof.stark_common` and passes it to verification at
  `P3/circuit-prover/src/batch_stark_prover.rs:1284-1322`.
- `verify` clones that preprocessed commitment/metadata into effective common
  data and calls `p3_batch_stark::verify_batch` at
  `P3/circuit-prover/src/batch_stark_prover.rs:1797-1814`.

Thus line 1319 is the point at which the cryptographic preprocessing root is
taken from the proof. It is not the only self-description input: the same
verifier also reads proof-carried `rows`, `table_packing`, `alu_variant`, and
`non_primitives` at `P3/circuit-prover/src/batch_stark_prover.rs:1750-1794`.
The gap is the entire proof-described verifier reconstruction, with line 1319
being its commitment root.

`COIN_VK_TAG` is only a byte label. It is declared as a byte string at
`crates/opencsv-pcd/src/security.rs:14-21`, and acceptance does only
`if vk != COIN_VK_TAG` before decoding the proof at
`crates/opencsv-pcd/src/accept.rs:254-271`. F2 is confirmed.

## 3. Finiteness/depth independence — REFUTED

There are three independent breaks.

### 3.1 The compact descriptor cannot reconstruct the current child setup

The design says an approximately 8-byte descriptor plus predecessor identities
is “exactly” what setup needs. The source says otherwise:

- `setup_circuit_with_verification_keys` receives an **already built**
  `Circuit`; the supplied `verification_keys` are appended only to the local
  cache identity (`crates/opencsv-pcd/src/recursion_config.rs:334-361`). They do
  not reconstruct a verifier circuit.
- The circuit builder calls `verify_p3_batch_proof_circuit` with a concrete
  predecessor `BatchStarkProof` and `stark_common` at
  `crates/opencsv-pcd/src/node.rs:1044-1073`.
- Upstream reads the concrete proof's rows, packing, ALU variant, NPO entries,
  public-value counts, core proof, and common data at
  `P3/recursion/src/verifier/batch_stark.rs:247-322`.
- Target allocation mirrors the nested `BatchProof` object, not an identity:
  `BatchProofTargets::new(circuit, proof)` and
  `CommonDataTargets::new(circuit, common_data)` at
  `P3/recursion/src/public_inputs.rs:622-650`.

A compact canonical **shape descriptor** could potentially replace the concrete
proof, but it must describe the complete target structure (all instance
degrees/widths, NPO entries and public counts, common-data matrix layout, and
FRI/opening target structure). The proposed four-field descriptor does not.

### 3.2 F1 repair plus D4 exact binding leaks exact key identity through every depth

Let `k` be the exact predecessor preprocessed commitment. Current D4 embeds
every field element of `k` as a parent-circuit constant
(`node.rs:973-996`). Once F1 is repaired correctly, changing `k` changes the
parent's authenticated preprocessed commitment. Therefore a one-input parent
key is of the form `F_one(shape, k, KS_ROOT, version, ...)`, and a two-input key
is `F_two(shape1, shape2, k1, k2, KS_ROOT, ...)`.

Pad-to-profile can make `shape` stable. It cannot erase `k`, `k1`, or `k2`
without undoing D4. A depth-`d+1` transfer consumes the exact key produced at
depth `d`; in general it therefore produces a new key. A finite set would have
to be closed under all one- and two-input successor functions. With
commitment/hash-like outputs, finding a small reachable cycle is a cryptographic
fixed-point problem, not a consequence of row padding. The design supplies no
cycle construction or closure proof.

The proposed dummy-same-shape fallback does not help. Building against a dummy
proof hardcodes the dummy's exact commitment. At proving time a real predecessor
with another commitment fails the equality at `node.rs:992-997`. The repository
README already warns that a void key must match exact table metadata and is
additional machinery, not a free fallback
(`crates/opencsv-pcd/README.md:136-151`).

This is fatal to arbitrary-depth acceptance, not an M2 measurement question.
M2 can measure how long accidental shape convergence lasts; it cannot prove
key-value convergence after F1.

### 3.3 The class count is not 6–9 and predecessor classes are not enumerated today

Today the builders accept concrete proofs:

- two-input transfer: `crates/opencsv-pcd/src/node.rs:745-750` and `:804-817`;
- one-input transfer: `:845-852` and `:901-909`;
- redeem: `:1132-1138` and `:1167-1177`.

`NodeMode::Transfer` covers both one- and two-input circuits
(`node.rs:174-183`), even though their proof shapes differ. A two-input parent
has an **ordered pair** of predecessor shapes/keys, not one predecessor class;
the code builds each verifier independently. If three predecessor kinds were
really closed, the two-input branch alone has up to `3 × 3 = 9` ordered shape
combinations, before mint, one-input, redeem, legacy-mint migration, or exact-key
evolution. There is no current enum that collapses these concrete inputs to the
claimed 6–9 classes.

Raw row equalization is also not sufficient by itself. Recursive construction
depends on `proof.proof` target structure, NPO manifest and public counts, common
metadata, packing, and ALU variant in addition to raw rows
(`P3/recursion/src/verifier/batch_stark.rs:247-322`).

## 4. Two-binding soundness — receiver membership is viable; the stated combined construction is incomplete and circular

### Receiver-side membership

Recomputing the leaf from the proof and verifying it against a binary-pinned
root is a sound pattern, assuming collision resistance and a fully specified
Merkle encoding. A path for another leaf or wrong index cannot help if the
verifier starts from the recomputed leaf and applies the correct orientations.

The document does not yet specify enough to guarantee that behavior:

- `MerkleRoot_sorted(KS_SET)` specifies leaf order, but not leaf hashing,
  internal-node domain separation, odd-leaf padding, or sibling orientation.
- `RootAuth` carries only `identity_leaf` and `Vec<[u8;32]>`; it carries no leaf
  index/direction bits. Sorting the leaves does not let a verifier recover the
  direction at each level. The design must either carry a checked index/direction
  bitmap or define a commutative pair hash. The latter has different proof and
  domain-separation requirements.
- The carried `identity_leaf` is redundant. The pseudocode ignores it. It must
  be removed or required equal to the recomputed identity; using it for the path
  check would reintroduce proof-carried self-authorization.

These are specification gaps, not evidence that standard Merkle membership is
inherently unsafe.

### Statement/in-circuit synchronization

If the parent circuit really constrains all `KS_ROOT` limbs into its statement,
the outer verifier checks all those limbs against its pinned root, and the
parent uses those same targets/root for predecessor membership, there is no
desynchronization opening. But the design does not specify that circuit-level
wiring or encoding. The current statement is exactly 53 base-field elements
with no KS field (`crates/opencsv-pcd/src/node.rs:126-140`). A 32-byte root
cannot be collision-resistently represented by one BabyBear element; OpenCSV's
native digest representation uses eight base-field elements
(`crates/opencsv-core/src/field.rs:43`). “One statement element” must therefore
mean a full multi-limb digest and the statement width/public count must change.

More seriously, the proposed constant introduces circularity. The design says
the circuit embeds `KS_ROOT`, while `KS_ROOT` is the Merkle root of the
identities of those circuits. After F1, circuit identity depends on the embedded
root, giving the equation:

`R = MerkleRoot({ Identity(C_i with constant R) })`.

If mint also carries/constrains the statement KS value, the alleged mint base
case already depends on `R`; bottom-up generation does not bottom out. If mint
does not, successors still combine this self-reference with the exact-key
recurrence above. No fixed-point construction is given.

One escape is to make deployment/KS identity a public input checked by the
receiver and propagated/equality-checked through predecessor statements, not a
setup constant. Another is to replace exact D4 binding with an in-circuit
authenticated-key-set check under a non-circular fixed verifier. Both are
materially different designs and require a fresh soundness analysis.

### The in-circuit hash is not specified or costed

`RootVkIdentity` is defined as SHA-256, but the existing in-circuit hash helper
is Poseidon2 (`crates/opencsv-pcd/src/hash.rs:1-5`, `:48-66`, and `:121-141`).
The only current SHA-256 use in this crate is host-side setup identity
(`crates/opencsv-pcd/src/setup_cache.rs:13-19`, `:25-38`). The design never says
how a circuit computes the SHA-256 identity/Merkle path from the allocated
predecessor commitment and canonical metadata. Hardcoding a host-computed leaf
does not bind that leaf to the allocated commitment unless the exact commitment
is separately pinned—which returns to the depth leak. This makes the claimed
“one small hash per predecessor” UNVERIFIED.

## 5. Migration rule — partially sound in isolation, but contradictory and not integrated

If the production pseudocode were faithfully installed, the combination of
`version == v5`, statement-version binding, and membership under a production
root would prevent a simple v3/v4 outer-version replay. Current code already
demonstrates that changing an outer v3 version to v4 fails the statement check
at `crates/opencsv-pcd/src/node.rs:1878-1885`.

However:

- The pseudocode sends every non-`Inspection` mode, including `SignetTest`,
  through the v5-only check, while the prose says SignetTest may accept v4.
  There is no matching branch. The migration rule is internally inconsistent.
- The actual `ProofVerifier` interface has no deployment/network argument
  (`crates/opencsv-core/src/accept.rs:19-29`), and `CoinProofVerifier` is a
  zero-state type whose `verify` method receives only `(vk, public_input, proof)`
  (`crates/opencsv-pcd/src/accept.rs:248-271`). The CLI passes this same verifier
  at receive sites (`crates/opencsv-cli/src/main.rs:673-687`). The design does
  not identify how `DeploymentMode` reaches the verifier or, alternatively,
  where the account write gate lives.
- Write-side mint/send/redeem call proving and anchoring directly
  (`crates/opencsv-cli/src/main.rs:623-671` and `:709-723`); the proposed
  `accept_root` pseudocode is a receive verifier, not the required account-layer
  write gate.
- “Inspection by version alone” must be labeled unauthenticated legacy
  inspection. The foreign statement-only fixture proves that low-level v4
  verification can validate a self-selected circuit
  (`crates/opencsv-pcd/src/node.rs:1888-1908`). Any later path from inspected
  state to a write must re-run v5 authentication.

Cross-deployment replay is not actually killed by the defined construction.
`KS_ROOT` is defined only from `KS_SET`, and `RootVkIdentity` includes domain,
upstream revision, profile, version/mode, shape, and commitment—but no deployment
ID. Merely carrying that same root in the statement does not make it deployment
specific. The document later says the root “includes the deployment id,” which
contradicts its own formulas. The deployment ID must be an unambiguous input to
the leaf/root derivation and statement binding, not an optional parenthetical.

## 6. Cost model — old baselines are cited correctly; all v5 deltas are unmeasured or understated

The v4 baseline values are accurately taken from
`crates/opencsv-pcd/BENCHMARKS.md:105-119`, and the iPhone memory limit is
documented at `:179-187`. They do not support the v5 projections.

- Correct F1 repair expands or changes const preprocessing and recursive
  openings. KS propagation expands the statement from the current 53 elements,
  and recursive verification allocates all predecessor statement public values.
- A Merkle proof needs `ceil(log2 K)` internal hashes per predecessor, not one;
  two-input transfer needs two memberships unless the design changes. Computing
  the defined SHA-256 identity in-circuit would be much more than the existing
  Poseidon helper.
- The asserted `~160 B` envelope delta is plausible only after Merkle encoding,
  directions, root representation, and exact K are fixed. It is not a receipt.
- “Memory unchanged” and “proving time unchanged/small” are unsupported. D5
  explicitly permits normalization only with measured proof, proving, and
  mobile-verification receipts
  (`D5_ROOT_VK_AUTHENTICATION.md:55-62`). None exist for F1 repair, shape
  normalization, wider statements, or in-circuit membership.
- `RECURSIVE_SETUP_CACHE_CAPACITY = 8` is real
  (`crates/opencsv-pcd/src/recursion_config.rs:303-310`), but `K > 8` does not by
  itself imply release-generation “thrashing.” A one-pass generator can compute
  and persist keys even if old cache entries are evicted. Conversely, ordinary
  proving still calls setup for each concrete predecessor-built circuit
  (`node.rs:1355-1362`, `:1464-1471`, and `:1613-1620`), so “per-tx none” is not
  true for the prover unless a new pre-generated setup loading path is designed.

The v5 cost claim is therefore UNVERIFIED and should not be used to select this
construction.

# Acceptance coverage against the local D5 record

The design would cover some negative tests if its receiver gate and canonical
encoding were implemented: changed root commitment, common-data metadata,
manifest, and version relabel should change the leaf or fail the statement.
It does not presently satisfy the complete closure bar:

- **Foreign statement-only root:** conceptually covered by outer membership,
  but only after F1 and canonical identity are correctly implemented.
- **Authenticated mint plus arbitrary-depth transfer/redeem:** **fails** because
  the finite-set closure/bootstrapping argument is invalid.
- **Changed root/common/manifest:** conditionally covered by a complete
  canonical identity and exact Merkle specification.
- **Version relabel:** conditionally covered; current statement binding already
  rejects the v3-to-v4 form.
- **Cross-deployment replay:** **not covered** by the actual identity/root
  formulas.
- **Mainnet account gate/no release override:** **not designed at the real call
  sites**; the proposed verifier mode has no source-level input path.
- **Reproducible key generation and exact CI receipts:** only promised. No
  generator format, deterministic command, checked artifact, independent
  recomputation rule, CI job, or v5 performance/adversarial receipt is specified.
- **Arbitrary-depth test methodology:** not specified. A finite test depth
  cannot establish arbitrary depth; the implementation needs a proof of key-set
  closure plus representative deep/mixed one-input/two-input/redeem tests.

# New findings, ranked

1. **Critical — KS self-commitment cycle.** If `KS_ROOT` is an authenticated
   circuit constant and KS commits those circuit identities, key generation is
   circular even before recursion depth is considered.
2. **Critical — F1 fix invalidates the finite-class abstraction.** Exact D4
   commitment values, not just predecessor shapes, flow into every successor
   key. Padding cannot remove them, and the dummy fallback binds the wrong key.
3. **High — Candidate A/KS reconstruction premise is false at this pin.** The
   current API needs a concrete proof/common-data shape; identities are only
   cache-key salt. The proposed compact descriptor omits load-bearing target
   structure.
4. **High — SHA-256/Poseidon mismatch.** The native identity and proposed
   in-circuit authentication are not the same specified hash construction; the
   cost estimate ignores implementing that bridge.
5. **High — cross-deployment replay remains possible.** Deployment identity is
   absent from the normative formulas.
6. **High — migration/account-gate integration is missing.** The real verifier
   seam has no deployment mode, and write commands do not pass through the
   proposed gate.
7. **Medium — Merkle proof format is incomplete.** No orientation/index or
   commutative-node rule is provided; the carried leaf is redundant and risky.
8. **Medium — RootVkIdentity completeness is asserted, not proved.** Recursive
   construction directly consumes the nested core proof shape, while the
   identity/descriptor specification lists only selected outer metadata. A
   canonical shape type and validation theorem are needed before “two equal
   identities imply identical verifier construction” is safe.
9. **Medium — legacy inspection semantics are ambiguous.** Low-level v4
   verification must not be presented as circuit-authenticated evidence, and
   inspected state must be unable to reach a write without reauthentication.

# Defensive disposition

Do not implement the recommended finite KS as written. F1 should be repaired
independently and tested with two same-topology circuits whose only differing
security constant is value-level. Then choose one of these coherent directions:

1. a genuinely fixed/cyclic/universal root key;
2. a normalized wrapper whose verifier key is independently fixed and which
   authenticates dynamic predecessor keys as inputs; or
3. a redesigned finite-set recursion that removes exact predecessor-key
   constants, proves finite closure, avoids `KS_ROOT` self-reference, and uses
   one precisely specified in-circuit/native hash and Merkle encoding.

Any replacement still needs the D5 record's mixed-shape arbitrary-depth,
cross-deployment, mainnet-gate, reproducible-generation, CI, and physical-mobile
receipts before mainnet enablement.
