# opencsv-kernel

The **pure decision logic** of `opencsv-core`, rewritten in the shape the
Aeneas spike validated for Rust→Lean 4 translation:

- **loops only** — no iterator adapters (`zip` / `chunks` / `enumerate` /
  `position` / `filter` / `map`): those trip charon's associated-type
  lifting and have no model in aeneas's Lean library;
- **no serde, no `dyn` traits, no RNG, no generics** beyond plain numeric /
  byte-array types;
- the Poseidon hash stays behind an **opaque boundary** (`hash` module) —
  the same cryptographic boundary the Lean model
  (`formal/OpenCsv/Interfaces.lean: bindHash`) takes as an axiom.

## Scope (phase 1)

| kernel item | mirrors (opencsv-core) |
|---|---|
| `binding::binding` | `anchor::binding` + `Digest::to_anchor` |
| `record::Record::well_formed` | `anchor::AnchorRecord::well_formed` (+ `payload_slots`) |
| `scan::first_occurrence` | `chain::AnchorChain::first_nullifier_occurrence` (mock semantics) |
| `batch::batch_occurrence` | `batch::envelope_occurrence` |
| `audit::supply` | `audit::supply` (mint dedupe by `mint_commit`) |

Semantics are **byte-identical** to `opencsv-core` — this is a rewrite, not
a redesign. `tests/kernel_equiv.rs` ports the relevant `opencsv-core` test
scenarios and asserts kernel ≡ core on shared cases.

## Boundary

- `types`, `binding`, `record`, `scan`, `batch`, `audit` are the
  **verification surface**: plain data in, plain data out.
- `hash` is the **crypto boundary**: the only place the kernel calls into
  `opencsv-core` (`anchor::binding`, `batch::batch_commit`). For the
  Aeneas run it is translated as an opaque (uninterpreted) function —
  exactly the model's `bindHash` axiom.
- `interop` (conversions from `opencsv-core` types) is glue for callers and
  tests; it is **not** part of the verification surface (excluded from
  translation).
- `scan::first_occurrence` takes the entries in **canonical chain order**
  (block height, then in-block position — the caller's responsibility,
  same contract as `AnchorChain`) and returns the *index* of the first
  well-formed entry; the entry's `Location` is read off the input. The
  core returns the location directly — equivalent by construction.

Wiring the kernel into `opencsv-core` (replacing the duplicated logic) is a
later decision; for now the two coexist and the equivalence tests pin them
together.
