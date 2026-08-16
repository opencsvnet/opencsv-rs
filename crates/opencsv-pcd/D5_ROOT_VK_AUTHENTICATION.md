# D5 root verification-key authentication

Status: open, mainnet-blocking. Proof lineage v4 remains signet-only.

## The boundary

D4 constrains each recursive successor circuit to the exact predecessor
verification key selected when that successor is built. That prevents a
witness from substituting a foreign predecessor after setup. It does not
authenticate the final proof's own circuit to a native verifier.

`verify_coin_proof` currently reconstructs the root verifier from the proof's
`table_packing`, non-primitive manifest, common data, and preprocessed
commitment. `COIN_VK_TAG` selects the serialization/profile family; it is not
a commitment to the final circuit. Consequently, a different circuit can
emit the same statement-table layout under the production FRI profile and
pass v4 native verification without enforcing OpenCSV's issuer,
conservation, ownership, or nullifier rules.

The ignored test
`foreign_statement_only_root_demonstrates_the_d5_boundary` constructs that
counterexample. It must remain executable as an adversarial receipt until a
v5 verifier rejects it for the right reason.

## Non-solutions

The following do not authenticate a general recursive root:

- comparing only `COIN_VK_TAG` or another proof-carried label;
- letting the proof attest to its own verification-key hash;
- accepting a mutable per-transaction allowlist of root keys;
- asking an issuer, server, or governance quorum to sign every ordinary
  transfer root;
- publishing a finite recursion-depth allowlist while describing it as
  unbounded proof-carrying data.

All of those either trust attacker-controlled data, add an online authority
to ordinary transfers, or silently abandon history-independent verification.

## Required v5 shape

A shippable v5 design must give the native verifier one immutable,
deployment-bound trust anchor while retaining all of these properties:

1. mint, one-input transfer, two-input transfer, and redeem are admitted only
   through audited transition semantics;
2. the final proof and verification work do not grow with transaction
   history;
3. predecessor keys and public statements remain hard-bound in-circuit;
4. an attacker cannot choose common data, a circuit manifest, or a root key
   that becomes its own authority;
5. proof versioning has no silent v4 fallback on mainnet;
6. signet v4 evidence remains inspectable during migration.

The preferred construction is a fixed/cyclic or genuinely universal
recursive verifier whose verification key is generated reproducibly and
pinned by the production deployment. The currently pinned
`plonky3-recursion` API builds verifier circuits from concrete predecessor
proof shapes; no supported cyclic setup primitive has yet been identified.
Changing proof systems or adding a normalization/wrapper layer is acceptable
only if it meets the six properties above and has measured proof, proving,
and mobile-verification receipts.

## Acceptance tests

D5 closes only when all of the following are green at one reviewed commit:

- the foreign statement-only proof is rejected before product acceptance;
- a valid authenticated mint and arbitrary-depth transfer/redeem lineage is
  accepted through the pinned root;
- changed root key, changed common data, changed table manifest, version
  relabel, and cross-deployment replay are rejected;
- the mainnet account gate calls the authenticated verifier and no test or
  configuration override exists in release builds;
- reproducible key generation and an independent adversarial review are
  published with exact CI receipts.

Until then, the stable account-layer rejection
`production_root_vk_authentication_required` is intentional. Read, restore,
sync, and evidence export remain available; consumer and issuer Bitcoin
writes remain disabled on mainnet.
