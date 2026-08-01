# opencsv-anchor-server (dev/test indexer)

**Status: development and test tooling — not a product component.**

This crate serves the anchor chain over HTTP (`GET /snapshot`, `POST /anchor`,
esplora and file backends). It was built to give wallets a chain view before the
direct-connection model was settled, and it remains useful for demos and
integration testing (it powered the first Mutinynet signet end-to-end run).

The production model does **not** include a bespoke server between wallets and
Bitcoin (paper §4.7.1):

- **Claimed-anchor verification** is trustless on-device via BIP157/158 compact
  block filters (`opencsv-cbf`).
- **Occurrence (double-spend) checks** default to N-of-M independent indexers
  cross-checked against each other — this crate can serve as *one such indexer*
  in a set, but no single instance is ever trusted — with an optional
  zero-trust full-block self-scan per receipt.
- **Broadcasting** goes directly to nodes/public APIs (`POST /tx`, P2P relay).

If you deploy this crate, deploy it as *dev/test infrastructure or as one
indexer among several* — never as a wallet's sole source of chain truth.
