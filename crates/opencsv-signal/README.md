# opencsv-signal

Signal transport for **OpenCSV** consignments. Links the OpenCSV client to
your **existing personal Signal account** as a secondary (linked) device —
like Signal Desktop — and moves consignment blobs back and forth as ordinary
Signal attachments. Verification stays client-side in the wallet
(`opencsv-cli`); Signal only ever sees opaque bytes inside Signal's normal
end-to-end encryption.

Built on [presage](https://github.com/whisperfish/presage), an all-Rust
Signal client library. No `signal-cli`, no libsignal bindings other than
what presage itself brings.

**Prototype-grade.** The local store holds unencrypted Signal session keys
and long-term identity keys (see *Storage & security*). Do not use with real
funds, and think twice before pointing it at an account you cannot afford to
compromise.

## Dependency choice

- `presage` + `presage-store-sqlite`, pinned by git revision
  [`f74b96e0fb9099ce8be2b28b7ca9d11f78a6faea`](https://github.com/whisperfish/presage/commit/f74b96e0fb9099ce8be2b28b7ca9d11f78a6faea)
  (master, 2026-07-27; crate version 0.8.0-dev).
- A git pin is mandatory: presage is **not published on crates.io** — the
  `presage` name there belongs to an unrelated event-bus crate.
- The sled store was dropped upstream; `presage-store-sqlite` (in-tree,
  SQLCipher-backed) is the only maintained persistent store, so that is what
  we use. We open it **without** a passphrase.
- presage is **AGPL-3.0-only**. The default `opencsv` binary stays
  MIT/Apache and does not compile this adapter. Building explicitly with
  `--features signal` links AGPL code, so treat that binary as AGPL.

### Build requirement: protoc

libsignal's build scripts generate protobuf code and need `protoc` on the
system. Either:

```sh
# Debian/Ubuntu
sudo apt-get install protobuf-compiler
```

or point `PROTOC` at any protoc ≥ 3.15 binary, e.g. a prebuilt release zip
from <https://github.com/protocolbuffers/protobuf/releases>:

```sh
export PROTOC=/path/to/protoc/bin/protoc
cargo build -p opencsv-cli
```

A C toolchain and OpenSSL development headers are also required (SQLCipher
is built from source).

## Command surface

The transport is driven through the `opencsv` binary (feature `signal`,
on by default). The Signal store directory defaults to
`<wallet-dir>/signal`; override with `--store-dir`.

```text
opencsv signal link [--device-name opencsv] [--store-dir dir]
opencsv signal send --to <self|ACI-uuid|+E164> <consignment-file> [--store-dir dir]
opencsv signal listen [--confirmations 6] [--store-dir dir]
```

## Linking walkthrough (one-time setup)

Run:

```sh
opencsv signal link
```

1. **Terminal** prints:

   ```text
   on your phone: Signal → Settings → Linked Devices → Link New Device, then scan:
   █████████████████████████████████
   ██ ▄▄▄▄▄ █ ▄ ▀▄▀▄██ ██ ▄▄▄▄▄ ██   <- a QR code rendered in block characters
   ...
   provisioning URI (if the QR code is unreadable):
   tsdevice:///?uuid=...&pub_key=...
   waiting for the phone to finish linking…
   ```

2. **Phone**: open Signal → your profile avatar → **Settings** →
   **Linked Devices** → **Link New Device** (the list shows e.g. "Signal
   Desktop" entries if you have any). The camera opens; point it at the
   terminal QR code.

3. **Phone** shows *"Linking new device…"* then *"Device approved!"* —
   after a few seconds **Linked Devices** lists a new entry named
   `opencsv` (or whatever `--device-name` you passed).

4. **Terminal** completes with:

   ```text
   linked as +15551234567 (device id Some(3)), store at <wallet-dir>/signal/signal.db
   ```

Re-running `opencsv signal link` does **not** re-link: it loads the existing
registration and prints `already linked as …`. To start over, delete
`<wallet-dir>/signal/signal.db` *and* remove the device on the phone
(Linked Devices → tap the entry → Unlink).

To undo the link from the phone side at any time: **Settings → Linked
Devices → `opencsv` → Unlink**. The local store then becomes useless and
`listen`/`send` will fail until you delete it and re-link.

## Message format

A consignment is an ordinary Signal direct message:

- **body**: `OpenCSV consignment (<n> bytes)` — a human-visible marker;
- **attachment**: the raw consignment blob as `opencsv-consignment.bin`,
  content type `application/octet-stream` (~50 KB for a typical transfer:
  constant-size recursive proof plus coin openings).

On the receiving side, an attachment counts as a consignment when its file
name is `opencsv-consignment.bin`, **or** when the body starts with the
`OpenCSV consignment` marker and the attachment is opaque binary. This means
you can also send a consignment **from your phone** (attach the `.bin` file
in Note to Self) and `opencsv signal listen` will pick it up — handy for
moving blobs between machines.

Everything rides inside Signal's normal sealed-sender E2E encryption;
Signal servers see ciphertext and roughly the message size, never coin
contents.

## Demo: two devices, one real payment

Plays the full loop over production Signal: mint, deliver the consignment as
an E2E-encrypted attachment, watch the listener verify it into a second
wallet. Use a release build — proving in debug is ~100× slower.

> **Live-tested note (2026-07-31):** a Signal device never receives *its own*
> messages. Note-to-Self sent from the CLI is delivered to your *other*
> devices (your phone shows it), but the sending CLI cannot be its own
> recipient. The receive side of the loop therefore needs a *second* Signal
> account (or a friend), and `--to <that-account-ACI>` — sending to yourself
> with `--to self` only exercises the send leg.

```sh
cargo build --release -p opencsv-cli
OP=target/release/opencsv
D=/tmp/opencsv-signal-demo
CHAIN=$D/chain.log
ALICE="--wallet-dir $D/alice --chain $CHAIN"   # sender / issuer
BOB="--wallet-dir $D/bob --chain $CHAIN"       # recipient

# one-time: link each wallet to ITS OWN Signal account (scan QR with phone)
$OP $ALICE signal link
$OP $BOB signal link        # second account / second phone

$OP $ALICE keygen
ASSET=$($OP $ALICE issuer init --currency USD | awk '{print $2}')
BOB_OWNER=$($OP $BOB keygen | awk '{print $4}')
BOB_ACI=<bob-account-uuid>  # printed by `signal link`, or resolve via contacts
```

Terminal 1 — bob's listener (leave it running):

```sh
$OP $BOB signal listen
# listening for OpenCSV consignments (Ctrl-C to stop)…
# message queue drained; waiting for new messages…
```

Terminal 2 — alice mints to bob and sends over Signal:

```sh
$OP $ALICE mint --asset $ASSET --to $BOB_OWNER --amounts 60,40 --out $D
# anchored at height 0 position 0
# consignment /tmp/opencsv-signal-demo/consignment-h0-p0.bin

$OP $ALICE chain advance 6   # simulate 6 confirmations (paper §4.7 rule 2)

$OP $ALICE signal send --to $BOB_ACI $D/consignment-h0-p0.bin
# syncing pending Signal messages before sending…
# sent .../consignment-h0-p0.bin (47008 bytes) to <bob-aci>
```

Terminal 1 receives and verifies (actual output from the 2026-07-31 live run):

```text
consignment from <alice-aci> (47008 bytes)
VERIFIED 100 <asset-hex>
```

`$OP $BOB balance` then shows `100 <asset-hex>` as two unspent coins.

Sending to a contact works the same way: `--to <their-ACI-uuid>`, or
`--to +15551234567` if they are in your Signal contacts (phone numbers
resolve through the contacts synced from your phone at link time). Their
wallet runs `opencsv signal listen` on their own linked device.

## Storage & security notes

- `<wallet-dir>/signal/signal.db` is a SQLCipher database opened **without**
  a passphrase — i.e. effectively plaintext. It contains the linked device's
  identity key pair, session state, pre-keys, and synced contacts. Anyone
  who copies it can impersonate this linked device until you unlink it from
  the phone. `chmod 600`-grade hygiene is on you; this is prototype-grade.
- The store directory also grows `signal.db-wal`/`signal.db-shm` (SQLite WAL
  files) — treat them the same.
- New identity keys from contacts are trusted on first use
  (`OnNewIdentity::Trust`), like the official clients.
- Unlinking from the phone invalidates the server side; delete the local
  store before re-linking.

## Troubleshooting / known limits

- **First send after linking can be slow or fail** — the client must
  process the sync backlog (sessions, profile keys). `signal send` drains
  the queue first (`syncing pending Signal messages…`, 30 s timeout);
  re-run if it times out.
- **Phone-number recipients** only resolve if the number appears in the
  synced contacts; otherwise pass the ACI uuid. (Proper CDSI lookup is not
  wired up.)
- **Attachment size**: consignments are ~50 KB, far below Signal's 100 MB
  attachment cap — no concern.
- **`could not decrypt a message from …`** — session state drift; usually
  heals after the next message exchange, or after the contact's app resets
  the session.
- **Rate limiting**: Signal may throttle a freshly linked device that
  receives messages in bursts; the demo volumes are far below that.
- presage is pinned to a git revision; upstream force-pushes or server-side
  protocol changes can break old revisions — if linking suddenly fails
  upstream, try bumping the pin.
