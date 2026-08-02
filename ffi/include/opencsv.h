#ifndef OPENCSV_FFI_H
#define OPENCSV_FFI_H

/* C ABI for embedding the OpenCSV wallet in native apps.
 *
 * Every function returns a newly allocated UTF-8 JSON string; free it with
 * opencsv_string_free(). Failures return {"error":"..."}; verification
 * rejections return {"status":"rejected","reason":"..."}.
 *
 * Handles are process-local and not thread-safe per handle: serialize calls
 * on one handle. Proving takes ~0.5-1 s on phone hardware - call all
 * opencsv_prove_* functions from a background queue.
 *
 * See the crate docs (ffi/src/lib.rs) for the persistence and two-phase
 * anchoring model, and ffi/src/snapshot.rs for the anchor-snapshot JSON.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wallet lifecycle. Secrets JSON belongs in the platform keystore. */
char *opencsv_wallet_create(void);
char *opencsv_wallet_open(const char *secrets_json);   /* {"handle":N,"owners":[...]} */
char *opencsv_wallet_close(uint64_t handle);
char *opencsv_wallet_secrets(uint64_t handle);
char *opencsv_wallet_status(uint64_t handle);
char *opencsv_wallet_keygen(uint64_t handle);
char *opencsv_wallet_init_issuer(uint64_t handle, const char *currency);

/* Prove (phase 1): returns {"pending_id":N,"anchor_record_hex":...,
 * "ctx_hex":...,"spends":[...]}. Publish the 64-byte anchor record together
 * with the 32-byte transaction context it is bound to (POST /anchor), then
 * finalize. */
char *opencsv_prove_mint(uint64_t handle, const char *asset_id_hex,
                         const char *to_owner_hex, const char *amounts_json);
char *opencsv_prove_transfer(uint64_t handle, const char *coin_ids_json,
                             const char *to_owner_hex, const char *amounts_json);
char *opencsv_prove_redeem(uint64_t handle, const char *coin_id);

/* Rebind (real chains): rebuild a pending transaction's anchor record under
 * a context reserved by the anchoring service, without re-proving. Returns
 * {"anchor_record_hex":...}, or an error if the context would make the
 * record misparse (reserve another and retry). */
char *opencsv_pending_rebind(uint64_t handle, uint64_t pending_id,
                             const char *ctx_hex);

/* Pending-transaction persistence across the broadcast->finalize window
 * (the crash-loses-consignment gap: openings carry fresh randomness that
 * cannot be re-derived). Export returns {"pending_json":"{...}"} — persist
 * the inner string as-is (sensitive: reveals coin values/owners). Import
 * returns {"pending_id":M} with a fresh id. */
char *opencsv_pending_export(uint64_t handle, uint64_t pending_id);
char *opencsv_pending_import(uint64_t handle, const char *pending_json);

/* Finalize (phase 2): anchor_ref_json = {"txid":"<64hex>","height":N,"position":M}.
 * Returns {"consignment_base64":"...","spends":[...]}. */
char *opencsv_consignment_finalize(uint64_t handle, uint64_t pending_id,
                                   const char *anchor_ref_json);

/* Verify a received consignment blob against an anchor snapshot. */
char *opencsv_verify_consignment(uint64_t handle, const uint8_t *blob,
                                 size_t blob_len,
                                 const char *anchor_snapshot_json,
                                 uint64_t required_confirmations);

/* Trustless anchor point verification over BIP157/158 P2P (opencsv-cbf).
 * config_json = {"network":"signet","peers":["host:port"],"cache_dir":"...",
 * "timeout_ms":30000,"anchor":{"record_hex":"<128hex>","txid_hex":"<64hex>",
 * "height":N,"position":M,"required_confirmations":N}} (anchor member only
 * for verify). Returns {"tip_height":N} or the verdict JSON
 * ({"status":"confirmed"|"not_present"|"insufficient_confirmations",...}). */
char *opencsv_cbf_sync(const char *config_json);
char *opencsv_cbf_verify_anchor(const char *config_json);

/* N-of-M cross-checked accept (paper 4.7.1): build a CrossCheckedChain from
 * request_json = {"backends":[{"type":"bitcoind",...}|{"type":"http","url":...}|
 * {"type":"snapshot","snapshot":{...}}],"consignment_base64":"...",
 * "required_confirmations":N} and run accept over it (read-only; credit via
 * opencsv_verify_consignment). Returns {"status":"verified"|"rejected",...};
 * backend tip disagreement returns {"error":...,"kind":"tip_disagreement",
 * "tips":[...]}. */
char *opencsv_cross_check(uint64_t handle, const char *request_json);

/* Self-scan-first exclusion (opencsv-cbf ScanIndex; the default posture):
 * sync walks BIP158 filters for the protocol marker output and SPV-fetches
 * matching blocks into a persistent occurrence index; check/verify are then
 * fully local. Sync config = {"network","peers":["host:port"],"cache_dir",
 * "timeout_ms","from_height","required_confirmations"}; the sync registers
 * the config for check/verify. Returns {"tip_height","filters_bytes",
 * "blocks_bytes","anchors"}. Check request = {"raw_nf_hex","birth","spend"};
 * returns {"occurrence":{...}|null}. Verify runs accept over a consignment
 * (hex) against the index (read-only). */
char *opencsv_scan_sync(const char *config_json);
char *opencsv_scan_check(uint64_t handle, const char *request_json);
char *opencsv_scan_verify(uint64_t handle, const char *consignment_hex);

/* State queries and spend-state replay. */
char *opencsv_wallet_mark_spent(uint64_t handle, const char *coin_ids_json);
char *opencsv_balance(uint64_t handle);
char *opencsv_audit(const char *asset_id_hex, const char *anchor_snapshot_json);

/* Persistent CBF client: opencsv_cbf_open handshakes once and returns
 * {"client_id":N,"tip_height":N,"handshakes":N}; opencsv_scan_sync_with
 * syncs on the existing connections (no per-call re-dial) with the
 * opencsv_scan_sync result shape plus "handshakes" (constant per client).
 * The one-shot opencsv_scan_sync keeps working (re-dials per call). */
char *opencsv_cbf_open(const char *config_json);
char *opencsv_cbf_close(uint64_t client_id);
char *opencsv_scan_sync_with(uint64_t client_id);

/* Export the registered scan index as an anchor-snapshot JSON — the exact
 * shape opencsv_verify_consignment consumes ({"tip_height":N,"entries":
 * [{"height","position","txid","ctx","record"}]}). The serverless crediting
 * path: every entry was SPV-fetched and PoW-verified by the scan.
 * Local-only; tip_height is the synced tip at call time. Returns
 * {"error":"no scan registered; call opencsv_scan_sync first"} when no sync
 * has registered an index. */
char *opencsv_scan_export_snapshot(void);

/* Free any string returned by this library. */
void opencsv_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* OPENCSV_FFI_H */
