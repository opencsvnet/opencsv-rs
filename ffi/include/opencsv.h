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
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Signal-native account wallet. The primary passes a random 32-byte account
 * root plus a distinct 32-byte device binding from a non-migratable
 * ThisDeviceOnly keystore item. Fresh setup creates both atomically. A primary
 * whose root exists after restore but whose binding is missing passes NULL/0
 * for the binding and opens read/export-only. That state is sticky; supplying
 * a new binding later cannot arm the database. Linked devices pass NULL/0 for
 * both plus watch descriptors in config_json. The public binding commitment
 * returned in status/checkpoints must accompany the account root during
 * recovery. No secret key, WIF, UTXO, change address, or coin-selection result
 * is accepted in JSON. */
char *opencsv_account_open(const char *config_json,
                           const uint8_t *account_key,
                           size_t account_key_len,
                           const uint8_t *device_binding_key,
                           size_t device_binding_key_len,
                           const char *database_path);
char *opencsv_account_close(uint64_t handle);
char *opencsv_account_status(uint64_t handle);
char *opencsv_account_sync(uint64_t handle);
char *opencsv_account_prepare_batch_reserves(uint64_t handle,
                                             uint8_t participant_count,
                                             const char *fee_policy_json);
char *opencsv_account_observe_batch_reserves(
    uint64_t handle,
    const char *maintenance_id,
    const uint8_t *raw_transaction,
    size_t raw_transaction_len,
    const char *observations_json);
char *opencsv_account_resume_batch_reserves(uint64_t handle,
                                            const char *maintenance_id);
char *opencsv_account_fee_bump_batch_reserves(
    uint64_t handle,
    const char *maintenance_id,
    uint64_t target_sat_per_vb);
char *opencsv_account_refresh_batch_reserves(uint64_t handle,
                                             const char *maintenance_id);
char *opencsv_account_set_backup_state(uint64_t handle, bool verified,
                                       uint32_t checkpoint_version);
char *opencsv_account_checkpoint(uint64_t handle);
char *opencsv_account_restore_checkpoint(uint64_t handle,
                                         const char *checkpoint_json);
#if defined(OPENCSV_TEST_WALLET_RECOVERY)
/* Present only in DEBUG signet/regtest builds compiled with the Rust
 * test-wallet-recovery feature. The caller supplies a fresh 32-byte
 * ThisDeviceOnly binding; no account root crosses this boundary. */
char *opencsv_account_rebind_test_device(
    uint64_t handle,
    const uint8_t *device_binding_key,
    size_t device_binding_key_len);
#endif
char *opencsv_account_verify_consignment(uint64_t handle,
                                         const uint8_t *blob,
                                         size_t blob_len,
                                         const char *snapshot_json);
char *opencsv_account_inspect_consignment(uint64_t handle,
                                          const uint8_t *blob,
                                          size_t blob_len);
char *opencsv_account_verify_consignment_unconfirmed(
    uint64_t handle,
    const uint8_t *blob,
    size_t blob_len,
    const char *snapshot_json);
char *opencsv_account_verify_consignment_unconfirmed_observed(
    uint64_t handle,
    const uint8_t *blob,
    size_t blob_len,
    const char *snapshot_json,
    const uint8_t *raw_transaction,
    size_t raw_transaction_len,
    const char *observations_json);
char *opencsv_operation_observe_unconfirmed(
    uint64_t handle,
    const char *operation_id,
    const uint8_t *raw_transaction,
    size_t raw_transaction_len,
    const char *observations_json);
char *opencsv_account_scan_verify(uint64_t handle,
                                  const char *consignment_hex);
char *opencsv_account_cross_check(uint64_t handle,
                                  const char *request_json);
/* Signal is an owner wallet, not an issuer. This production header exposes
 * no asset-definition, issuer-key, or mint-preparation API. */
/* request_json is exactly
 * {"asset_id":"<hex>","to_owner":"<hex>","amount":N}. Planning is the
 * fast durable UI boundary; proof generation resumes the same operation in
 * background. Swift never supplies OpenCSV coins, Bitcoin inputs, or change. */
char *opencsv_transfer_plan(uint64_t handle, const char *request_json);
/* Wallet-owned two-second collection window. Add Recipient succeeds only
 * while membership can still be durably guaranteed. Freeze routes a
 * one-member timeout to the solo path and 2+ members to batching-v2. */
char *opencsv_transfer_batch_plan(uint64_t handle,
                                  const char *request_json);
char *opencsv_transfer_batch_add_recipient(uint64_t handle,
                                           const char *batch_local_id,
                                           const char *request_json);
char *opencsv_send_batch_freeze(uint64_t handle,
                                const char *batch_local_id);
char *opencsv_send_batch_status(uint64_t handle,
                                const char *batch_local_id);
char *opencsv_send_batch_cancel(uint64_t handle,
                                const char *batch_local_id);
char *opencsv_send_batch_prove(uint64_t handle,
                               const char *batch_local_id);
char *opencsv_send_batch_ack_backup(uint64_t handle,
                                    const char *batch_local_id,
                                    const char *checkpoint_hash);
char *opencsv_send_batch_sign_and_broadcast(uint64_t handle,
                                            const char *batch_local_id);
char *opencsv_send_batch_observe_unconfirmed(
    uint64_t handle,
    const char *batch_local_id,
    const uint8_t *raw_transaction,
    size_t raw_transaction_len,
    const char *observations_json);
char *opencsv_send_batch_resume(uint64_t handle,
                                const char *batch_local_id);
char *opencsv_send_batch_fee_bump(uint64_t handle,
                                  const char *batch_local_id,
                                  uint64_t target_sat_per_vb);
char *opencsv_send_batch_refresh_spv(uint64_t handle,
                                     const char *batch_local_id);
/* A transient mandatory-chain outage returns retryable=true and preserves the
 * exact unsigned operation/batch and fee locks. A verified conflict returns
 * retryable=false and closes the complete unsigned batch. */
char *opencsv_operation_prove(uint64_t handle, const char *operation_id);
/* Compatibility one-shot for non-interactive callers. */
char *opencsv_transfer_prepare(uint64_t handle, const char *request_json);
char *opencsv_operation_ack_backup(uint64_t handle,
                                   const char *operation_id,
                                   const char *checkpoint_hash);
char *opencsv_operation_sign_and_broadcast(uint64_t handle,
                                           const char *operation_id,
                                           const char *fee_policy_json);
char *opencsv_operation_status(uint64_t handle, const char *operation_id);
char *opencsv_operation_refresh_spv(uint64_t handle,
                                    const char *operation_id);
char *opencsv_operation_resume(uint64_t handle, const char *operation_id);
char *opencsv_operation_cancel(uint64_t handle, const char *operation_id);
char *opencsv_fee_bump(uint64_t handle, const char *operation_id,
                       uint64_t target_sat_per_vb);
char *opencsv_operation_mark_delivered(uint64_t handle,
                                       const char *operation_id,
                                       const char *delivery_nonce);

/* Wallet lifecycle. Secrets JSON belongs in the platform keystore. */
char *opencsv_wallet_create(void);
char *opencsv_wallet_open(const char *secrets_json);   /* {"handle":N,"owners":[...]} */
char *opencsv_wallet_close(uint64_t handle);
char *opencsv_wallet_secrets(uint64_t handle);
char *opencsv_wallet_status(uint64_t handle);
char *opencsv_wallet_keygen(uint64_t handle);

/* Prove (phase 1): returns {"pending_id":N,"anchor_record_hex":...,
 * "ctx_hex":...,"spends":[...]}. Publish the 64-byte anchor record together
 * with the 32-byte transaction context it is bound to (POST /anchor), then
 * finalize. */
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
