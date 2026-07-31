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

/* Prove (phase 1): returns {"pending_id":N,"anchor_record_hex":...,"spends":[...]}.
 * Publish the 64-byte anchor record, then finalize. */
char *opencsv_prove_mint(uint64_t handle, const char *asset_id_hex,
                         const char *to_owner_hex, const char *amounts_json);
char *opencsv_prove_transfer(uint64_t handle, const char *coin_ids_json,
                             const char *to_owner_hex, const char *amounts_json);
char *opencsv_prove_redeem(uint64_t handle, const char *coin_id);

/* Finalize (phase 2): anchor_ref_json = {"txid":"<64hex>","height":N,"position":M}.
 * Returns {"consignment_base64":"...","spends":[...]}. */
char *opencsv_consignment_finalize(uint64_t handle, uint64_t pending_id,
                                   const char *anchor_ref_json);

/* Verify a received consignment blob against an anchor snapshot. */
char *opencsv_verify_consignment(uint64_t handle, const uint8_t *blob,
                                 size_t blob_len,
                                 const char *anchor_snapshot_json,
                                 uint64_t required_confirmations);

/* State queries and spend-state replay. */
char *opencsv_wallet_mark_spent(uint64_t handle, const char *coin_ids_json);
char *opencsv_balance(uint64_t handle);
char *opencsv_audit(const char *asset_id_hex, const char *anchor_snapshot_json);

/* Free any string returned by this library. */
void opencsv_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* OPENCSV_FFI_H */
