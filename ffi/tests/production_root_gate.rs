//! Release-shape regression for the D5 fail-closed boundary.

use opencsv_ffi::account::AccountConfig;

#[test]
fn shipped_config_has_no_root_authentication_test_override() {
    let error = serde_json::from_str::<AccountConfig>(
        r#"{
            "version": 2,
            "network": "signet",
            "esplora_url": "https://mempool.space/signet/api",
            "role": "primary",
            "backup_verified": true,
            "test_assume_authenticated_proof_root": true
        }"#,
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unknown field `test_assume_authenticated_proof_root`"),
        "unexpected config error: {error}"
    );
}
