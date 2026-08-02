//! The no-registration error path of `opencsv_scan_export_snapshot`
//! (its own test process so no other test registers a scan first).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use opencsv_ffi::*;
use serde_json::Value;

fn take(ptr: *mut c_char) -> Value {
    assert!(!ptr.is_null());
    let json = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("UTF-8")
        .to_owned();
    unsafe { opencsv_string_free(ptr) };
    serde_json::from_str(&json).expect("valid JSON")
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

#[test]
fn export_without_registration_errors() {
    let out = take(opencsv_scan_export_snapshot());
    assert_eq!(
        out["error"].as_str().unwrap(),
        "no scan registered; call opencsv_scan_sync first",
        "{out}"
    );
    // scan_check and scan_verify fail the same way.
    let out = take(unsafe {
        opencsv_scan_check(
            1,
            cstr(r#"{"raw_nf_hex":"0000000000000000000000000000000000000000000000000000000000000000","birth":1,"spend":2}"#).as_ptr(),
        )
    });
    assert!(out.get("error").is_some(), "{out}");
}
