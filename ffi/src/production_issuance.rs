//! Pure production-issuance authorization validation.
//!
//! The consumer registry and the AIR issuer key do not authorize expansion of
//! production supply. This module defines a distinct, threshold-signed
//! administrative envelope. It intentionally owns no signing key and performs
//! no wallet or network write.

use std::collections::HashSet;

use bdk_wallet::bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::hex::{from_hex, from_hex_array, to_hex};

pub(crate) const PRODUCTION_ISSUANCE_POLICY_FORMAT_VERSION: u32 = 1;
pub(crate) const PRODUCTION_MINT_AUTHORIZATION_FORMAT_VERSION: u32 = 1;

/// Stable failure returned by the secret-free policy and authorization verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    /// Machine-readable rejection reason.
    pub code: &'static str,
    /// Human-readable evidence detail; callers must not branch on this text.
    pub message: String,
}

impl ValidationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionIssuancePolicy {
    pub(crate) format_version: u32,
    pub(crate) policy_version: u64,
    pub(crate) deployment_id: String,
    pub(crate) registry_commitment_sha256: String,
    pub(crate) asset_id: String,
    pub(crate) authority_public_keys: Vec<String>,
    pub(crate) signature_threshold: u8,
    pub(crate) max_authorization_base_units: u64,
    pub(crate) max_cumulative_supply_base_units: u64,
    pub(crate) max_authorization_lifetime_seconds: u64,
    pub(crate) valid_from_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) source_revision: String,
    pub(crate) approval_receipts: Vec<String>,
    pub(crate) commitment_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionAuthoritySignature {
    pub(crate) authority_public_key: String,
    pub(crate) signature_compact: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductionMintAuthorization {
    pub(crate) format_version: u32,
    pub(crate) authorization_id_sha256: String,
    pub(crate) deployment_id: String,
    pub(crate) registry_commitment_sha256: String,
    pub(crate) issuance_policy_commitment_sha256: String,
    pub(crate) asset_id: String,
    pub(crate) to_owner: String,
    pub(crate) amounts: Vec<u64>,
    pub(crate) sequence: u64,
    pub(crate) supply_before_base_units: u64,
    pub(crate) supply_after_base_units: u64,
    pub(crate) not_before_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) approval_receipts: Vec<String>,
    pub(crate) signatures: Vec<ProductionAuthoritySignature>,
}

#[derive(Serialize)]
struct PolicyCommitmentPayload<'a> {
    domain: &'static str,
    format_version: u32,
    policy_version: u64,
    deployment_id: &'a str,
    registry_commitment_sha256: &'a str,
    asset_id: &'a str,
    authority_public_keys: &'a [String],
    signature_threshold: u8,
    max_authorization_base_units: u64,
    max_cumulative_supply_base_units: u64,
    max_authorization_lifetime_seconds: u64,
    valid_from_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    source_revision: &'a str,
    approval_receipts: &'a [String],
}

#[derive(Serialize)]
struct AuthorizationPayload<'a> {
    domain: &'static str,
    format_version: u32,
    deployment_id: &'a str,
    registry_commitment_sha256: &'a str,
    issuance_policy_commitment_sha256: &'a str,
    asset_id: &'a str,
    to_owner: &'a str,
    amounts: &'a [u64],
    sequence: u64,
    supply_before_base_units: u64,
    supply_after_base_units: u64,
    not_before_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    approval_receipts: &'a [String],
}

pub(crate) fn production_issuance_policy_commitment(
    policy: &ProductionIssuancePolicy,
) -> Result<String, ValidationError> {
    let canonical = serde_json::to_vec(&PolicyCommitmentPayload {
        domain: "OpenCSV-production-issuance-policy-v1",
        format_version: policy.format_version,
        policy_version: policy.policy_version,
        deployment_id: &policy.deployment_id,
        registry_commitment_sha256: &policy.registry_commitment_sha256,
        asset_id: &policy.asset_id,
        authority_public_keys: &policy.authority_public_keys,
        signature_threshold: policy.signature_threshold,
        max_authorization_base_units: policy.max_authorization_base_units,
        max_cumulative_supply_base_units: policy.max_cumulative_supply_base_units,
        max_authorization_lifetime_seconds: policy.max_authorization_lifetime_seconds,
        valid_from_unix_seconds: policy.valid_from_unix_seconds,
        expires_at_unix_seconds: policy.expires_at_unix_seconds,
        source_revision: &policy.source_revision,
        approval_receipts: &policy.approval_receipts,
    })
    .map_err(|error| {
        ValidationError::new(
            "invalid_production_issuance_policy",
            format!("encode production issuance policy: {error}"),
        )
    })?;
    Ok(to_hex(&Sha256::digest(canonical)))
}

pub(crate) fn production_mint_authorization_digest(
    authorization: &ProductionMintAuthorization,
) -> Result<[u8; 32], ValidationError> {
    let canonical = serde_json::to_vec(&AuthorizationPayload {
        domain: "OpenCSV-production-mint-authorization-v1",
        format_version: authorization.format_version,
        deployment_id: &authorization.deployment_id,
        registry_commitment_sha256: &authorization.registry_commitment_sha256,
        issuance_policy_commitment_sha256: &authorization.issuance_policy_commitment_sha256,
        asset_id: &authorization.asset_id,
        to_owner: &authorization.to_owner,
        amounts: &authorization.amounts,
        sequence: authorization.sequence,
        supply_before_base_units: authorization.supply_before_base_units,
        supply_after_base_units: authorization.supply_after_base_units,
        not_before_unix_seconds: authorization.not_before_unix_seconds,
        expires_at_unix_seconds: authorization.expires_at_unix_seconds,
        approval_receipts: &authorization.approval_receipts,
    })
    .map_err(|error| {
        ValidationError::new(
            "production_issuance_not_authorized",
            format!("encode production mint authorization: {error}"),
        )
    })?;
    Ok(Sha256::digest(canonical).into())
}

pub(crate) fn validate_production_issuance_policy(
    policy: &ProductionIssuancePolicy,
    expected_deployment_id: &str,
    expected_registry_commitment: &str,
    expected_asset_id: &str,
    expected_policy_commitment: &str,
) -> Result<(), ValidationError> {
    if policy.format_version != PRODUCTION_ISSUANCE_POLICY_FORMAT_VERSION {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "unsupported production issuance policy format version",
        ));
    }
    if policy.policy_version == 0 {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy version must be nonzero",
        ));
    }
    validate_mainnet_deployment(&policy.deployment_id)?;
    if policy.deployment_id != expected_deployment_id {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy belongs to another deployment",
        ));
    }
    validate_hex_32(
        &policy.registry_commitment_sha256,
        "production registry commitment",
    )?;
    if policy.registry_commitment_sha256 != expected_registry_commitment {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy belongs to another registry release",
        ));
    }
    validate_hex_32(&policy.asset_id, "production issuance asset id")?;
    if policy.asset_id != expected_asset_id {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy belongs to another asset",
        ));
    }
    if policy.authority_public_keys.len() < 2 {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance requires at least two distinct authority keys",
        ));
    }
    let mut previous_key: Option<&str> = None;
    let mut keys = HashSet::new();
    for encoded in &policy.authority_public_keys {
        let bytes = from_hex(encoded).map_err(|error| {
            ValidationError::new(
                "invalid_production_issuance_policy",
                format!("production issuance authority key: {error}"),
            )
        })?;
        let key = PublicKey::from_slice(&bytes).map_err(|_| {
            ValidationError::new(
                "invalid_production_issuance_policy",
                "production issuance authority key is not a secp256k1 public key",
            )
        })?;
        if key.serialize().as_slice() != bytes.as_slice() {
            return Err(ValidationError::new(
                "invalid_production_issuance_policy",
                "production issuance authority keys must use compressed canonical encoding",
            ));
        }
        if previous_key.is_some_and(|previous| previous >= encoded.as_str()) {
            return Err(ValidationError::new(
                "invalid_production_issuance_policy",
                "production issuance authority keys must be unique and sorted",
            ));
        }
        previous_key = Some(encoded);
        keys.insert(encoded);
    }
    if usize::from(policy.signature_threshold) < 2
        || usize::from(policy.signature_threshold) > keys.len()
    {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance signature threshold must be between two and the authority-key count",
        ));
    }
    if policy.max_authorization_base_units == 0
        || policy.max_cumulative_supply_base_units == 0
        || policy.max_authorization_base_units > policy.max_cumulative_supply_base_units
    {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance amount limits are inconsistent",
        ));
    }
    if policy.max_authorization_lifetime_seconds == 0 {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance authorization lifetime must be nonzero",
        ));
    }
    if policy.valid_from_unix_seconds >= policy.expires_at_unix_seconds {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy validity window is empty",
        ));
    }
    validate_source_revision(&policy.source_revision)?;
    validate_receipts(
        &policy.approval_receipts,
        "production issuance policy",
        "invalid_production_issuance_policy",
    )?;
    validate_hex_32(
        &policy.commitment_sha256,
        "production issuance policy commitment",
    )?;
    validate_hex_32(
        expected_policy_commitment,
        "expected production issuance policy commitment",
    )?;
    if policy.commitment_sha256 != expected_policy_commitment {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy does not match the commitment authorized by the containing release",
        ));
    }
    if production_issuance_policy_commitment(policy)? != policy.commitment_sha256 {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy commitment does not match its exact payload",
        ));
    }
    Ok(())
}

pub(crate) fn verify_production_mint_authorization(
    policy: &ProductionIssuancePolicy,
    authorization: &ProductionMintAuthorization,
    expected_policy_commitment: &str,
    expected_to_owner: &str,
    expected_amounts: &[u64],
    now_unix_seconds: u64,
) -> Result<[u8; 32], ValidationError> {
    validate_production_issuance_policy(
        policy,
        &authorization.deployment_id,
        &authorization.registry_commitment_sha256,
        &authorization.asset_id,
        expected_policy_commitment,
    )?;
    if authorization.format_version != PRODUCTION_MINT_AUTHORIZATION_FORMAT_VERSION {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "unsupported production mint authorization format version",
        ));
    }
    if authorization.issuance_policy_commitment_sha256 != policy.commitment_sha256 {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "mint authorization belongs to another issuance policy",
        ));
    }
    validate_hex_32(&authorization.to_owner, "production mint recipient owner")?;
    if authorization.to_owner != expected_to_owner || authorization.amounts != expected_amounts {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "mint authorization does not match the exact recipient and amounts",
        ));
    }
    if authorization.amounts.is_empty()
        || authorization.amounts.len() > 2
        || authorization.amounts.contains(&0)
    {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization requires one or two positive outputs",
        ));
    }
    let total = authorization
        .amounts
        .iter()
        .try_fold(0_u64, |sum, amount| sum.checked_add(*amount))
        .ok_or_else(|| {
            ValidationError::new(
                "production_issuance_limit_exceeded",
                "production mint amount overflow",
            )
        })?;
    if total > policy.max_authorization_base_units {
        return Err(ValidationError::new(
            "production_issuance_limit_exceeded",
            "production mint exceeds the per-authorization supply limit",
        ));
    }
    if authorization.sequence == 0 {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization sequence must be nonzero",
        ));
    }
    let expected_supply_after = authorization
        .supply_before_base_units
        .checked_add(total)
        .ok_or_else(|| {
            ValidationError::new(
                "production_issuance_limit_exceeded",
                "production cumulative supply overflow",
            )
        })?;
    if expected_supply_after != authorization.supply_after_base_units {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization supply transition is inconsistent",
        ));
    }
    if authorization.supply_after_base_units > policy.max_cumulative_supply_base_units {
        return Err(ValidationError::new(
            "production_issuance_limit_exceeded",
            "production mint exceeds the cumulative supply limit",
        ));
    }
    if authorization.not_before_unix_seconds < policy.valid_from_unix_seconds
        || authorization.expires_at_unix_seconds > policy.expires_at_unix_seconds
        || authorization.not_before_unix_seconds >= authorization.expires_at_unix_seconds
    {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization is outside the policy validity window",
        ));
    }
    let lifetime = authorization
        .expires_at_unix_seconds
        .saturating_sub(authorization.not_before_unix_seconds);
    if lifetime > policy.max_authorization_lifetime_seconds {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization lifetime exceeds policy",
        ));
    }
    if now_unix_seconds < authorization.not_before_unix_seconds
        || now_unix_seconds > authorization.expires_at_unix_seconds
    {
        return Err(ValidationError::new(
            "production_issuance_authorization_expired",
            "production mint authorization is not currently valid",
        ));
    }
    validate_receipts(
        &authorization.approval_receipts,
        "production mint authorization",
        "production_issuance_not_authorized",
    )?;

    let digest = production_mint_authorization_digest(authorization)?;
    if authorization.authorization_id_sha256 != to_hex(&digest) {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization id does not match its exact payload",
        ));
    }
    if authorization.signatures.len() < usize::from(policy.signature_threshold) {
        return Err(ValidationError::new(
            "production_issuance_not_authorized",
            "production mint authorization lacks the required signature threshold",
        ));
    }
    let permitted = policy
        .authority_public_keys
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut previous_key: Option<&str> = None;
    let secp = Secp256k1::verification_only();
    for signed in &authorization.signatures {
        if previous_key.is_some_and(|previous| previous >= signed.authority_public_key.as_str()) {
            return Err(ValidationError::new(
                "production_issuance_not_authorized",
                "production mint signatures must be unique and sorted by authority key",
            ));
        }
        previous_key = Some(&signed.authority_public_key);
        if !permitted.contains(signed.authority_public_key.as_str()) {
            return Err(ValidationError::new(
                "production_issuance_not_authorized",
                "production mint signature uses an unauthorized key",
            ));
        }
        let public_key_bytes = from_hex(&signed.authority_public_key).map_err(|_| {
            ValidationError::new(
                "production_issuance_not_authorized",
                "production mint authority key is malformed",
            )
        })?;
        let public_key = PublicKey::from_slice(&public_key_bytes).map_err(|_| {
            ValidationError::new(
                "production_issuance_not_authorized",
                "production mint authority key is malformed",
            )
        })?;
        let signature_bytes = from_hex_array::<64>(
            &signed.signature_compact,
            "production mint authority signature",
        )
        .map_err(|error| ValidationError::new("production_issuance_not_authorized", error))?;
        let signature = Signature::from_compact(&signature_bytes).map_err(|_| {
            ValidationError::new(
                "production_issuance_not_authorized",
                "production mint authority signature is malformed",
            )
        })?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Err(ValidationError::new(
                "production_issuance_not_authorized",
                "production mint authority signature is not low-S",
            ));
        }
        secp.verify_ecdsa(&Message::from_digest(digest), &signature, &public_key)
            .map_err(|_| {
                ValidationError::new(
                    "production_issuance_not_authorized",
                    "production mint authority signature does not verify",
                )
            })?;
    }
    Ok(digest)
}

/// Build the canonical commitment for a draft production issuance policy.
///
/// The draft must omit `commitment_sha256`; accepting a caller-supplied value
/// here would make the builder silently bless ambiguous input.
pub fn build_production_issuance_policy_json(
    draft_json: &str,
) -> Result<serde_json::Value, ValidationError> {
    let mut value: serde_json::Value = serde_json::from_str(draft_json).map_err(|error| {
        ValidationError::new(
            "invalid_production_issuance_policy",
            format!("production issuance policy draft JSON: {error}"),
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy draft must be an object",
        )
    })?;
    if object.contains_key("commitment_sha256") {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance policy build input must omit commitment_sha256",
        ));
    }
    object.insert(
        "commitment_sha256".into(),
        serde_json::json!("00".repeat(32)),
    );
    let mut policy =
        serde_json::from_value::<ProductionIssuancePolicy>(value).map_err(|error| {
            ValidationError::new(
                "invalid_production_issuance_policy",
                format!("production issuance policy draft: {error}"),
            )
        })?;
    policy.commitment_sha256 = production_issuance_policy_commitment(&policy)?;
    validate_production_issuance_policy(
        &policy,
        &policy.deployment_id,
        &policy.registry_commitment_sha256,
        &policy.asset_id,
        &policy.commitment_sha256,
    )?;
    serde_json::to_value(policy).map_err(|error| {
        ValidationError::new(
            "json_encode_failed",
            format!("production issuance policy: {error}"),
        )
    })
}

/// Verify a complete policy against the exact release and asset expected by
/// the containing production application.
pub fn verify_production_issuance_policy_json(
    policy_json: &str,
    expected_deployment_id: &str,
    expected_registry_commitment: &str,
    expected_asset_id: &str,
    expected_policy_commitment: &str,
) -> Result<serde_json::Value, ValidationError> {
    let policy =
        serde_json::from_str::<ProductionIssuancePolicy>(policy_json).map_err(|error| {
            ValidationError::new(
                "invalid_production_issuance_policy",
                format!("production issuance policy JSON: {error}"),
            )
        })?;
    validate_production_issuance_policy(
        &policy,
        expected_deployment_id,
        expected_registry_commitment,
        expected_asset_id,
        expected_policy_commitment,
    )?;
    Ok(serde_json::json!({
        "structurally_valid": true,
        "issuance_authorized": false,
        "authorization_note": "policy verification does not create a signed mint authorization or activate mainnet issuance",
        "format_version": policy.format_version,
        "policy_version": policy.policy_version,
        "deployment_id": policy.deployment_id,
        "asset_id": policy.asset_id,
        "signature_threshold": policy.signature_threshold,
        "authority_count": policy.authority_public_keys.len(),
        "max_authorization_base_units": policy.max_authorization_base_units,
        "max_cumulative_supply_base_units": policy.max_cumulative_supply_base_units,
        "commitment_sha256": policy.commitment_sha256,
    }))
}

/// Verify a threshold-signed mint envelope without opening a wallet or
/// possessing any authority secret.
pub fn verify_production_mint_authorization_json(
    policy_json: &str,
    authorization_json: &str,
    expected_deployment_id: &str,
    expected_registry_commitment: &str,
    expected_asset_id: &str,
    expected_policy_commitment: &str,
    expected_to_owner: &str,
    expected_amounts: &[u64],
    now_unix_seconds: u64,
) -> Result<serde_json::Value, ValidationError> {
    let policy =
        serde_json::from_str::<ProductionIssuancePolicy>(policy_json).map_err(|error| {
            ValidationError::new(
                "invalid_production_issuance_policy",
                format!("production issuance policy JSON: {error}"),
            )
        })?;
    let authorization = serde_json::from_str::<ProductionMintAuthorization>(authorization_json)
        .map_err(|error| {
            ValidationError::new(
                "production_issuance_not_authorized",
                format!("production mint authorization JSON: {error}"),
            )
        })?;
    validate_production_issuance_policy(
        &policy,
        expected_deployment_id,
        expected_registry_commitment,
        expected_asset_id,
        expected_policy_commitment,
    )?;
    let digest = verify_production_mint_authorization(
        &policy,
        &authorization,
        expected_policy_commitment,
        expected_to_owner,
        expected_amounts,
        now_unix_seconds,
    )?;
    Ok(serde_json::json!({
        "authorization_valid": true,
        "authorization_id_sha256": to_hex(&digest),
        "policy_commitment_sha256": policy.commitment_sha256,
        "asset_id": authorization.asset_id,
        "sequence": authorization.sequence,
        "supply_before_base_units": authorization.supply_before_base_units,
        "supply_after_base_units": authorization.supply_after_base_units,
        "signature_count": authorization.signatures.len(),
        "signature_threshold": policy.signature_threshold,
        "expires_at_unix_seconds": authorization.expires_at_unix_seconds,
    }))
}

fn validate_mainnet_deployment(deployment_id: &str) -> Result<(), ValidationError> {
    if deployment_id.len() < 8
        || deployment_id.len() > 96
        || !deployment_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || deployment_id.contains("test")
        || deployment_id.contains("signet")
        || deployment_id.contains("regtest")
    {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance deployment is not a valid non-test mainnet namespace",
        ));
    }
    Ok(())
}

fn validate_hex_32(value: &str, label: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            format!("{label} must be 32-byte lowercase hex"),
        ));
    }
    Ok(())
}

fn validate_source_revision(source_revision: &str) -> Result<(), ValidationError> {
    if !matches!(source_revision.len(), 40 | 64)
        || !source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ValidationError::new(
            "invalid_production_issuance_policy",
            "production issuance source revision must be a lowercase Git SHA",
        ));
    }
    Ok(())
}

fn validate_receipts(
    receipts: &[String],
    label: &str,
    code: &'static str,
) -> Result<(), ValidationError> {
    if receipts.is_empty() {
        return Err(ValidationError::new(
            code,
            format!("{label} requires at least one public approval receipt"),
        ));
    }
    let mut unique = HashSet::new();
    for receipt in receipts {
        let parsed = Url::parse(receipt).map_err(|_| {
            ValidationError::new(code, format!("{label} receipt is not a valid URL"))
        })?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() || !unique.insert(receipt) {
            return Err(ValidationError::new(
                code,
                format!("{label} receipts must be unique HTTPS URLs"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::secp256k1::{SecretKey, Signing};

    use super::*;

    fn authority_secret(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn authority_key<C: Signing>(secp: &Secp256k1<C>, byte: u8) -> String {
        to_hex(&PublicKey::from_secret_key(secp, &authority_secret(byte)).serialize())
    }

    fn policy() -> ProductionIssuancePolicy {
        let secp = Secp256k1::signing_only();
        let mut authority_public_keys = vec![
            authority_key(&secp, 3),
            authority_key(&secp, 4),
            authority_key(&secp, 5),
        ];
        authority_public_keys.sort();
        let mut policy = ProductionIssuancePolicy {
            format_version: PRODUCTION_ISSUANCE_POLICY_FORMAT_VERSION,
            policy_version: 1,
            deployment_id: "opencsv-mainnet-v1".into(),
            registry_commitment_sha256: "11".repeat(32),
            asset_id: "22".repeat(32),
            authority_public_keys,
            signature_threshold: 2,
            max_authorization_base_units: 1_000,
            max_cumulative_supply_base_units: 1_000_000,
            max_authorization_lifetime_seconds: 3_600,
            valid_from_unix_seconds: 1_000,
            expires_at_unix_seconds: 100_000,
            source_revision: "ab".repeat(20),
            approval_receipts: vec!["https://github.com/opencsvnet/opencsv/issues/1".into()],
            commitment_sha256: "00".repeat(32),
        };
        policy.commitment_sha256 = production_issuance_policy_commitment(&policy).unwrap();
        policy
    }

    fn authorization(policy: &ProductionIssuancePolicy) -> ProductionMintAuthorization {
        let mut authorization = ProductionMintAuthorization {
            format_version: PRODUCTION_MINT_AUTHORIZATION_FORMAT_VERSION,
            authorization_id_sha256: "00".repeat(32),
            deployment_id: policy.deployment_id.clone(),
            registry_commitment_sha256: policy.registry_commitment_sha256.clone(),
            issuance_policy_commitment_sha256: policy.commitment_sha256.clone(),
            asset_id: policy.asset_id.clone(),
            to_owner: "33".repeat(32),
            amounts: vec![400, 500],
            sequence: 7,
            supply_before_base_units: 100,
            supply_after_base_units: 1_000,
            not_before_unix_seconds: 2_000,
            expires_at_unix_seconds: 3_000,
            approval_receipts: vec!["https://github.com/opencsvnet/opencsv/issues/1#mint-7".into()],
            signatures: Vec::new(),
        };
        let digest = production_mint_authorization_digest(&authorization).unwrap();
        authorization.authorization_id_sha256 = to_hex(&digest);
        let secp = Secp256k1::signing_only();
        for byte in [3_u8, 4] {
            let key = authority_key(&secp, byte);
            let signature = secp.sign_ecdsa(&Message::from_digest(digest), &authority_secret(byte));
            authorization.signatures.push(ProductionAuthoritySignature {
                authority_public_key: key,
                signature_compact: to_hex(&signature.serialize_compact()),
            });
        }
        authorization
            .signatures
            .sort_by(|left, right| left.authority_public_key.cmp(&right.authority_public_key));
        authorization
    }

    #[test]
    fn threshold_authorization_binds_exact_supply_transition() {
        let policy = policy();
        validate_production_issuance_policy(
            &policy,
            &policy.deployment_id,
            &policy.registry_commitment_sha256,
            &policy.asset_id,
            &policy.commitment_sha256,
        )
        .unwrap();
        let authorization = authorization(&policy);
        verify_production_mint_authorization(
            &policy,
            &authorization,
            &policy.commitment_sha256,
            &authorization.to_owner,
            &authorization.amounts,
            2_500,
        )
        .unwrap();

        let mut changed_amount = authorization.clone();
        changed_amount.amounts[0] += 1;
        assert_eq!(
            verify_production_mint_authorization(
                &policy,
                &changed_amount,
                &policy.commitment_sha256,
                &changed_amount.to_owner,
                &changed_amount.amounts,
                2_500,
            )
            .unwrap_err()
            .code,
            "production_issuance_not_authorized"
        );

        let mut changed_supply = authorization.clone();
        changed_supply.supply_after_base_units += 1;
        assert_eq!(
            verify_production_mint_authorization(
                &policy,
                &changed_supply,
                &policy.commitment_sha256,
                &changed_supply.to_owner,
                &changed_supply.amounts,
                2_500,
            )
            .unwrap_err()
            .code,
            "production_issuance_not_authorized"
        );
    }

    #[test]
    fn threshold_and_authority_set_fail_closed() {
        let policy = policy();
        let authorization = authorization(&policy);

        let mut one_signature = authorization.clone();
        one_signature.signatures.pop();
        assert!(verify_production_mint_authorization(
            &policy,
            &one_signature,
            &policy.commitment_sha256,
            &one_signature.to_owner,
            &one_signature.amounts,
            2_500,
        )
        .unwrap_err()
        .message
        .contains("threshold"));

        let mut duplicate_signature = authorization.clone();
        duplicate_signature.signatures[1] = duplicate_signature.signatures[0].clone();
        assert!(verify_production_mint_authorization(
            &policy,
            &duplicate_signature,
            &policy.commitment_sha256,
            &duplicate_signature.to_owner,
            &duplicate_signature.amounts,
            2_500,
        )
        .unwrap_err()
        .message
        .contains("unique and sorted"));

        let mut wrong_key = authorization.clone();
        let secp = Secp256k1::signing_only();
        wrong_key.signatures[1].authority_public_key = authority_key(&secp, 6);
        wrong_key
            .signatures
            .sort_by(|left, right| left.authority_public_key.cmp(&right.authority_public_key));
        assert!(verify_production_mint_authorization(
            &policy,
            &wrong_key,
            &policy.commitment_sha256,
            &wrong_key.to_owner,
            &wrong_key.amounts,
            2_500,
        )
        .unwrap_err()
        .message
        .contains("unauthorized key"));
    }

    #[test]
    fn time_and_supply_caps_fail_closed() {
        let policy = policy();
        let valid_authorization = authorization(&policy);
        assert_eq!(
            verify_production_mint_authorization(
                &policy,
                &valid_authorization,
                &policy.commitment_sha256,
                &valid_authorization.to_owner,
                &valid_authorization.amounts,
                3_001,
            )
            .unwrap_err()
            .code,
            "production_issuance_authorization_expired"
        );

        let mut small_cap = policy.clone();
        small_cap.max_authorization_base_units = 899;
        small_cap.commitment_sha256 = production_issuance_policy_commitment(&small_cap).unwrap();
        let mut over_cap = authorization(&small_cap);
        over_cap.amounts = vec![900];
        over_cap.supply_after_base_units = over_cap.supply_before_base_units + 900;
        let digest = production_mint_authorization_digest(&over_cap).unwrap();
        over_cap.authorization_id_sha256 = to_hex(&digest);
        assert_eq!(
            verify_production_mint_authorization(
                &small_cap,
                &over_cap,
                &small_cap.commitment_sha256,
                &over_cap.to_owner,
                &over_cap.amounts,
                2_500,
            )
            .unwrap_err()
            .code,
            "production_issuance_limit_exceeded"
        );
    }

    #[test]
    fn policy_rejects_self_authenticating_or_ambiguous_key_sets() {
        let mut one_of_one = policy();
        one_of_one.authority_public_keys.truncate(1);
        one_of_one.signature_threshold = 1;
        one_of_one.commitment_sha256 = production_issuance_policy_commitment(&one_of_one).unwrap();
        assert!(validate_production_issuance_policy(
            &one_of_one,
            &one_of_one.deployment_id,
            &one_of_one.registry_commitment_sha256,
            &one_of_one.asset_id,
            &one_of_one.commitment_sha256,
        )
        .unwrap_err()
        .message
        .contains("at least two"));

        let mut duplicate = policy();
        duplicate.authority_public_keys[1] = duplicate.authority_public_keys[0].clone();
        duplicate.commitment_sha256 = production_issuance_policy_commitment(&duplicate).unwrap();
        assert!(validate_production_issuance_policy(
            &duplicate,
            &duplicate.deployment_id,
            &duplicate.registry_commitment_sha256,
            &duplicate.asset_id,
            &duplicate.commitment_sha256,
        )
        .unwrap_err()
        .message
        .contains("unique and sorted"));
    }

    #[test]
    fn secret_free_boundary_requires_external_release_identity() {
        let policy = policy();
        let authorization = authorization(&policy);
        let verified = verify_production_mint_authorization_json(
            &serde_json::to_string(&policy).unwrap(),
            &serde_json::to_string(&authorization).unwrap(),
            &policy.deployment_id,
            &policy.registry_commitment_sha256,
            &policy.asset_id,
            &policy.commitment_sha256,
            &authorization.to_owner,
            &authorization.amounts,
            2_500,
        )
        .unwrap();
        assert_eq!(verified["authorization_valid"], true);
        assert_eq!(verified["signature_count"], 2);

        let error = verify_production_mint_authorization_json(
            &serde_json::to_string(&policy).unwrap(),
            &serde_json::to_string(&authorization).unwrap(),
            &policy.deployment_id,
            &"44".repeat(32),
            &policy.asset_id,
            &policy.commitment_sha256,
            &authorization.to_owner,
            &authorization.amounts,
            2_500,
        )
        .unwrap_err();
        assert!(error.message.contains("another registry release"));

        let error = verify_production_mint_authorization_json(
            &serde_json::to_string(&policy).unwrap(),
            &serde_json::to_string(&authorization).unwrap(),
            &policy.deployment_id,
            &policy.registry_commitment_sha256,
            &policy.asset_id,
            &"55".repeat(32),
            &authorization.to_owner,
            &authorization.amounts,
            2_500,
        )
        .unwrap_err();
        assert!(error.message.contains("containing release"));

        let mut draft = serde_json::to_value(&policy).unwrap();
        draft.as_object_mut().unwrap().remove("commitment_sha256");
        let rebuilt = build_production_issuance_policy_json(&draft.to_string()).unwrap();
        assert_eq!(rebuilt["commitment_sha256"], policy.commitment_sha256);
        assert!(
            build_production_issuance_policy_json(&serde_json::to_string(&policy).unwrap())
                .unwrap_err()
                .message
                .contains("must omit")
        );
    }
}
