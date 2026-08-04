//! Versioned human/legal terms committed by an OpenCSV asset genesis.
//!
//! A unit code is not an asset identity. [`InstrumentTermsV1`] commits the
//! issuer-facing product definition into [`crate::AssetGenesis::terms_hash`],
//! while the genesis issuer key and mint PCD authorize issuance.

use serde::{Deserialize, Serialize};

use crate::asset::AssetGenesis;
use crate::digest::Digest;
use crate::field::{bytes_to_felts, hash_felts};

/// Current instrument terms version.
pub const INSTRUMENT_TERMS_VERSION: u32 = 1;

/// Maximum decimal precision accepted by the v1 wallet presentation layer.
pub const MAX_INSTRUMENT_DECIMALS: u8 = 18;

/// Display name of the single built-in instrument in the preview wallet.
pub const PREVIEW_USD_DISPLAY_NAME: &str = "OpenCSV USD Preview";

/// Human issuer label for the test-only built-in instrument.
pub const PREVIEW_USD_ISSUER_NAME: &str = "OpenCSV Preview Issuer";

/// Decimal precision chosen to avoid a presentation change if a future,
/// independently authenticated Tether instrument uses its customary scale.
pub const PREVIEW_USD_DECIMALS: u8 = 6;

/// Public terms page for the test-only built-in instrument.
pub const PREVIEW_USD_TERMS_URI: &str = "https://opencsv.net/usd-preview/terms-v1";

/// Return the one instrument definition the preview wallet is allowed to
/// originate. It is deliberately unavailable on mainnet.
pub fn preview_usd_terms(network: &str) -> Result<InstrumentTermsV1, InstrumentError> {
    if !matches!(network, "signet" | "regtest") {
        return Err(InstrumentError::new(
            "OpenCSV USD Preview is available only on signet or regtest",
        ));
    }
    Ok(InstrumentTermsV1 {
        version: INSTRUMENT_TERMS_VERSION,
        network: network.to_owned(),
        display_name: PREVIEW_USD_DISPLAY_NAME.to_owned(),
        unit_code: "USD".to_owned(),
        decimals: PREVIEW_USD_DECIMALS,
        issuer_name: PREVIEW_USD_ISSUER_NAME.to_owned(),
        terms_uri: PREVIEW_USD_TERMS_URI.to_owned(),
        redemption_summary:
            "Test-only units with no monetary value; not redeemable for dollars or USDT.".to_owned(),
        test_only: true,
    })
}

/// Human/legal instrument definition committed by an asset genesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentTermsV1 {
    /// Format version. Must be [`INSTRUMENT_TERMS_VERSION`].
    pub version: u32,
    /// Bitcoin network on which this instrument is issued.
    pub network: String,
    /// Human-readable instrument name, not a unique identifier.
    pub display_name: String,
    /// Three uppercase ASCII letters used to display base units.
    pub unit_code: String,
    /// Number of decimal places between display and protocol base units.
    pub decimals: u8,
    /// Human-readable issuer name. Trust is not inferred from this string.
    pub issuer_name: String,
    /// HTTPS document containing the complete human/legal terms.
    pub terms_uri: String,
    /// Short human-readable description of redemption rights and process.
    pub redemption_summary: String,
    /// Whether this definition explicitly represents a valueless test claim.
    pub test_only: bool,
}

impl InstrumentTermsV1 {
    /// Validate and return the deterministic Poseidon2 commitment stored in
    /// `AssetGenesis::terms_hash`.
    pub fn terms_hash(&self) -> Result<Digest, InstrumentError> {
        self.validate()?;
        let encoded = self.canonical_bytes();
        Ok(hash_felts(
            "OpenCSV-instrument-terms-v1",
            &[&bytes_to_felts(&encoded)],
        ))
    }

    /// Validate the bounded, unambiguous v1 definition.
    pub fn validate(&self) -> Result<(), InstrumentError> {
        if self.version != INSTRUMENT_TERMS_VERSION {
            return Err(InstrumentError::new("unsupported instrument terms version"));
        }
        if !matches!(self.network.as_str(), "mainnet" | "signet" | "regtest") {
            return Err(InstrumentError::new(
                "network must be mainnet, signet, or regtest",
            ));
        }
        validate_text("display name", &self.display_name, 1, 96)?;
        validate_text("issuer name", &self.issuer_name, 1, 160)?;
        validate_text("redemption summary", &self.redemption_summary, 1, 512)?;
        if self.unit_code.len() != 3
            || !self.unit_code.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(InstrumentError::new(
                "unit code must be exactly three uppercase ASCII letters",
            ));
        }
        if self.decimals > MAX_INSTRUMENT_DECIMALS {
            return Err(InstrumentError::new("instrument decimals exceed 18"));
        }
        validate_text("terms URI", &self.terms_uri, 1, 512)?;
        if !self.terms_uri.starts_with("https://") {
            return Err(InstrumentError::new("terms URI must use HTTPS"));
        }
        if self.network == "mainnet" && self.test_only {
            return Err(InstrumentError::new(
                "a mainnet instrument cannot be marked test-only",
            ));
        }
        if self.network != "mainnet" && !self.test_only {
            return Err(InstrumentError::new(
                "signet and regtest instruments must be marked test-only",
            ));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_be_bytes());
        push_text(&mut bytes, &self.network);
        push_text(&mut bytes, &self.display_name);
        push_text(&mut bytes, &self.unit_code);
        bytes.push(self.decimals);
        push_text(&mut bytes, &self.issuer_name);
        push_text(&mut bytes, &self.terms_uri);
        push_text(&mut bytes, &self.redemption_summary);
        bytes.push(u8::from(self.test_only));
        bytes
    }
}

/// A complete v1 manifest: committed terms plus their exact asset genesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentManifestV1 {
    /// Terms committed by the genesis.
    pub terms: InstrumentTermsV1,
    /// Protocol genesis whose asset id uniquely identifies this instrument.
    pub genesis: AssetGenesis,
}

impl InstrumentManifestV1 {
    /// Validate that the human definition is exactly the one committed by
    /// the protocol genesis.
    pub fn validate(&self) -> Result<(), InstrumentError> {
        let expected_code: [u8; 3] = self
            .terms
            .unit_code
            .as_bytes()
            .try_into()
            .map_err(|_| InstrumentError::new("unit code is not three bytes"))?;
        if self.genesis.currency_code != expected_code {
            return Err(InstrumentError::new(
                "manifest unit code does not match asset genesis",
            ));
        }
        if self.genesis.terms_hash != self.terms.terms_hash()? {
            return Err(InstrumentError::new(
                "manifest terms do not match the genesis terms hash",
            ));
        }
        Ok(())
    }
}

/// Instrument definition validation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstrumentError {
    message: String,
}

impl InstrumentError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for InstrumentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for InstrumentError {}

fn validate_text(
    field: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), InstrumentError> {
    let length = value.as_bytes().len();
    if !(minimum..=maximum).contains(&length) {
        return Err(InstrumentError::new(format!(
            "{field} must be {minimum}..={maximum} UTF-8 bytes"
        )));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(InstrumentError::new(format!(
            "{field} must not contain surrounding whitespace or control characters"
        )));
    }
    Ok(())
}

fn push_text(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> InstrumentTermsV1 {
        InstrumentTermsV1 {
            version: 1,
            network: "signet".into(),
            display_name: "OpenCSV test dollars".into(),
            unit_code: "TST".into(),
            decimals: 2,
            issuer_name: "OpenCSV test issuer".into(),
            terms_uri: "https://opencsv.net/test-terms/v1".into(),
            redemption_summary: "Test-only units with no monetary value.".into(),
            test_only: true,
        }
    }

    #[test]
    fn terms_hash_is_deterministic_and_field_sensitive() {
        let original = terms();
        let first = original.terms_hash().unwrap();
        assert_eq!(first, original.terms_hash().unwrap());
        let mut changed = original;
        changed.issuer_name.push_str(" 2");
        assert_ne!(first, changed.terms_hash().unwrap());
    }

    #[test]
    fn manifest_rejects_metadata_not_committed_by_genesis() {
        let terms = terms();
        let genesis = AssetGenesis {
            issuer_pk: [3; 32],
            currency_code: *b"TST",
            terms_hash: terms.terms_hash().unwrap(),
            nonce: 1,
        };
        let manifest = InstrumentManifestV1 {
            terms: terms.clone(),
            genesis,
        };
        assert!(manifest.validate().is_ok());

        let mut dishonest = manifest;
        dishonest.terms.display_name = "Different claim".into();
        assert!(dishonest.validate().is_err());
    }

    #[test]
    fn test_networks_cannot_imply_production_backing() {
        let mut invalid = terms();
        invalid.test_only = false;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn preview_usd_is_fixed_and_never_mainnet() {
        let terms = preview_usd_terms("signet").unwrap();
        assert_eq!(terms.unit_code, "USD");
        assert_eq!(terms.decimals, 6);
        assert!(terms.test_only);
        assert!(terms.redemption_summary.contains("not redeemable"));
        assert!(preview_usd_terms("mainnet").is_err());
    }
}
