//! AIR-native issuer authorization shared by the mint circuits.
//!
//! A mint proves knowledge of a 32-byte issuer seed whose domain-separated
//! Poseidon2 commitment is the `issuer_pk` embedded in [`AssetGenesis`]. The
//! circuit then reproduces [`AssetGenesis::asset_id`] exactly, including its
//! byte-to-field packing, and connects it to the mint's claimed asset id.

use opencsv_core::{AssetGenesis, POSEIDON_ISSUER_KEY_DOMAIN};
use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};

use crate::hash::{connect_digest, hash_felts_base, hash_felts_limbs};
use crate::value::{range_check_value, u64_to_felts, VALUE_LIMBS};
use crate::{DIGEST_ELEMS, EF};

/// Number of field elements in a 32-byte seed packed three bytes per element.
pub(crate) const ISSUER_SECRET_ELEMS: usize = 11;

/// Genesis witness elements: currency (1), terms digest (8), nonce (3).
pub(crate) const ISSUER_GENESIS_ELEMS: usize = 1 + DIGEST_ELEMS + VALUE_LIMBS;

/// Total private witness elements used by issuer authorization.
pub(crate) const ISSUER_AUTH_ELEMS: usize = ISSUER_SECRET_ELEMS + ISSUER_GENESIS_ELEMS;

/// Circuit slices for the issuer authorization witness.
pub(crate) struct IssuerWitness<'a> {
    pub(crate) secret: &'a [ExprId],
    pub(crate) currency: &'a [ExprId],
    pub(crate) terms_hash: &'a [ExprId],
    pub(crate) nonce: &'a [ExprId],
}

/// Split an issuer authorization witness in allocation order.
pub(crate) fn witness_layout(private: &[ExprId]) -> IssuerWitness<'_> {
    assert_eq!(private.len(), ISSUER_AUTH_ELEMS);
    let secret = &private[..ISSUER_SECRET_ELEMS];
    let currency = &private[ISSUER_SECRET_ELEMS..ISSUER_SECRET_ELEMS + 1];
    let terms_start = ISSUER_SECRET_ELEMS + 1;
    let nonce_start = terms_start + DIGEST_ELEMS;
    IssuerWitness {
        secret,
        currency,
        terms_hash: &private[terms_start..nonce_start],
        nonce: &private[nonce_start..nonce_start + VALUE_LIMBS],
    }
}

fn bytes_to_felts(bytes: &[u8]) -> Vec<BabyBear> {
    bytes
        .chunks(3)
        .map(|chunk| {
            let mut packed = [0u8; 4];
            packed[..chunk.len()].copy_from_slice(chunk);
            BabyBear::new(u32::from_le_bytes(packed))
        })
        .collect()
}

/// Native issuer/genesis witness values in circuit allocation order.
pub(crate) fn witness_values(
    secret: &[u8; 32],
    genesis: &AssetGenesis,
) -> [BabyBear; ISSUER_AUTH_ELEMS] {
    let secret = bytes_to_felts(secret);
    debug_assert_eq!(secret.len(), ISSUER_SECRET_ELEMS);
    let currency = bytes_to_felts(&genesis.currency_code);
    debug_assert_eq!(currency.len(), 1);

    let mut values = [BabyBear::default(); ISSUER_AUTH_ELEMS];
    values[..ISSUER_SECRET_ELEMS].copy_from_slice(&secret);
    values[ISSUER_SECRET_ELEMS] = currency[0];
    let terms_start = ISSUER_SECRET_ELEMS + 1;
    values[terms_start..terms_start + DIGEST_ELEMS].copy_from_slice(&genesis.terms_hash.to_elems());
    values[terms_start + DIGEST_ELEMS..].copy_from_slice(&u64_to_felts(genesis.nonce));
    values
}

/// Convert eight canonical BabyBear digest elements, serialized as eight
/// little-endian `u32`s, into the eleven three-byte limbs used by core's
/// `bytes_to_felts` encoding.
fn digest_to_byte_felts(
    builder: &mut CircuitBuilder<EF>,
    digest: &[ExprId; DIGEST_ELEMS],
) -> Result<[ExprId; ISSUER_SECRET_ELEMS], CircuitBuilderError> {
    let mut bytes_bits = Vec::with_capacity(32);
    for &element in digest {
        // Full-width decomposition pins the unique canonical BabyBear value.
        let bits = builder.decompose_to_bits::<BabyBear>(element, 31)?;
        bytes_bits.push(bits[0..8].to_vec());
        bytes_bits.push(bits[8..16].to_vec());
        bytes_bits.push(bits[16..24].to_vec());
        let mut high = bits[24..31].to_vec();
        high.push(ExprId::ZERO);
        bytes_bits.push(high);
    }

    let mut packed = [ExprId::ZERO; ISSUER_SECRET_ELEMS];
    for (i, chunk) in bytes_bits.chunks(3).enumerate() {
        let mut bits = Vec::with_capacity(chunk.len() * 8);
        for byte in chunk {
            bits.extend_from_slice(byte);
        }
        packed[i] = builder.reconstruct_index_from_bits::<BabyBear>(&bits)?;
    }
    Ok(packed)
}

/// Enforce issuer control and reproduce `AssetGenesis::asset_id` in-circuit.
pub(crate) fn enforce_authorization(
    builder: &mut CircuitBuilder<EF>,
    claimed_asset_id: &[ExprId],
    witness: &IssuerWitness<'_>,
) -> Result<(), CircuitBuilderError> {
    assert_eq!(claimed_asset_id.len(), DIGEST_ELEMS);

    // Seeds use ten 24-bit limbs plus one 16-bit limb; the currency is one
    // 24-bit limb and the genesis nonce is the standard u64 limb triple.
    for (i, &limb) in witness.secret.iter().enumerate() {
        builder.decompose_to_bits::<BabyBear>(limb, if i == 10 { 16 } else { 24 })?;
    }
    builder.decompose_to_bits::<BabyBear>(witness.currency[0], 24)?;
    for &element in witness.terms_hash {
        builder.decompose_to_bits::<BabyBear>(element, 31)?;
    }
    range_check_value(
        builder,
        witness.nonce.try_into().expect("genesis nonce has 3 limbs"),
    )?;

    let issuer_pk = hash_felts_base(builder, POSEIDON_ISSUER_KEY_DOMAIN, &[witness.secret])?;
    let issuer_pk_bytes = digest_to_byte_felts(builder, &issuer_pk)?;
    let asset_id = hash_felts_limbs(
        builder,
        "OpenCSV-asset",
        &[
            &issuer_pk_bytes,
            witness.currency,
            witness.terms_hash,
            witness.nonce,
        ],
    )?;
    connect_digest(builder, asset_id, claimed_asset_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencsv_core::{Digest, PoseidonIssuerAuthorization};

    #[test]
    fn native_witness_matches_core_asset_encoding_inputs() {
        let secret = [0x42; 32];
        let genesis = AssetGenesis {
            issuer_pk: PoseidonIssuerAuthorization::public_key(&secret),
            currency_code: *b"USD",
            terms_hash: Digest::from_bytes([0x24; 32]),
            nonce: 7,
        };
        let values = witness_values(&secret, &genesis);
        assert_eq!(&values[..ISSUER_SECRET_ELEMS], bytes_to_felts(&secret));
        assert_eq!(values[ISSUER_SECRET_ELEMS], bytes_to_felts(b"USD")[0]);
        assert_ne!(genesis.asset_id(), Digest::from_bytes([0; 32]));
    }
}
