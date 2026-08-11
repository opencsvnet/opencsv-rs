//! u64 value gadget (paper §4.4–4.5: `0 ≤ v < 2^64`).
//!
//! Values are represented as three little-endian limbs (24, 24, 16 bits),
//! matching [`opencsv-core`]'s `u64_to_felts` encoding exactly. The limb
//! widths are range-checked by binary decomposition, so a checked limb
//! triple encodes a unique value in `[0, 2^64)`.
//!
//! Sum constraints (`Σ lhs = Σ rhs`) propagate carries limb by limb and pin
//! the final carry to zero, so equality holds over the integers — not just
//! mod `p` — and any sum overflowing `u64` fails proving. All carry/balance
//! failures surface at witness generation (slot conflicts), never as STARK
//! constraint failures.

use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::PrimeCharacteristicRing;

use crate::EF;

/// Number of limbs per value (mirrors `opencsv-core`'s `u64_to_felts`).
pub const VALUE_LIMBS: usize = 3;

/// Bit width of each limb: two 24-bit limbs plus a 16-bit top limb, so a
/// range-checked triple encodes exactly `0 ≤ v < 2^64`.
pub(crate) const LIMB_BITS: [usize; VALUE_LIMBS] = [24, 24, 16];

/// Encode a `u64` as three little-endian limbs (24, 24, 16 bits) — identical
/// to `opencsv-core`'s `u64_to_felts`.
pub fn u64_to_felts(v: u64) -> [BabyBear; VALUE_LIMBS] {
    [
        BabyBear::new((v & 0xFF_FFFF) as u32),
        BabyBear::new(((v >> 24) & 0xFF_FFFF) as u32),
        BabyBear::new((v >> 48) as u32),
    ]
}

/// Range-check each limb to its bit width via binary decomposition, so the
/// triple encodes a unique value in `[0, 2^64)`. A limb outside its width
/// fails at witness generation (the decomposition hint truncates to
/// `n_bits`, so the reconstruction conflicts with the limb's slot).
pub(crate) fn range_check_value(
    builder: &mut CircuitBuilder<EF>,
    limbs: &[ExprId; VALUE_LIMBS],
) -> Result<(), CircuitBuilderError> {
    for (i, &limb) in limbs.iter().enumerate() {
        builder.decompose_to_bits::<BabyBear>(limb, LIMB_BITS[i])?;
    }
    Ok(())
}

/// Enforce `lhs[0] + lhs[1] = rhs[0] + rhs[1]` with exact u64 arithmetic.
///
/// Per limb `i` (with carry `c_0 = 0`):
///
/// ```text
/// lhs[0][i] + lhs[1][i] + c_i = rhs[0][i] + rhs[1][i] + 2^24 · c_{i+1}
/// ```
///
/// where each `c_{i+1}` is constrained to `{-1, 0, 1}`. Negative carry is a
/// real borrow: for example, the low limbs of `25_000_000 = 10_000_000 +
/// 15_000_000` differ by exactly `-2^24`. The final carry is pinned to zero,
/// so a sum that would overflow `u64` still fails proving.
///
/// Soundness: all limbs must already be range-checked
/// ([`range_check_value`]). Then every per-limb difference `t` lies in
/// `(-2^26, 2^26) ⊂ (-p/2, p/2)`, so the field equality `t = 2^24 · c` with
/// `c ∈ {-1, 0, 1}` (the set enforced by `c(c-1)(c+1) = 0` below; `-1` is a
/// borrow, as above) holds in BabyBear iff it holds over the integers:
/// `|t - 2^24 · c| < 2^26 + 2^24 < p`, so no wrap-around can fake balance.
/// (Using a uniform radix `2^24` on the 16-bit top limb is deliberate: it
/// treats values as 72-bit for the carry arithmetic, which is still exact,
/// and any top-limb overflow yields a non-zero final carry.)
pub(crate) fn enforce_sum_eq(
    builder: &mut CircuitBuilder<EF>,
    lhs: [&[ExprId; VALUE_LIMBS]; 2],
    rhs: [&[ExprId; VALUE_LIMBS]; 2],
) -> Result<(), CircuitBuilderError> {
    let radix = builder.alloc_const(EF::from(BabyBear::new(1 << 24)), "radix");
    let one = builder.define_const(EF::ONE);
    let mut carry: Option<ExprId> = None;
    for i in 0..VALUE_LIMBS {
        let mut t = builder.add(lhs[0][i], lhs[1][i]);
        if let Some(c) = carry {
            t = builder.add(t, c);
        }
        t = builder.sub(t, rhs[0][i]);
        t = builder.sub(t, rhs[1][i]);
        // The difference must be exactly `2^24 · carry`. Both sides contain
        // two checked limbs, so the only valid carry/borrow values are
        // {-1, 0, 1}. Enforce membership with c(c-1)(c+1) = 0.
        let next = builder.div(t, radix);
        let next_minus_one = builder.sub(next, one);
        let next_plus_one = builder.add(next, one);
        let roots = builder.mul(next, next_minus_one);
        let roots = builder.mul(roots, next_plus_one);
        builder.assert_zero(roots);
        carry = Some(next);
    }
    // No overflow past the top limb.
    builder.assert_zero(carry.expect("three limbs processed"));
    Ok(())
}
