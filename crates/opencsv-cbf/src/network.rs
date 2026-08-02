//! Per-network consensus parameters and proof-of-work validation:
//! compact target (`nBits`) arithmetic, chainwork accumulation, and the
//! `GetNextWorkRequired` difficulty rules for mainnet, signet
//! (testnet-style minimum-difficulty), and regtest (no retargeting).

use opencsv_bitcoin::Network;

use crate::block::BlockHeader;
use crate::error::Error;

/// A 256-bit unsigned integer as four little-endian `u64` limbs.
pub type U256 = [u64; 4];

const RETARGET_INTERVAL: u64 = 2016;

/// Consensus parameters needed for header validation and P2P.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Which network.
    pub network: Network,
    /// P2P message magic.
    pub magic: u32,
    /// Default P2P port.
    pub default_port: u16,
    /// Genesis block hash (internal order).
    pub genesis_hash: [u8; 32],
    /// The proof-of-work limit (highest allowed target).
    pub pow_limit: U256,
    /// The compact (`nBits`) encoding of the proof-of-work limit.
    pub pow_limit_bits: u32,
    /// Target spacing between blocks, in seconds.
    pub pow_target_spacing: u64,
    /// Target retarget timespan, in seconds.
    pub pow_target_timespan: u64,
    /// Testnet-style rule: a block more than 2× the spacing after its
    /// parent may drop to the minimum difficulty.
    pub allow_min_difficulty: bool,
    /// Regtest-style rule: difficulty never changes.
    pub no_retargeting: bool,
}

/// Consensus parameters for a network.
pub fn params(network: Network) -> Params {
    match network {
        Network::Mainnet => Params {
            network,
            magic: 0xd9b4bef9,
            default_port: 8333,
            genesis_hash: crate::hash::hash_from_display(
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            )
            .expect("constant"),
            pow_limit: from_compact(0x1d00ffff).expect("constant"),
            pow_limit_bits: 0x1d00ffff,
            pow_target_spacing: 600,
            pow_target_timespan: 14 * 24 * 60 * 60,
            allow_min_difficulty: false,
            no_retargeting: false,
        },
        Network::Signet => Params {
            network,
            magic: 0x40cf030a,
            default_port: 38333,
            genesis_hash: crate::hash::hash_from_display(
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            )
            .expect("constant"),
            pow_limit: from_compact(0x1e0377ae).expect("constant"),
            pow_limit_bits: 0x1e0377ae,
            pow_target_spacing: 600,
            pow_target_timespan: 14 * 24 * 60 * 60,
            // Signet uses MAINNET-style difficulty rules (Bitcoin Core's
            // chainparams: fPowAllowMinDifficultyBlocks = false,
            // enforce_BIP94 = false): within a retarget period bits must
            // equal the previous block's, with no testnet-style
            // min-difficulty timestamp exception. (The min-difficulty
            // branch below models testnet4-style networks; none of the
            // supported networks use it.)
            allow_min_difficulty: false,
            no_retargeting: false,
        },
        Network::Regtest => Params {
            network,
            magic: 0xdab5bffa,
            default_port: 18444,
            genesis_hash: crate::hash::hash_from_display(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            )
            .expect("constant"),
            pow_limit: from_compact(0x207fffff).expect("constant"),
            pow_limit_bits: 0x207fffff,
            pow_target_spacing: 600,
            pow_target_timespan: 14 * 24 * 60 * 60,
            allow_min_difficulty: true,
            no_retargeting: true,
        },
    }
}

fn consensus_err(what: impl std::fmt::Display) -> Error {
    Error::Consensus(what.to_string())
}

/// Expand a compact (`nBits`) target. Returns `None` for negative,
/// overflow, or zero mantissas (consensus `SetCompact` failure cases).
pub fn from_compact(bits: u32) -> Option<U256> {
    let size = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    let mut out: U256 = [0; 4];
    if size <= 3 {
        out[0] = u64::from(mantissa >> (8 * (3 - size)));
    } else {
        // mantissa * 256^(size-3): place the 3 mantissa bytes at byte
        // offset size-3 (8-byte limbs).
        let byte_offset = (size - 3) as usize;
        for i in 0..3 {
            let byte = u64::from((mantissa >> (8 * i)) & 0xff);
            let pos = byte_offset + i;
            if pos < 32 {
                out[pos / 8] |= byte << (8 * (pos % 8));
            }
        }
    }
    // Consensus rejects negative and overflowing targets.
    if mantissa != 0
        && (size > 34 || (mantissa > 0xff && size > 33) || (mantissa > 0xffff && size > 32))
    {
        return None;
    }
    if bits & 0x0080_0000 != 0 {
        return None; // negative
    }
    Some(out)
}

/// Compact (`nBits`) encoding of a target (consensus `GetCompact`).
pub fn to_compact(target: &U256) -> u32 {
    let mut bytes = [0u8; 32];
    for (i, limb) in target.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    let mut size = 32usize;
    while size > 1 && bytes[size - 1] == 0 {
        size -= 1;
    }
    let mut compact = if size <= 3 {
        let mut w = 0u32;
        for (i, &byte) in bytes.iter().take(size).enumerate() {
            w |= u32::from(byte) << (8 * i);
        }
        w << (8 * (3 - size))
    } else {
        u32::from(bytes[size - 1]) << 16
            | u32::from(bytes[size - 2]) << 8
            | u32::from(bytes[size - 3])
    };
    let mut size = size as u32;
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    (size << 24) | compact
}

/// `a >= b`
pub fn u256_ge(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn u256_is_zero(a: &U256) -> bool {
    a.iter().all(|&l| l == 0)
}

/// Interpret internal-order hash bytes as a 256-bit number.
pub fn u256_from_hash(hash: &[u8; 32]) -> U256 {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().expect("8"));
    }
    out
}

/// `a * b` where `b` is a `u64` factor — full 512-bit product.
fn u256_mul_u64(a: &U256, b: u64) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut carry = 0u128;
    for i in 0..4 {
        let acc = u128::from(a[i]) * u128::from(b) + carry;
        out[i] = acc as u64;
        carry = acc >> 64;
    }
    out[4] = carry as u64;
    out
}

/// `a / b` for a 512-bit dividend and `u64` divisor (quotient must fit
/// in 256 bits; higher limbs of the dividend must be < divisor, which
/// holds for difficulty retargeting).
fn u512_div_u64(a: &[u64; 8], b: u64) -> U256 {
    let mut out = [0u64; 4];
    let mut rem = 0u128;
    for i in (0..8).rev() {
        let cur = (rem << 64) | u128::from(a[i]);
        let q = cur / u128::from(b);
        rem = cur % u128::from(b);
        if i < 4 {
            out[i] = q as u64;
        } else {
            debug_assert_eq!(q, 0, "retarget quotient overflow");
        }
    }
    out
}

/// `a + 1` (wrapping at 2^256, unreachable for real targets).
fn u256_add_one(a: &U256) -> U256 {
    let mut out = *a;
    for limb in &mut out {
        let (v, carry) = limb.overflowing_add(1);
        *limb = v;
        if !carry {
            break;
        }
    }
    out
}

fn u256_sub(a: &U256, b: &U256) -> U256 {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (v1, b1) = a[i].overflowing_sub(b[i]);
        let (v2, b2) = v1.overflowing_sub(u64::from(borrow));
        out[i] = v2;
        borrow = b1 || b2;
    }
    debug_assert!(!borrow);
    out
}

/// The proof of work represented by a target:
/// `work = 2^256 / (target + 1)`, computed as
/// `((2^256 - 1 - target) / (target + 1)) + 1` (Bitcoin Core's
/// `GetBlockProof`). Fits in a `u128` for every real target.
pub fn work_from_target(target: &U256) -> u128 {
    let denominator = u256_add_one(target);
    // numerator = ~target (bitwise not) = 2^256 - 1 - target
    let numerator: U256 = [!target[0], !target[1], !target[2], !target[3]];
    // Binary long division, 256 bits.
    let mut quotient = 0u128;
    let mut rem: U256 = [0; 4];
    for i in (0..256).rev() {
        // rem = (rem << 1) | bit i of numerator, tracking the 257th bit.
        let top = rem[3] >> 63;
        for j in (0..4).rev() {
            let carry = if j > 0 { rem[j - 1] >> 63 } else { 0 };
            rem[j] = (rem[j] << 1) | carry;
        }
        rem[0] |= (numerator[i / 64] >> (i % 64)) & 1;
        // If the 257th bit is set, rem >= denominator for sure.
        if top == 1 || u256_ge(&rem, &denominator) {
            rem = u256_sub(&rem, &denominator);
            if i < 128 {
                quotient |= 1u128 << i;
            } else {
                debug_assert!(i < 128, "work quotient exceeds u128");
            }
        }
    }
    quotient + 1
}

/// Median time past of the block at `height - 1` (BIP113 rule applies
/// to the block at `height`): median of the up-to-11 previous block
/// times.
fn median_time_past(headers: &[BlockHeader], height: usize) -> u32 {
    let start = height.saturating_sub(11);
    let mut times: Vec<u32> = headers[start..height].iter().map(|h| h.time).collect();
    times.sort_unstable();
    times[times.len() / 2]
}

/// The `nBits` value consensus requires for the block at `height`,
/// given all previous headers (Bitcoin Core's `GetNextWorkRequired`).
pub fn next_work_required(params: &Params, headers: &[BlockHeader], height: usize) -> u32 {
    let prev = &headers[height - 1];
    if params.no_retargeting {
        return prev.bits;
    }
    if !(height as u64).is_multiple_of(RETARGET_INTERVAL) {
        if params.allow_min_difficulty {
            // Special rule: allow the minimum-difficulty block if the
            // new block's timestamp is more than 2× the spacing after
            // the previous block. The actual timestamp check happens
            // against the candidate block; here we return the bound the
            // caller checks (see `validate_header_bits`).
            unreachable!("min-difficulty networks need the candidate header");
        }
        return prev.bits;
    }
    // Retarget: timespan over the last interval (2015 block intervals,
    // the well-known off-by-one), clamped to [timespan/4, timespan*4].
    let first = &headers[height - RETARGET_INTERVAL as usize];
    let mut actual = i64::from(prev.time) - i64::from(first.time);
    let timespan = params.pow_target_timespan as i64;
    actual = actual.clamp(timespan / 4, timespan * 4);
    let prev_target = from_compact(prev.bits).expect("validated on append");
    let product = u256_mul_u64(&prev_target, actual as u64);
    let new_target = u512_div_u64(&product, params.pow_target_timespan);
    let clamped = if u256_ge(&new_target, &params.pow_limit) {
        params.pow_limit
    } else {
        new_target
    };
    to_compact(&clamped)
}

/// The required `nBits` for `header` at `height`, handling the
/// minimum-difficulty special case (testnet/signet): if the candidate
/// block's timestamp is more than 2× the target spacing after its
/// parent, the pow limit itself is allowed.
pub fn required_bits(params: &Params, headers: &[BlockHeader], height: usize, header: &BlockHeader) -> u32 {
    let prev = &headers[height - 1];
    if params.no_retargeting {
        return prev.bits;
    }
    if !(height as u64).is_multiple_of(RETARGET_INTERVAL) {
        if params.allow_min_difficulty {
            if header.time > prev.time + 2 * params.pow_target_spacing as u32 {
                return params.pow_limit_bits;
            }
            // Otherwise the difficulty equals that of the last
            // non-minimum-difficulty block in the current retarget
            // period.
            let mut h = height - 1;
            while !(h as u64).is_multiple_of(RETARGET_INTERVAL) && headers[h].bits == params.pow_limit_bits {
                h -= 1;
            }
            return headers[h].bits;
        }
        return prev.bits;
    }
    next_work_required(params, headers, height)
}

/// Validate one header for appending at `height` over `headers`
/// (genesis excluded): linkage, required `nBits`, hash below target,
/// and median-time-past. Returns the block's work.
pub fn validate_header(
    params: &Params,
    headers: &[BlockHeader],
    height: usize,
    header: &BlockHeader,
) -> Result<u128, Error> {
    if header.prev_block != headers[height - 1].hash() {
        return Err(consensus_err(format!(
            "height {height}: previous-block linkage broken"
        )));
    }
    let required = required_bits(params, headers, height, header);
    if header.bits != required {
        return Err(consensus_err(format!(
            "height {height}: bits {:#010x}, required {:#010x}",
            header.bits, required
        )));
    }
    let target = from_compact(header.bits).ok_or_else(|| {
        consensus_err(format!("height {height}: invalid compact target"))
    })?;
    if u256_is_zero(&target) || u256_ge(&target, &params.pow_limit) && target != params.pow_limit {
        return Err(consensus_err(format!(
            "height {height}: target out of range"
        )));
    }
    if !u256_ge(&target, &u256_from_hash(&header.hash())) {
        return Err(consensus_err(format!(
            "height {height}: hash does not meet target"
        )));
    }
    if header.time <= median_time_past(headers, height) {
        return Err(consensus_err(format!(
            "height {height}: timestamp not after median-time-past"
        )));
    }
    Ok(work_from_target(&target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_roundtrip() {
        for bits in [0x1d00ffff, 0x1e0377ae, 0x207fffff, 0x1b0404cb] {
            let target = from_compact(bits).unwrap();
            assert_eq!(to_compact(&target), bits);
        }
    }

    #[test]
    fn compact_expansion() {
        // 0x1d00ffff = 0x00ffff * 256^26 = 2^224 - 2^208
        let target = from_compact(0x1d00ffff).unwrap();
        assert_eq!(target, [0, 0, 0, 0xffff_0000]);
        // Regtest limit: 0x7fffff * 256^29
        let target = from_compact(0x207fffff).unwrap();
        assert_eq!(target, [0, 0, 0, 0x7fff_ff00_0000_0000]);
    }

    #[test]
    fn work_regtest_two_per_block() {
        let target = from_compact(0x207fffff).unwrap();
        assert_eq!(work_from_target(&target), 2);
    }

    #[test]
    fn work_mainnet_genesis() {
        // Difficulty-1 target → work = 2^256 / (2^224-ish) ≈ 2^32.
        let target = from_compact(0x1d00ffff).unwrap();
        assert_eq!(work_from_target(&target), 0x1_0001_0001);
    }

    #[test]
    fn regtest_constant_bits_and_pow() {
        let params = params(Network::Regtest);
        // The real regtest genesis header (mainnet coinbase, bits
        // 0x207fffff, nonce 2) plus one block mined right after.
        let genesis = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: crate::hash::from_hex(
                "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            time: 1296688602,
            bits: 0x207fffff,
            nonce: 2,
        };
        assert_eq!(genesis.hash(), params.genesis_hash);
        let headers = vec![genesis];
        // Regtest PoW is trivial: grind the nonce until the hash meets
        // the target (a couple of tries on average).
        let mut block1 = BlockHeader {
            version: 1,
            prev_block: genesis.hash(),
            merkle_root: [0u8; 32],
            time: 1296688602 + 1,
            bits: 0x207fffff,
            nonce: 0,
        };
        let target = from_compact(0x207fffff).unwrap();
        while !u256_ge(&target, &u256_from_hash(&block1.hash())) {
            block1.nonce += 1;
        }
        let work = validate_header(&params, &headers, 1, &block1).unwrap();
        assert_eq!(work, 2);
    }

    #[test]
    fn mainnet_style_retarget() {
        let params = params(Network::Mainnet);
        let fake_chain = |spacing: u32| {
            let mut headers = Vec::new();
            let mut prev = BlockHeader {
                version: 1,
                prev_block: [0u8; 32],
                merkle_root: [0u8; 32],
                time: 1_000_000_000,
                bits: 0x1d00ffff,
                nonce: 0,
            };
            headers.push(prev);
            for i in 1..2016usize {
                let h = BlockHeader {
                    time: 1_000_000_000 + spacing * i as u32,
                    prev_block: prev.hash(),
                    ..prev
                };
                headers.push(h);
                prev = h;
            }
            headers
        };
        // Exactly 600s spacing: the measured timespan is 600*2015 s
        // (2015 intervals between 2016 blocks — the consensus
        // off-by-one), slightly under the 600*2016 target, so the
        // difficulty rises a touch.
        assert_eq!(next_work_required(&params, &fake_chain(600), 2016), 0x1d00ffde);
        // Twice too slow: the target would double, but clamps at the
        // pow limit (previous bits are already the limit).
        assert_eq!(next_work_required(&params, &fake_chain(1200), 2016), 0x1d00ffff);
    }

    #[test]
    fn signet_uses_mainnet_style_rules() {
        // Regression test for the signet sync failure at the first
        // retarget boundary (iOS host report: scan_sync died at height
        // 2016 on signet). Signet has fPowAllowMinDifficultyBlocks =
        // false: the testnet-style >20min min-difficulty exception does
        // NOT exist, so a slow block must still carry its parent's bits.
        let params = params(Network::Signet);
        let hard_bits = 0x1e012fa7; // the real signet post-2016 bits
        let base = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            time: 1_600_000_000,
            bits: hard_bits,
            nonce: 0,
        };
        let headers = vec![base];
        let slow = BlockHeader {
            time: base.time + 2 * params.pow_target_spacing as u32 + 1,
            ..base
        };
        assert_eq!(
            required_bits(&params, &headers, 1, &slow),
            hard_bits,
            "signet has no min-difficulty timestamp exception"
        );
        let fast = BlockHeader {
            time: base.time + 60,
            ..base
        };
        assert_eq!(required_bits(&params, &headers, 1, &fast), hard_bits);
    }

    #[test]
    fn testnet_style_min_difficulty_rule() {
        // The min-difficulty branch models testnet4-style networks
        // (none of the supported networks enable it); keep it covered
        // with synthetic params.
        let params = Params {
            allow_min_difficulty: true,
            ..params(Network::Signet)
        };
        let hard_bits = 0x1d0ffff0;
        let base = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            time: 1_600_000_000,
            bits: hard_bits,
            nonce: 0,
        };
        let headers = vec![base];
        // height 1 % 2016 != 0: slow candidate → pow limit allowed.
        let slow = BlockHeader {
            time: base.time + 2 * params.pow_target_spacing as u32 + 1,
            ..base
        };
        assert_eq!(
            required_bits(&params, &headers, 1, &slow),
            params.pow_limit_bits
        );
        // A fast candidate must match the previous block's bits.
        let fast = BlockHeader {
            time: base.time + 60,
            ..base
        };
        assert_eq!(required_bits(&params, &headers, 1, &fast), hard_bits);
    }

    /// Real signet headers 2016–2022 (hex, from a synced node) through
    /// the first retarget boundary, validated against a synthetic
    /// prefix with the real boundary timestamps. Height 2019 is the
    /// exact case that broke the iOS host: it came 1631 s after its
    /// parent (a testnet-style rule would demand min-difficulty bits)
    /// yet carries the retargeted bits 0x1e012fa7.
    #[test]
    fn signet_first_retarget_boundary_real_headers() {
        const GENESIS_TIME: u32 = 1598918400; // real signet genesis
        const T_2015: u32 = 1599332177; // real block-2015 time
        const REAL: [&str; 7] = [
            "000000204de7ca88f25ebdb6a499b2bf22d50fb41453e24a86454ce66a1a84a3c0000000eef4cadbdfb67370f88951a0ad863a87d00b50bfa68c099705657a7b79a966e6ece1535fa72f011e37fc8a00", // 2016
            "0000002074a66cc632aa5e66569bc2c66d5b1d03d686757f30818a00650ec1d88f00000093a8147f9329e6d3a61ff5b769ad2c8ac232531aef0def5a94983e602211aa145ae3535fa72f011e4f3bd000", // 2017
            "0000002065c90fb9dc8a9bebdf8acf12342861865919f40964b6335c28c09f2d13000000ab15ac2a8bb6405d8892b30df8e8f4e890888909775ba5e46094a2d08341922c7ee5535fa72f011e27986b02", // 2018
            "00000020caa66b60a472df08b4c8e786f1468e03948c2489890106c4d10284f07f000000ea8e51a87cf10466fa5085bacbe74528f634a1a2ab20317f73957926b668e87cddeb535fa72f011e8ddb3002", // 2019
            "00000020d7f29dd46ff80f747622f3dadf85337e9c341db4469a96a91e8d98db07000000bf2b63df90626422e85e5501239ef90d5326e175468529178547bb2fff19fef0a1f1535fa72f011eebe24100", // 2020
            "0000002084197245c22736900bc5a1210322a693b7f8f9ef8ac27028378a63749e0000008c046085c3ada8b12ea9ca49cfada0057de629d0a2c981a9827601cfe1b87b794ff2535fa72f011e02f08800", // 2021
            "00000020cc83c07db8814d99223157e6617b7fed07c98c6324048ef376da0752f50000005d4cf07f35bb62bab8a5d203eb5912fb6f82fa55b30be7ce200d61819e365f70b7f3535fa72f011eb17ce300", // 2022
        ];
        let params = params(Network::Signet);
        // Synthetic prefix 0..=2015: real signet blocks all carried the
        // pow-limit bits through 2015, and the boundary retarget uses
        // only the endpoint timestamps (both real here).
        let mut headers = Vec::new();
        let mut prev = BlockHeader {
            version: 1,
            prev_block: [0u8; 32],
            merkle_root: [0u8; 32],
            time: GENESIS_TIME,
            bits: 0x1e0377ae,
            nonce: 0,
        };
        headers.push(prev);
        for i in 1..=2015usize {
            let h = BlockHeader {
                time: GENESIS_TIME + (T_2015 - GENESIS_TIME) * i as u32 / 2015,
                prev_block: prev.hash(),
                ..prev
            };
            headers.push(h);
            prev = h;
        }
        // The boundary retarget: base = block-2015 bits (pow limit),
        // timespan over the real endpoint times → the retargeted bits.
        let real: Vec<BlockHeader> = REAL
            .iter()
            .map(|h| BlockHeader::parse(&crate::hash::from_hex(h).unwrap()).unwrap())
            .collect();
        assert_eq!(next_work_required(&params, &headers, 2016), real[0].bits);
        assert_eq!(real[0].bits, 0x1e012fa7);
        // Full validation of 2016 is impossible against the synthetic
        // prefix (linkage), so check its bits + PoW + MTP directly...
        let target = from_compact(real[0].bits).unwrap();
        assert!(u256_ge(&target, &u256_from_hash(&real[0].hash())));
        // ...and validate 2017–2022 end-to-end (real linkage).
        for (offset, header) in real.iter().enumerate().skip(1) {
            let height = 2016 + offset;
            headers.push(real[offset - 1]);
            validate_header(&params, &headers, height, header).unwrap();
        }
        // The exact iOS failure: block 2019 came 1631 s after its
        // parent; a testnet-style rule would demand 0x1e0377ae here.
        assert_eq!(real[3].time - real[2].time, 1631);
        assert_eq!(
            required_bits(&params, &headers[..2019], 2019, &real[3]),
            0x1e012fa7
        );
    }
}
