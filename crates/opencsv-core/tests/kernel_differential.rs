//! Deterministic generated differential tests for kernel adoption. The
//! oracle freezes the pre-adoption core algorithms while production switches
//! to the verified kernel one decision surface at a time.

use std::collections::HashSet;

use opencsv_core::anchor::{self, AnchorRecord};
use opencsv_core::batch;
use opencsv_core::field::hash_felts;
use opencsv_core::{
    AnchorChain, AnchorLocation, Digest, MockAnchorChain, RejectReason as CoreRejectReason,
    TruncatedDigest,
};
use opencsv_kernel::accept::{
    AcceptDecision, AcceptInput, AnchorObservation, AssetObservation, OccurrenceObservation,
    RejectReason as KernelRejectReason,
};
use opencsv_kernel::audit::SupplyError as KernelSupplyError;
use opencsv_kernel::record::Record as KernelRecord;
use opencsv_kernel::types::{Entry as KernelEntry, Location as KernelLocation};
use p3_baby_bear::BabyBear;

struct Generator(u64);

impl Generator {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn usize(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut result = [0u8; N];
        let mut offset = 0usize;
        while offset < N {
            let word = self.next().to_le_bytes();
            let take = usize::min(8, N - offset);
            result[offset..offset + take].copy_from_slice(&word[..take]);
            offset += take;
        }
        result
    }
}

fn bytes_to_felts(bytes: &[u8]) -> Vec<BabyBear> {
    bytes
        .chunks(3)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            BabyBear::new(u32::from_le_bytes(word))
        })
        .collect()
}

fn legacy_binding(raw: &Digest, ctx: &[u8; 32]) -> TruncatedDigest {
    hash_felts("bind", &[&raw.to_elems(), &bytes_to_felts(ctx)]).to_anchor()
}

fn legacy_batch_commit(payloads: &[TruncatedDigest], ctx: &[u8; 32]) -> TruncatedDigest {
    let bytes: Vec<u8> = payloads
        .iter()
        .flat_map(|payload| payload.as_bytes().iter().copied())
        .collect();
    hash_felts("batch", &[&bytes_to_felts(&bytes), &bytes_to_felts(ctx)]).to_anchor()
}

fn legacy_well_formed(record: &AnchorRecord, ctx: &[u8; 32], raw: &Digest) -> bool {
    let bound = legacy_binding(raw, ctx);
    match record {
        AnchorRecord::Mint { .. } | AnchorRecord::BatchHeader { .. } => false,
        AnchorRecord::Xfer { payloads } => payloads[0] == bound || payloads[1] == bound,
        AnchorRecord::XferCompressed { nullifier_commit } => *nullifier_commit == bound,
        AnchorRecord::Redeem { payload, .. } => *payload == bound,
    }
}

fn kernel_record(record: &AnchorRecord) -> KernelRecord {
    match *record {
        AnchorRecord::Mint {
            asset_id,
            value,
            mint_commit,
        } => KernelRecord::Mint {
            asset_id: asset_id.0,
            value,
            mint_commit: mint_commit.0,
        },
        AnchorRecord::Xfer { payloads } => KernelRecord::Xfer {
            payloads: [payloads[0].0, payloads[1].0],
        },
        AnchorRecord::XferCompressed { nullifier_commit } => KernelRecord::XferCompressed {
            payload: nullifier_commit.0,
        },
        AnchorRecord::BatchHeader {
            count,
            batch_commit,
        } => KernelRecord::BatchHeader {
            count,
            batch_commit: batch_commit.0,
        },
        AnchorRecord::Redeem {
            asset_id,
            value,
            payload,
        } => KernelRecord::Redeem {
            asset_id: asset_id.0,
            value,
            payload: payload.0,
        },
    }
}

fn core_record(record: KernelRecord) -> AnchorRecord {
    match record {
        KernelRecord::Mint {
            asset_id,
            value,
            mint_commit,
        } => AnchorRecord::Mint {
            asset_id: TruncatedDigest(asset_id),
            value,
            mint_commit: TruncatedDigest(mint_commit),
        },
        KernelRecord::Xfer { payloads } => AnchorRecord::Xfer {
            payloads: [TruncatedDigest(payloads[0]), TruncatedDigest(payloads[1])],
        },
        KernelRecord::XferCompressed { payload } => AnchorRecord::XferCompressed {
            nullifier_commit: TruncatedDigest(payload),
        },
        KernelRecord::BatchHeader {
            count,
            batch_commit,
        } => AnchorRecord::BatchHeader {
            count,
            batch_commit: TruncatedDigest(batch_commit),
        },
        KernelRecord::Redeem {
            asset_id,
            value,
            payload,
        } => AnchorRecord::Redeem {
            asset_id: TruncatedDigest(asset_id),
            value,
            payload: TruncatedDigest(payload),
        },
    }
}

fn mutate_payload(record: AnchorRecord, offset: usize) -> AnchorRecord {
    let byte = offset % 24;
    match record {
        AnchorRecord::Xfer { mut payloads } => {
            payloads[offset % 2].0[byte] ^= 0x80;
            AnchorRecord::Xfer { payloads }
        }
        AnchorRecord::XferCompressed {
            mut nullifier_commit,
        } => {
            nullifier_commit.0[byte] ^= 0x80;
            AnchorRecord::XferCompressed { nullifier_commit }
        }
        AnchorRecord::Redeem {
            asset_id,
            value,
            mut payload,
        } => {
            payload.0[byte] ^= 0x80;
            AnchorRecord::Redeem {
                asset_id,
                value,
                payload,
            }
        }
        other => other,
    }
}

#[test]
fn generated_binding_and_batch_hashes_match_legacy() {
    let mut generator = Generator::new(0xA4_0001);
    for case in 0..256 {
        let raw = Digest::from_bytes(generator.bytes());
        let ctx = generator.bytes();
        assert_eq!(
            opencsv_kernel::binding(raw.as_bytes(), &ctx),
            legacy_binding(&raw, &ctx).0,
            "kernel binding case {case}"
        );
        assert_eq!(
            anchor::binding(&raw, &ctx).to_anchor(),
            legacy_binding(&raw, &ctx),
            "core binding case {case}"
        );

        let payloads: Vec<_> = (0..=generator.usize(12))
            .map(|_| TruncatedDigest(generator.bytes()))
            .collect();
        let kernel_payloads: Vec<_> = payloads.iter().map(|payload| payload.0).collect();
        assert_eq!(
            opencsv_kernel::truncate24(&opencsv_kernel::hash::hash_batch(&kernel_payloads, &ctx,)),
            legacy_batch_commit(&payloads, &ctx).0,
            "kernel batch hash case {case}"
        );
        assert_eq!(
            batch::batch_commit(&payloads, &ctx).to_anchor(),
            legacy_batch_commit(&payloads, &ctx),
            "core batch hash case {case}"
        );
    }
}

#[test]
fn generated_valid_and_mutated_occurrences_match_legacy() {
    let mut generator = Generator::new(0xA4_0002);
    for case in 0..256 {
        let raw = Digest::from_bytes(generator.bytes());
        let other = Digest::from_bytes(generator.bytes());
        let ctx = generator.bytes();
        let asset = TruncatedDigest(generator.bytes());
        let bound = legacy_binding(&raw, &ctx);
        let record = match generator.usize(5) {
            0 => AnchorRecord::Xfer {
                payloads: [bound, TruncatedDigest([0u8; 24])],
            },
            1 => AnchorRecord::Xfer {
                payloads: [TruncatedDigest(generator.bytes()), bound],
            },
            2 => AnchorRecord::XferCompressed {
                nullifier_commit: bound,
            },
            3 => AnchorRecord::Redeem {
                asset_id: asset,
                value: generator.next(),
                payload: bound,
            },
            _ => AnchorRecord::Mint {
                asset_id: asset,
                value: generator.next(),
                mint_commit: TruncatedDigest(generator.bytes()),
            },
        };
        for (candidate, candidate_ctx, candidate_raw) in [
            (record, ctx, raw),
            (record, generator.bytes(), raw),
            (record, ctx, other),
            (mutate_payload(record, generator.usize(48)), ctx, raw),
        ] {
            let expected = legacy_well_formed(&candidate, &candidate_ctx, &candidate_raw);
            assert_eq!(
                kernel_record(&candidate).well_formed(&candidate_ctx, candidate_raw.as_bytes()),
                expected,
                "kernel occurrence case {case}"
            );
            assert_eq!(
                candidate.well_formed(&candidate_ctx, &candidate_raw),
                expected,
                "core occurrence case {case}"
            );
        }
    }
}

#[test]
fn generated_first_occurrence_traces_match_legacy() {
    let mut generator = Generator::new(0xA4_0003);
    for case in 0..128 {
        let raw = Digest::from_bytes(generator.bytes());
        let length = 1 + generator.usize(32);
        let occurrence_at = generator.usize(length + 1);
        let mut legacy_entries = Vec::with_capacity(length);
        let mut kernel_entries = Vec::with_capacity(length);
        let mut chain = MockAnchorChain::new();

        for index in 0..length {
            let ctx = generator.bytes();
            let unrelated = Digest::from_bytes(generator.bytes());
            let source = if index == occurrence_at {
                raw
            } else {
                unrelated
            };
            let record = AnchorRecord::Xfer {
                payloads: [
                    legacy_binding(&source, &ctx),
                    TruncatedDigest(generator.bytes()),
                ],
            };
            let location = KernelLocation {
                height: (index / 3) as u64,
                position: (index % 3) as u32,
            };
            legacy_entries.push((record, ctx));
            kernel_entries.push(KernelEntry {
                record: kernel_record(&record),
                ctx,
                location,
            });
            if location.height > chain.tip_height() {
                chain.advance_blocks(location.height - chain.tip_height());
            }
            let anchor_ref = chain.append_with_ctx(record, ctx);
            assert_eq!(
                (anchor_ref.location.height, anchor_ref.location.position),
                (location.height, location.position),
                "generated trace stays in canonical order"
            );
        }

        let expected = legacy_entries
            .iter()
            .position(|(record, ctx)| legacy_well_formed(record, ctx, &raw));
        assert_eq!(
            opencsv_kernel::first_occurrence(&kernel_entries, raw.as_bytes()),
            expected,
            "first-occurrence trace {case}"
        );
        assert_eq!(
            chain.first_nullifier_occurrence(&raw),
            expected.map(|index| opencsv_core::AnchorLocation {
                height: kernel_entries[index].location.height,
                position: kernel_entries[index].location.position,
            }),
            "production first-occurrence trace {case}"
        );
    }
}

fn legacy_supply(
    anchors: &[(KernelLocation, KernelRecord)],
    asset: &[u8; 24],
    height: u64,
) -> Result<u64, KernelSupplyError> {
    let mut seen = HashSet::new();
    let mut total = 0i128;
    for (location, record) in anchors {
        if location.height > height {
            continue;
        }
        match record {
            KernelRecord::Mint {
                asset_id,
                value,
                mint_commit,
            } if asset_id == asset && seen.insert(*mint_commit) => total += i128::from(*value),
            KernelRecord::Redeem {
                asset_id, value, ..
            } if asset_id == asset => total -= i128::from(*value),
            _ => {}
        }
    }
    u64::try_from(total).map_err(|_| KernelSupplyError::NegativeSupply)
}

#[test]
fn generated_supply_traces_match_legacy() {
    let mut generator = Generator::new(0xA4_0004);
    for case in 0..128 {
        let asset = generator.bytes();
        let other_asset = generator.bytes();
        let mut previous_commit = generator.bytes();
        let mut anchors = Vec::new();
        let mut chain = MockAnchorChain::new();
        for index in 0..(1 + generator.usize(40)) {
            let record = match generator.usize(5) {
                0 | 1 => {
                    let commit = if generator.usize(4) == 0 {
                        previous_commit
                    } else {
                        generator.bytes()
                    };
                    previous_commit = commit;
                    KernelRecord::Mint {
                        asset_id: if generator.usize(4) == 0 {
                            other_asset
                        } else {
                            asset
                        },
                        value: generator.next() % 10_000,
                        mint_commit: commit,
                    }
                }
                2 => KernelRecord::Redeem {
                    asset_id: if generator.usize(4) == 0 {
                        other_asset
                    } else {
                        asset
                    },
                    value: generator.next() % 10_000,
                    payload: generator.bytes(),
                },
                _ => KernelRecord::Xfer {
                    payloads: [generator.bytes(), generator.bytes()],
                },
            };
            let location = KernelLocation {
                height: (index / 2) as u64,
                position: (index % 2) as u32,
            };
            anchors.push((location, record));
            if location.height > chain.tip_height() {
                chain.advance_blocks(location.height - chain.tip_height());
            }
            chain.append_with_ctx(core_record(record), generator.bytes());
        }
        let height = generator.usize(anchors.len().div_ceil(2) + 2) as u64;
        let expected = legacy_supply(&anchors, &asset, height);
        assert_eq!(
            opencsv_kernel::supply(&anchors, &asset, height),
            expected,
            "supply trace {case}"
        );
        let mut asset_digest = [0u8; 32];
        asset_digest[..24].copy_from_slice(&asset);
        assert_eq!(
            opencsv_core::supply(&chain, &Digest::from_bytes(asset_digest), height)
                .map_err(|_| KernelSupplyError::NegativeSupply),
            expected,
            "production supply trace {case}"
        );
    }
}

#[test]
fn generated_batch_occurrence_mutations_match_legacy() {
    let mut generator = Generator::new(0xA4_0005);
    for case in 0..128 {
        let raw = Digest::from_bytes(generator.bytes());
        let ctx = generator.bytes();
        let length = 1 + generator.usize(20);
        let occurrence = generator.usize(length);
        let mut payloads: Vec<_> = (0..length)
            .map(|_| TruncatedDigest(generator.bytes()))
            .collect();
        payloads[occurrence] = legacy_binding(&raw, &ctx);
        let committed = legacy_batch_commit(&payloads, &ctx);
        let kernel_payloads: Vec<_> = payloads.iter().map(|payload| payload.0).collect();
        let record = AnchorRecord::BatchHeader {
            count: length as u8,
            batch_commit: committed,
        };
        assert_eq!(
            opencsv_kernel::batch_occurrence(
                length as u8,
                &committed.0,
                &kernel_payloads,
                &ctx,
                raw.as_bytes(),
            ),
            Some(occurrence as u32),
            "valid batch {case}"
        );
        assert_eq!(
            batch::envelope_occurrence(&record, &payloads, &ctx, &raw),
            Some(occurrence as u32),
            "production valid batch {case}"
        );

        let mut mutated = kernel_payloads.clone();
        mutated[generator.usize(length)][generator.usize(24)] ^= 1;
        assert_eq!(
            opencsv_kernel::batch_occurrence(
                length as u8,
                &committed.0,
                &mutated,
                &ctx,
                raw.as_bytes(),
            ),
            None,
            "mutated batch {case}"
        );
        let mutated_core: Vec<_> = mutated.into_iter().map(TruncatedDigest).collect();
        assert_eq!(
            batch::envelope_occurrence(&record, &mutated_core, &ctx, &raw),
            None,
            "production mutated batch {case}"
        );
    }
}

fn legacy_accept(input: &AcceptInput) -> AcceptDecision {
    if !input.has_openings {
        return AcceptDecision::Reject(KernelRejectReason::EmptyConsignment);
    }
    match input.asset {
        AssetObservation::GenesisMismatch => {
            return AcceptDecision::Reject(KernelRejectReason::GenesisMismatch);
        }
        AssetObservation::UnknownAsset => {
            return AcceptDecision::Reject(KernelRejectReason::UnknownAsset);
        }
        AssetObservation::Valid => {}
    }
    let AnchorObservation::Present {
        location,
        confirmations,
        binds_nullifiers,
        occurrences,
    } = &input.anchor
    else {
        return AcceptDecision::Reject(KernelRejectReason::AnchorNotFound);
    };
    if !input.has_distinct_nullifiers {
        return AcceptDecision::Reject(KernelRejectReason::DuplicateNullifier);
    }
    if !input.proof_valid {
        return AcceptDecision::Reject(KernelRejectReason::InvalidProof);
    }
    if *confirmations < input.required_confirmations {
        return AcceptDecision::Reject(KernelRejectReason::InsufficientConfirmations {
            have: *confirmations,
            required: input.required_confirmations,
        });
    }
    if !binds_nullifiers {
        return AcceptDecision::Reject(KernelRejectReason::IllFormedAnchor);
    }
    for occurrence in occurrences {
        let Some(first) = occurrence.first else {
            return AcceptDecision::Reject(KernelRejectReason::AnchorNotFound);
        };
        if first != *location {
            return AcceptDecision::Reject(KernelRejectReason::NullifierConflict {
                nullifier: occurrence.nullifier,
                first,
            });
        }
    }
    if !input.has_owned_output {
        return AcceptDecision::Reject(KernelRejectReason::NoOwnedOutput);
    }
    AcceptDecision::Accept { anchor: *location }
}

#[test]
fn generated_accept_observations_match_legacy_precedence() {
    let mut generator = Generator::new(0xA5_0001);
    for case in 0..512 {
        let location = KernelLocation {
            height: generator.next() % 100_000,
            position: generator.usize(4_000) as u32,
        };
        let mut occurrences = Vec::new();
        for _ in 0..generator.usize(6) {
            let first = match generator.usize(4) {
                0 => None,
                1 | 2 => Some(location),
                _ => Some(KernelLocation {
                    height: generator.next() % 100_000,
                    position: generator.usize(4_000) as u32,
                }),
            };
            occurrences.push(OccurrenceObservation {
                nullifier: generator.bytes(),
                first,
            });
        }
        let anchor = if generator.usize(5) == 0 {
            AnchorObservation::Missing
        } else {
            AnchorObservation::Present {
                location,
                confirmations: generator.next() % 12,
                binds_nullifiers: generator.usize(3) != 0,
                occurrences,
            }
        };
        let asset = match generator.usize(3) {
            0 => AssetObservation::Valid,
            1 => AssetObservation::GenesisMismatch,
            _ => AssetObservation::UnknownAsset,
        };
        let input = AcceptInput {
            has_openings: generator.usize(5) != 0,
            asset,
            anchor,
            has_distinct_nullifiers: generator.usize(5) != 0,
            proof_valid: generator.usize(4) != 0,
            required_confirmations: generator.next() % 12,
            has_owned_output: generator.usize(4) != 0,
        };
        assert_eq!(
            opencsv_kernel::decide_accept(&input),
            legacy_accept(&input),
            "accept observation case {case}: {input:?}"
        );
    }
}

#[test]
fn public_rejection_codes_match_the_kernel_boundary() {
    let location = AnchorLocation {
        height: 7,
        position: 3,
    };
    let kernel_location = KernelLocation {
        height: 7,
        position: 3,
    };
    let pairs = [
        (
            CoreRejectReason::EmptyConsignment,
            KernelRejectReason::EmptyConsignment,
        ),
        (
            CoreRejectReason::GenesisMismatch,
            KernelRejectReason::GenesisMismatch,
        ),
        (
            CoreRejectReason::UnknownAsset,
            KernelRejectReason::UnknownAsset,
        ),
        (
            CoreRejectReason::AnchorNotFound,
            KernelRejectReason::AnchorNotFound,
        ),
        (
            CoreRejectReason::DuplicateNullifier,
            KernelRejectReason::DuplicateNullifier,
        ),
        (
            CoreRejectReason::InsufficientConfirmations {
                have: 1,
                required: 6,
            },
            KernelRejectReason::InsufficientConfirmations {
                have: 1,
                required: 6,
            },
        ),
        (
            CoreRejectReason::NullifierConflict {
                nullifier: TruncatedDigest([9u8; 24]),
                first: location,
            },
            KernelRejectReason::NullifierConflict {
                nullifier: [9u8; 24],
                first: kernel_location,
            },
        ),
        (
            CoreRejectReason::IllFormedAnchor,
            KernelRejectReason::IllFormedAnchor,
        ),
        (
            CoreRejectReason::InvalidProof,
            KernelRejectReason::InvalidProof,
        ),
        (
            CoreRejectReason::NoOwnedOutput,
            KernelRejectReason::NoOwnedOutput,
        ),
    ];
    for (core, kernel) in pairs {
        assert_eq!(core.code(), kernel.code());
    }
}
