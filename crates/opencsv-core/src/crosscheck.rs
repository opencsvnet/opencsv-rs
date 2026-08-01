//! N-of-M cross-checked exclusion (paper §4.7.1, amended).
//!
//! OpenCSV's double-spend rule is *first occurrence wins*, which requires
//! an exclusion check: "no EARLIER anchor binds this nullifier". A single
//! indexer performing that check can lie by omission — hide the legitimate
//! first occurrence so a later double-spend appears first.
//! [`CrossCheckedChain`] removes that single point of failure: occurrence
//! queries fan out to **all** member chains and the **earliest** reported
//! occurrence wins, so hiding an occurrence requires compromising every
//! member. The production posture is N independent indexers (the operator's
//! own bitcoind, an org indexer, a third-party service), each individually
//! untrusted.
//!
//! Two query classes, two policies:
//!
//! - **Occurrence queries** ([`AnchorChain::first_nullifier_occurrence`],
//!   [`AnchorChain::nullifier_occurrences`]) — union across ALL members;
//!   the earliest reported occurrence is authoritative. Any single honest
//!   member exposes a double-spend.
//! - **Presence queries** ([`AnchorChain::anchor_at`],
//!   [`AnchorChain::ctx_at`], [`AnchorChain::anchors_up_to`]) — the first
//!   member that has the entry answers. Presence is not the
//!   exclusion-critical direction: a member claiming a phantom anchor can
//!   only grief (rejections the victim can re-check against their own
//!   scan — see `opencsv-cbf`'s `FullScanChain`), while a member *hiding*
//!   an occurrence would enable theft.
//!
//! **Tip agreement is a hard error, never a silent pick.** Confirmation
//! depth is only meaningful if all members look at the same chain:
//! [`CrossCheckedChain::new`] and [`CrossCheckedChain::refresh`] require
//! byte-identical tip heights and fail with
//! [`CrossCheckError::TipDisagreement`] otherwise. The [`AnchorChain`]
//! trait methods are infallible, so the agreed value is latched at
//! construction/refresh time; callers re-checking liveness use
//! [`CrossCheckedChain::refresh`].

use std::fmt;

use crate::chain::{AnchorChain, AnchorLocation, AnchorRef};
use crate::{AnchorRecord, Digest};

/// Why a [`CrossCheckedChain`] could not be assembled or refreshed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossCheckError {
    /// A cross-checked chain needs at least one member.
    NoMembers,
    /// Members disagree on the tip height (one of them is stale,
    /// misconfigured, or malicious). Never silently resolved.
    TipDisagreement(Vec<u64>),
}

impl fmt::Display for CrossCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMembers => write!(f, "no anchor backends configured"),
            Self::TipDisagreement(tips) => {
                write!(f, "anchor backends disagree on tip height: {tips:?}")
            }
        }
    }
}

impl std::error::Error for CrossCheckError {}

/// An [`AnchorChain`] with N-of-M quorum semantics over independently
/// operated backends (see module docs).
pub struct CrossCheckedChain {
    members: Vec<Box<dyn AnchorChain>>,
    agreed_tip: u64,
}

impl CrossCheckedChain {
    /// Assemble from `members`, requiring tip-height agreement (a
    /// [`CrossCheckError::TipDisagreement`] otherwise).
    pub fn new(members: Vec<Box<dyn AnchorChain>>) -> Result<Self, CrossCheckError> {
        if members.is_empty() {
            return Err(CrossCheckError::NoMembers);
        }
        let agreed_tip = check_tips(&members)?;
        Ok(Self {
            members,
            agreed_tip,
        })
    }

    /// Re-check tip agreement and latch the new agreed tip (e.g. after
    /// giving members time to catch up to new blocks).
    pub fn refresh(&mut self) -> Result<(), CrossCheckError> {
        self.agreed_tip = check_tips(&self.members)?;
        Ok(())
    }

    /// The tip height the members agreed on at construction/last refresh.
    pub fn agreed_tip(&self) -> u64 {
        self.agreed_tip
    }

    /// Number of member backends.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

fn check_tips(members: &[Box<dyn AnchorChain>]) -> Result<u64, CrossCheckError> {
    let tips: Vec<u64> = members.iter().map(|m| m.tip_height()).collect();
    match tips.first() {
        Some(&tip) if tips.iter().all(|t| *t == tip) => Ok(tip),
        _ => Err(CrossCheckError::TipDisagreement(tips)),
    }
}

impl AnchorChain for CrossCheckedChain {
    fn tip_height(&self) -> u64 {
        self.agreed_tip
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.members.iter().find_map(|m| m.anchor_at(anchor_ref))
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.members.iter().find_map(|m| m.ctx_at(anchor_ref))
    }

    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        self.members.iter().find_map(|m| m.locate(anchor_ref))
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        // Earliest across ALL members: any one honest member exposes a
        // double-spend (module docs).
        self.members
            .iter()
            .filter_map(|m| m.first_nullifier_occurrence(raw_nf))
            .min()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        let mut locations: Vec<AnchorLocation> = self
            .members
            .iter()
            .flat_map(|m| m.nullifier_occurrences(raw_nf))
            .collect();
        locations.sort();
        locations.dedup();
        locations
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        // Presence direction: the first member's view (module docs).
        self.members
            .first()
            .map(|m| m.anchors_up_to(height))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept::{accept, public_input, AcceptParams, MockVerifier, RejectReason};
    use crate::chain::MockAnchorChain;
    use crate::coin::OwnerSecret;
    use crate::consignment::{CoinOpening, Consignment};
    use crate::{AssetGenesis, AssetId, Digest};

    const VK: &[u8] = b"test-vk";

    fn digest(seed: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Digest::from_bytes(bytes)
    }

    fn secret(seed: u8) -> OwnerSecret {
        OwnerSecret::from_bytes(digest(seed).0)
    }

    fn asset_id() -> AssetId {
        AssetGenesis {
            issuer_pk: [7u8; 32],
            currency_code: *b"USD",
            terms_hash: digest(2),
            nonce: 1,
        }
        .asset_id()
    }

    fn opening(seed: u8, value: u64) -> CoinOpening {
        CoinOpening {
            asset_id: asset_id(),
            value,
            owner: secret(seed).owner(),
            randomness: digest(seed + 100),
        }
    }

    /// A double-spend scenario on one honest chain: `nf` is spent at
    /// anchor 1 (the legitimate spend, height 0) and re-anchored at
    /// anchor 2 (the double-spend attempt, height 1), each bound to its
    /// own ctx.
    struct Scenario {
        nf: Digest,
        honest: MockAnchorChain,
        ref1: AnchorRef,
        ref2: AnchorRef,
    }

    fn scenario() -> Scenario {
        let nf = digest(42);
        let mut honest = MockAnchorChain::new();
        let ctx1 = honest.fresh_ctx();
        let ref1 = honest.append_with_ctx(AnchorRecord::xfer(&[nf], &ctx1), ctx1);
        honest.advance_blocks(1);
        let ctx2 = honest.fresh_ctx();
        let ref2 = honest.append_with_ctx(AnchorRecord::xfer(&[nf], &ctx2), ctx2);
        honest.advance_blocks(6);
        Scenario {
            nf,
            honest,
            ref1,
            ref2,
        }
    }

    /// A second MockAnchorChain with the same entries (the mock derives
    /// txids deterministically from entry order, so refs match).
    fn clone_honest(s: &Scenario) -> MockAnchorChain {
        let mut chain = MockAnchorChain::new();
        let ctx1 = s.honest.ctx_at(&s.ref1).unwrap();
        chain.append_with_ctx(s.honest.anchor_at(&s.ref1).unwrap(), ctx1);
        chain.advance_blocks(1);
        let ctx2 = s.honest.ctx_at(&s.ref2).unwrap();
        chain.append_with_ctx(s.honest.anchor_at(&s.ref2).unwrap(), ctx2);
        chain.advance_blocks(6);
        chain
    }

    /// A chain reporting only the double-spend anchor (the malicious
    /// indexer hiding the legitimate first occurrence). Same record,
    /// same location coordinates, same ctx — occurrence checks compare
    /// locations, and presence lookups are answered by the honest
    /// member.
    fn malicious_hiding_first(s: &Scenario) -> (MockAnchorChain, AnchorRef) {
        let mut chain = MockAnchorChain::new();
        chain.advance_blocks(1);
        let record = s.honest.anchor_at(&s.ref2).unwrap();
        let ctx = s.honest.ctx_at(&s.ref2).unwrap();
        let m_ref = chain.append_with_ctx(record, ctx);
        assert_eq!(m_ref.location, s.ref2.location);
        chain.advance_blocks(6);
        (chain, m_ref)
    }

    fn consignment_for(
        chain: &MockAnchorChain,
        anchor_ref: AnchorRef,
        nullifiers: Vec<Digest>,
        openings: Vec<CoinOpening>,
    ) -> Consignment {
        let record = chain.anchor_at(&anchor_ref).unwrap();
        let ctx = chain.ctx_at(&anchor_ref).unwrap();
        Consignment {
            coin_openings: openings.clone(),
            nullifiers,
            proof: MockVerifier::prove(VK, &public_input(&record, &ctx, &openings)),
            anchor_ref,
            aux: None,
        }
    }

    fn params<'a>(secrets: &'a [OwnerSecret], known: &'a [AssetId]) -> AcceptParams<'a> {
        AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: secrets,
            known_assets: known,
        }
    }

    fn boxed(chain: MockAnchorChain) -> Box<dyn AnchorChain> {
        Box::new(chain)
    }

    #[test]
    fn empty_members_rejected() {
        assert!(matches!(
            CrossCheckedChain::new(Vec::new()),
            Err(CrossCheckError::NoMembers)
        ));
    }

    #[test]
    fn tip_disagreement_is_a_hard_error() {
        let mut a = MockAnchorChain::new();
        a.advance_blocks(7);
        let mut b = MockAnchorChain::new();
        b.advance_blocks(8);
        match CrossCheckedChain::new(vec![boxed(a), boxed(b)]) {
            Err(CrossCheckError::TipDisagreement(tips)) => {
                assert_eq!(tips, vec![7, 8], "never silently pick a tip")
            }
            other => panic!("expected TipDisagreement, got {}", other.is_ok()),
        }
    }

    #[test]
    fn all_honest_accepts_legitimate_spend() {
        let s = scenario();
        let cross = CrossCheckedChain::new(vec![
            boxed(clone_honest(&s)),
            boxed(clone_honest(&s)),
        ])
        .unwrap();
        assert_eq!(cross.tip_height(), s.honest.tip_height());

        // The legitimate spend (anchor 1) verifies.
        let receiver = secret(9);
        let known = [asset_id()];
        let consignment = consignment_for(&s.honest, s.ref1, vec![s.nf], vec![opening(9, 50)]);
        let accepted = accept(
            &consignment,
            &cross,
            &MockVerifier,
            &params(std::slice::from_ref(&receiver), &known),
        );
        assert!(accepted.is_ok(), "{accepted:?}");
    }

    #[test]
    fn one_malicious_member_cannot_hide_an_occurrence() {
        let s = scenario();
        let (malicious, m_ref) = malicious_hiding_first(&s);
        let receiver = secret(9);
        let known = [asset_id()];

        // Control: against the malicious chain alone, the double-spend
        // consignment passes the occurrence check.
        let m_consignment = consignment_for(&malicious, m_ref, vec![s.nf], vec![opening(9, 50)]);
        let alone = accept(
            &m_consignment,
            &malicious,
            &MockVerifier,
            &params(std::slice::from_ref(&receiver), &known),
        );
        assert!(
            alone.is_ok(),
            "control: the malicious chain alone accepts the double-spend: {alone:?}"
        );

        // Cross-checked — 1 honest + 1 malicious, and 1 malicious + 2
        // honest: the earliest reported occurrence is the legitimate
        // anchor, so the double-spend is rejected either way.
        let consignment = consignment_for(&s.honest, s.ref2, vec![s.nf], vec![opening(9, 50)]);
        for members in [
            vec![boxed(clone_honest(&s)), boxed(malicious_hiding_first(&s).0)],
            vec![
                boxed(malicious_hiding_first(&s).0),
                boxed(clone_honest(&s)),
                boxed(clone_honest(&s)),
            ],
        ] {
            let cross = CrossCheckedChain::new(members).unwrap();
            let rejected = accept(
                &consignment,
                &cross,
                &MockVerifier,
                &params(std::slice::from_ref(&receiver), &known),
            );
            assert!(
                matches!(
                    rejected,
                    Err(RejectReason::NullifierConflict { first, .. })
                        if first == s.ref1.location
                ),
                "victim still rejects with one malicious member: {rejected:?}"
            );
        }

        // And the earliest occurrence is observable directly.
        let cross = CrossCheckedChain::new(vec![
            boxed(malicious_hiding_first(&s).0),
            boxed(clone_honest(&s)),
        ])
        .unwrap();
        assert_eq!(
            cross.first_nullifier_occurrence(&s.nf),
            Some(s.ref1.location)
        );
        assert_eq!(
            cross.nullifier_occurrences(&s.nf),
            vec![s.ref1.location, s.ref2.location]
        );
    }
}
