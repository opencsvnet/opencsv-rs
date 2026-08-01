//! Wallet operations: the whole OpenCSV protocol flow over the storage in
//! [`crate::store`] and the anchor seam in [`crate::chain`].
//!
//! Proving is real (`opencsv-pcd`): mints, transfers, and redeems produce
//! recursive coin proofs (~64 ms / ~3 s / ~1.5 s in release; ~100× slower in
//! debug — callers should print progress notes, as the CLI does).
//! Verification in [`receive`] is generic over [`ProofVerifier`]; production
//! callers pass [`opencsv_pcd::CoinProofVerifier`].
//!
//! **Interface for a transport crate** (e.g. Signal):
//!
//! - produce a blob to send: [`mint`] / [`send`] / [`redeem`] return a
//!   [`Produced`]; serialize `produced.consignment` with
//!   `Consignment::to_bytes` and move the bytes;
//! - ingest a blob: [`receive`] with the raw bytes — it runs the core
//!   `accept()` driver and, on success, stores the coins and pins the asset.

use opencsv_core::accept::{accept, AcceptParams, ProofVerifier};
use opencsv_core::chain::{AnchorChain, AnchorLocation};
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::{
    AnchorRecord, AssetId, Coin, Digest, Owner, OwnerSecret, RejectReason, mint_commit,
};
use opencsv_core::{mint_signing_message, Ed25519IssuerSignature, IssuerSignature};
use opencsv_pcd::{decode_coin_proof, encode_coin_proof, NODE_INPUTS, NODE_OUTPUTS};
use rand::RngExt;

use crate::chain::AnchorWriter;
use crate::error::Error;
use crate::hexutil::to_hex;
use crate::store::{consignment_name, CoinStatus, IssuerRecord, StoredCoin, Wallet};

/// vk tag passed to the accept driver. `opencsv_pcd::CoinProofVerifier`
/// ignores it (circuit shapes are fixed — see the adapter docs).
pub const COIN_VK: &[u8] = b"opencsv-pcd-coin-v1";

/// Default confirmation depth required by [`receive`] (paper §4.7 rule 2).
pub const DEFAULT_CONFIRMATIONS: u64 = 6;

/// 32 bytes of fresh randomness as a digest.
pub fn random_digest() -> Digest {
    Digest::from_bytes(rand::rng().random())
}

/// A fresh random anchor transaction context (synthetic outpoint) for the
/// demo backends, which draw `ctx` freely. Drawn *before* constructing a
/// nullifier-bearing anchor record: the record's bound payloads
/// `H("bind" ∥ nf ∥ ctx)` commit to it (see `opencsv-core`'s anchor docs).
/// Wallet flows do not call this directly — they anchor via
/// [`AnchorWriter::append_bound`], which lets the backend assign `ctx`
/// (the `bitcoind` backend derives it from the funding input's outpoint).
pub fn random_ctx() -> [u8; 32] {
    rand::rng().random()
}

/// Create a new owner identity, returning its public key (`owner = H(osk)`).
pub fn keygen(wallet: &mut Wallet) -> Result<Owner, Error> {
    let secret = OwnerSecret::from_bytes(rand::rng().random());
    let owner = secret.owner();
    wallet.add_key(secret)?;
    Ok(owner)
}

/// Create an issuer key and asset genesis for a 3-letter currency code,
/// returning the new asset id. The genesis is pinned locally; publish it
/// out-of-band so recipients can pin it too (or rely on consignment `aux`).
///
/// `terms_hash` is zeroed (no legal-terms document in the prototype) and the
/// nonce is a per-wallet counter.
pub fn issuer_init(wallet: &mut Wallet, currency: [u8; 3]) -> Result<AssetId, Error> {
    let seed: [u8; 32] = rand::rng().random();
    let (isk, ipk) = Ed25519IssuerSignature::keypair_from_seed(seed);
    let genesis = opencsv_core::AssetGenesis {
        issuer_pk: ipk,
        currency_code: currency,
        terms_hash: Digest::from_bytes([0u8; 32]),
        nonce: wallet.issuers().len() as u64 + 1,
    };
    let asset_id = genesis.asset_id();
    wallet.add_issuer(IssuerRecord { isk, genesis })?;
    Ok(asset_id)
}

/// A produced transaction: the consignment to deliver plus its anchor.
pub struct Produced {
    /// The consignment; serialize with `Consignment::to_bytes` for transport.
    pub consignment: Consignment,
    /// Where the transaction anchored.
    pub anchor: opencsv_core::AnchorRef,
}

/// The outcome of [`receive`].
#[derive(Debug)]
pub enum ReceiveReport {
    /// The consignment verified; the credited coins are stored.
    Verified {
        /// Per-asset totals credited.
        credits: Vec<(AssetId, u64)>,
        /// The coins credited (a subset of the openings owned by us).
        coins: Vec<Coin>,
        /// Where the transaction sits on-chain.
        anchor: AnchorLocation,
    },
    /// The consignment was rejected by the accept driver.
    Rejected(RejectReason),
}

/// Issuer-signed mint of 1–2 coins to `to` (paper §4.4).
///
/// The Ed25519 authorization over `(asset_id, V, mint_nonce)` is produced and
/// self-checked here, but **not carried in the consignment** — the core
/// `Consignment`/`accept` has no signature field yet (the paper's §4.4 item 1
/// check belongs in the mint AIR; see the crate README's caveats).
pub fn mint<C: AnchorWriter>(
    wallet: &mut Wallet,
    chain: &mut C,
    asset_id: &AssetId,
    to: Owner,
    amounts: &[u64],
) -> Result<Produced, Error> {
    let issuer = wallet
        .issuer_for(asset_id)
        .ok_or_else(|| Error::NotIssuer(to_hex(asset_id.as_bytes())))?
        .clone();
    let outputs = pad_outputs(asset_id, to, amounts)?;
    let total = checked_total(amounts)?;
    let mint_nonce = random_digest();

    // Off-circuit issuer authorization (paper §4.4 item 1; see doc note).
    let message = mint_signing_message(asset_id, total, &mint_nonce);
    let sig = Ed25519IssuerSignature::sign(&issuer.isk, &message);
    debug_assert!(Ed25519IssuerSignature::verify(
        &issuer.genesis.issuer_pk,
        &message,
        &sig
    ));

    let proof = opencsv_pcd::prove_genesis_mint(asset_id, &mint_nonce, &outputs)?;
    let record = AnchorRecord::Mint {
        asset_id: asset_id.to_anchor(),
        value: total,
        mint_commit: mint_commit(asset_id, total, &mint_nonce).to_anchor(),
    };
    // MINT carries no bound payload, so the closure ignores the ctx — but
    // anchoring still goes through the backend's ctx assignment (the
    // bitcoind backend derives ctx from the funding input's outpoint).
    let anchor = chain.append_bound(|_| record)?;
    let consignment = Consignment {
        coin_openings: openings_of(&outputs),
        nullifiers: vec![],
        proof: encode_coin_proof(&proof),
        anchor_ref: anchor,
        aux: Some(issuer.genesis),
    };
    Ok(Produced {
        consignment,
        anchor,
    })
}

/// Spend exactly [`NODE_INPUTS`] coins into 1–2 outputs owned by `to`
/// (paper §4.5, fixed 2-in/2-out circuit). Output values must sum to the
/// input total (conservation); a missing second amount means a zero-value
/// padding output. To pay someone and keep change, send the change output
/// to yourself in a separate spend, or use `--to self`.
///
/// The consignment carries `aux` (the pinned genesis) when available, so
/// first-contact recipients pass the asset check.
///
/// With `allow_spent` the local spent check is skipped — for demonstrating
/// double-spend *detection* only: the second anchor loses to first
/// occurrence (paper §4.7 rule 1) and its consignment is rejected.
pub fn send<C: AnchorWriter>(
    wallet: &mut Wallet,
    chain: &mut C,
    input_prefixes: &[String],
    to: Owner,
    amounts: &[u64],
    allow_spent: bool,
) -> Result<Produced, Error> {
    if input_prefixes.len() != NODE_INPUTS {
        return Err(Error::WrongInputCount {
            expected: NODE_INPUTS,
            got: input_prefixes.len(),
        });
    }
    let stored: Vec<StoredCoin> = input_prefixes
        .iter()
        .map(|p| wallet.find_coin(p).cloned())
        .collect::<Result<_, _>>()?;
    let ids: Vec<String> = stored.iter().map(StoredCoin::id).collect();
    let mut inputs = Vec::with_capacity(NODE_INPUTS);
    for s in &stored {
        if !allow_spent && s.status == CoinStatus::Spent {
            return Err(Error::CoinSpent(s.id()));
        }
        let osk = wallet
            .secret_for(&s.coin.owner)
            .ok_or_else(|| Error::UnknownOwner(to_hex(s.coin.owner.as_bytes())))?;
        inputs.push((s.coin, osk));
    }
    let asset_id = inputs[0].0.asset_id;
    if inputs.iter().any(|(c, _)| c.asset_id != asset_id) {
        return Err(Error::MixedAssets);
    }
    let input_total = checked_total(&inputs.iter().map(|(c, _)| c.value).collect::<Vec<_>>())?;
    let outputs = pad_outputs(&asset_id, to, amounts)?;
    let output_total = checked_total(amounts)?;
    if output_total != input_total {
        return Err(Error::AmountMismatch {
            inputs: input_total,
            outputs: output_total,
        });
    }

    let predecessors = stored
        .iter()
        .map(predecessor_proof)
        .collect::<Result<Vec<_>, _>>()?;
    let inputs: [(Coin, OwnerSecret); NODE_INPUTS] = inputs.try_into().expect("2 inputs");
    let proof = opencsv_pcd::prove_coin_transfer(
        &asset_id,
        &inputs,
        &outputs,
        [&predecessors[0], &predecessors[1]],
        [stored[0].selector, stored[1].selector],
    )?;

    // The raw nullifiers travel only in the consignment; the anchor
    // publishes bound payloads `H("bind" ∥ nf ∥ ctx)` (anti-grief, see
    // `opencsv-core`'s anchor docs). The 2-in circuit fits XFER's two
    // payload slots directly. The record is built against the backend's
    // ctx inside `append_bound` (tag-collision redraw included).
    let zero = Digest::from_bytes([0u8; 32]);
    let nullifiers: Vec<Digest> = proof
        .statement
        .nullifiers
        .iter()
        .copied()
        .filter(|nf| *nf != zero)
        .collect();
    if nullifiers.is_empty() {
        return Err(Error::Internal("transfer statement has no nullifiers"));
    }
    let anchor = chain.append_bound(|ctx| AnchorRecord::xfer(&nullifiers, ctx))?;
    let consignment = Consignment {
        coin_openings: openings_of(&outputs),
        nullifiers,
        proof: encode_coin_proof(&proof),
        anchor_ref: anchor,
        aux: wallet.find_genesis(&asset_id).cloned(),
    };
    for id in &ids {
        wallet.mark_spent(id)?;
    }
    Ok(Produced {
        consignment,
        anchor,
    })
}

/// Burn a coin back to the issuer (paper §4.6). The resulting consignment
/// carries no openings (redeems credit no one); the issuer verifies it with
/// the same `CoinProofVerifier` adapter (see the crate README).
pub fn redeem<C: AnchorWriter>(
    wallet: &mut Wallet,
    chain: &mut C,
    coin_prefix: &str,
) -> Result<Produced, Error> {
    let stored = wallet.find_coin(coin_prefix)?.clone();
    if stored.status == CoinStatus::Spent {
        return Err(Error::CoinSpent(stored.id()));
    }
    let coin = stored.coin;
    let osk = wallet
        .secret_for(&coin.owner)
        .ok_or_else(|| Error::UnknownOwner(to_hex(coin.owner.as_bytes())))?;
    let predecessor = predecessor_proof(&stored)?;
    let proof =
        opencsv_pcd::prove_redeem(&coin.asset_id, &(coin, osk), &predecessor, stored.selector)?;

    let raw_nf = proof.statement.nullifiers[0];
    let anchor = chain.append_bound(|ctx| {
        AnchorRecord::redeem(coin.asset_id.to_anchor(), coin.value, &raw_nf, ctx)
    })?;
    let consignment = Consignment {
        coin_openings: vec![],
        nullifiers: vec![raw_nf],
        proof: encode_coin_proof(&proof),
        anchor_ref: anchor,
        aux: None,
    };
    wallet.mark_spent(&stored.id())?;
    Ok(Produced {
        consignment,
        anchor,
    })
}

/// Run the core accept driver over a received consignment blob and, on
/// success, pin the asset, store the credited coins (with the creating
/// proof, for later spends), and archive the blob.
///
/// This is the ingest half of the transport interface: `verifier` is
/// [`opencsv_pcd::CoinProofVerifier`] in production; tests may pass
/// [`opencsv_core::MockVerifier`] to skip proving.
pub fn receive<V: ProofVerifier, C: AnchorChain>(
    wallet: &mut Wallet,
    chain: &C,
    verifier: &V,
    blob: &[u8],
    required_confirmations: u64,
) -> Result<ReceiveReport, Error> {
    let consignment = Consignment::from_bytes(blob)?;
    let known_assets = wallet.known_asset_ids();
    let accepted = match accept(
        &consignment,
        chain,
        verifier,
        &AcceptParams {
            vk: COIN_VK,
            required_confirmations,
            recipient_secrets: wallet.secrets(),
            known_assets: &known_assets,
        },
    ) {
        Ok(accepted) => accepted,
        Err(reason) => return Ok(ReceiveReport::Rejected(reason)),
    };

    if let Some(genesis) = &consignment.aux {
        wallet.pin_asset(genesis.clone())?;
    }
    let mut credits: Vec<(AssetId, u64)> = Vec::new();
    for coin in &accepted.coins {
        let selector = consignment
            .coin_openings
            .iter()
            .position(|o| o.to_coin() == *coin)
            .ok_or(Error::Internal("accepted coin not among the openings"))?;
        let mut stored = StoredCoin {
            coin: *coin,
            status: CoinStatus::Unspent,
            proof: consignment.proof.clone(),
            selector,
            anchor: consignment.anchor_ref,
        };
        // Redelivery of an already-stored coin must not resurrect it if we
        // have spent it since.
        if let Some(existing) = wallet.coins().iter().find(|c| c.id() == stored.id()) {
            stored.status = existing.status;
        }
        wallet.store_coin(stored)?;
        match credits.iter_mut().find(|(a, _)| a == &coin.asset_id) {
            Some((_, total)) => *total += coin.value,
            None => credits.push((coin.asset_id, coin.value)),
        }
    }
    wallet.save_consignment(&consignment_name(&consignment.anchor_ref), blob)?;
    Ok(ReceiveReport::Verified {
        credits,
        coins: accepted.coins,
        anchor: accepted.anchor,
    })
}

/// Unspent balances per asset (optionally filtered to one asset).
pub fn balance(wallet: &Wallet, asset: Option<&AssetId>) -> Vec<(AssetId, u64)> {
    let mut out: Vec<(AssetId, u64)> = Vec::new();
    for stored in wallet.coins() {
        if stored.status != CoinStatus::Unspent {
            continue;
        }
        let coin = stored.coin;
        if asset.is_some_and(|a| *a != coin.asset_id) {
            continue;
        }
        match out.iter_mut().find(|(a, _)| *a == coin.asset_id) {
            Some((_, total)) => *total += coin.value,
            None => out.push((coin.asset_id, coin.value)),
        }
    }
    out
}

/// The public supply of `asset` at `height` (default: tip), computed from
/// the anchor chain (paper §4.9).
pub fn audit<C: AnchorChain>(
    chain: &C,
    asset: &AssetId,
    height: Option<u64>,
) -> Result<u64, Error> {
    Ok(opencsv_core::audit::supply(
        chain,
        asset,
        height.unwrap_or_else(|| chain.tip_height()),
    )?)
}

/// Decode the stored creating proof of a coin (the in-circuit predecessor).
fn predecessor_proof(stored: &StoredCoin) -> Result<opencsv_pcd::CoinProof, Error> {
    decode_coin_proof(&stored.proof).ok_or(Error::Internal("stored coin proof does not decode"))
}

/// Build 2 output coins from 1–2 amounts (missing second amount pads a
/// zero-value output to the same owner).
fn pad_outputs(
    asset_id: &AssetId,
    owner: Owner,
    amounts: &[u64],
) -> Result<[Coin; NODE_OUTPUTS], Error> {
    if amounts.is_empty() || amounts.len() > NODE_OUTPUTS {
        return Err(Error::Parse(format!(
            "expected 1–{NODE_OUTPUTS} amounts, got {}",
            amounts.len()
        )));
    }
    let coin = |value: u64| Coin {
        asset_id: *asset_id,
        value,
        owner,
        randomness: random_digest(),
    };
    Ok(match amounts {
        [v] => [coin(*v), coin(0)],
        [v1, v2] => [coin(*v1), coin(*v2)],
        _ => unreachable!("length checked above"),
    })
}

fn checked_total(amounts: &[u64]) -> Result<u64, Error> {
    amounts.iter().try_fold(0u64, |acc, v| {
        acc.checked_add(*v)
            .ok_or_else(|| Error::Parse("amounts overflow u64".into()))
    })
}

fn openings_of(coins: &[Coin; NODE_OUTPUTS]) -> Vec<CoinOpening> {
    coins
        .iter()
        .map(|c| CoinOpening {
            asset_id: c.asset_id,
            value: c.value,
            owner: c.owner,
            randomness: c.randomness,
        })
        .collect()
}
