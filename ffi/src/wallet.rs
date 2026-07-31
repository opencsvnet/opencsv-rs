//! The in-memory wallet engine behind the C ABI.
//!
//! A port of `opencsv-cli`'s `ops` flows with two host-app-shaped changes:
//!
//! - **No filesystem.** State lives in memory; the host persists the small
//!   secret state (see [`MemWallet::secrets_json`]) in its platform keystore
//!   and rebuilds coins by replaying verified consignment blobs through
//!   [`MemWallet::verify`] (verification is milliseconds; proving is the
//!   expensive part).
//! - **No chain writer.** Producing a transaction is two-phase: a `prove_*`
//!   call returns the 64-byte anchor record for the host to publish, and
//!   [`MemWallet::finalize`] builds the consignment once the host knows
//!   where the record anchored. The host never holds key material.
//!
//! Transfers support change: the first output amount pays the recipient,
//! an optional second amount returns to this wallet's first owner key.

use std::collections::HashMap;

use opencsv_core::accept::{accept, AcceptParams};
use opencsv_core::chain::{AnchorChain, AnchorRef};
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::{
    mint_commit, mint_signing_message, nullifier_commit, AnchorRecord, AssetGenesis, AssetId, Coin,
    Digest, Ed25519IssuerSignature, IssuerSignature, Owner, OwnerSecret,
};
use opencsv_pcd::{decode_coin_proof, encode_coin_proof, NODE_INPUTS, NODE_OUTPUTS};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::hex::{from_hex_array, to_hex};
use crate::snapshot::SnapshotChain;

/// vk tag passed to the accept driver (`opencsv_pcd::CoinProofVerifier`
/// ignores it; kept identical to `opencsv-cli`'s for consistency).
pub const COIN_VK: &[u8] = b"opencsv-pcd-coin-v1";

/// One operation's failure, as a display string for the JSON boundary.
pub type OpError = String;

fn random_digest() -> Digest {
    Digest::from_bytes(rand::rng().random())
}

/// An issuer keypair plus the asset genesis it controls.
#[derive(Clone)]
struct IssuerRecord {
    isk: [u8; 32],
    genesis: AssetGenesis,
}

/// Local spend state of a stored coin.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CoinStatus {
    Unspent,
    Spent,
}

/// A received coin plus the creating proof needed to spend it later.
#[derive(Clone)]
struct StoredCoin {
    coin: Coin,
    status: CoinStatus,
    /// `encode_coin_proof` envelope of the proof that created this coin.
    proof: Vec<u8>,
    /// Which output of the creating proof's statement this coin is.
    selector: usize,
}

impl StoredCoin {
    fn id(&self) -> String {
        to_hex(self.coin.commitment().as_bytes())
    }
}

/// A proved-but-not-yet-anchored transaction awaiting [`MemWallet::finalize`].
struct Pending {
    openings: Vec<CoinOpening>,
    proof: Vec<u8>,
    aux: Option<AssetGenesis>,
    /// Coin ids consumed by this transaction, marked spent at finalize.
    spent_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Serde forms of the host-persisted secret state and of API responses.
// ---------------------------------------------------------------------------

/// Serde form of an asset genesis.
#[derive(Serialize, Deserialize)]
pub struct GenesisJson {
    /// Issuer public key, 32 bytes hex.
    pub issuer_pk: String,
    /// 3-character currency code, e.g. `"USD"`.
    pub currency_code: String,
    /// Terms hash, 32 bytes hex.
    pub terms_hash: String,
    /// Genesis nonce.
    pub nonce: u64,
}

#[derive(Serialize, Deserialize)]
struct IssuerJson {
    isk: String,
    genesis: GenesisJson,
}

/// The wallet's secret state: everything the host must persist in its
/// keystore. Coins are intentionally absent — they are rebuilt by replaying
/// verified consignments (see module docs).
#[derive(Serialize, Deserialize)]
pub struct SecretsJson {
    /// Format version, currently 1.
    pub version: u32,
    owner_secrets: Vec<String>,
    issuers: Vec<IssuerJson>,
    assets: Vec<GenesisJson>,
}

/// One credited asset total in a verification verdict.
#[derive(Serialize)]
pub struct CreditJson {
    /// Asset id, 32 bytes hex.
    pub asset_id: String,
    /// Currency code from the pinned genesis, if known.
    pub currency: Option<String>,
    /// Total credited value in base units.
    pub amount: u64,
}

/// One coin in a status/verdict listing.
#[derive(Serialize)]
pub struct CoinJson {
    /// Coin id (commitment hex).
    pub id: String,
    /// Asset id, 32 bytes hex.
    pub asset_id: String,
    /// Currency code from the pinned genesis, if known.
    pub currency: Option<String>,
    /// Value in base units.
    pub value: u64,
    /// `true` if the coin is spendable.
    pub unspent: bool,
}

fn genesis_to_json(g: &AssetGenesis) -> GenesisJson {
    GenesisJson {
        issuer_pk: to_hex(&g.issuer_pk),
        currency_code: String::from_utf8_lossy(&g.currency_code).into_owned(),
        terms_hash: to_hex(g.terms_hash.as_bytes()),
        nonce: g.nonce,
    }
}

fn genesis_from_json(g: &GenesisJson) -> Result<AssetGenesis, OpError> {
    let code: [u8; 3] = g
        .currency_code
        .as_bytes()
        .try_into()
        .map_err(|_| format!("currency code `{}` is not 3 bytes", g.currency_code))?;
    Ok(AssetGenesis {
        issuer_pk: from_hex_array::<32>(&g.issuer_pk, "issuer_pk")?,
        currency_code: code,
        terms_hash: Digest::from_bytes(from_hex_array::<32>(&g.terms_hash, "terms_hash")?),
        nonce: g.nonce,
    })
}

// ---------------------------------------------------------------------------
// The wallet.
// ---------------------------------------------------------------------------

/// An in-memory OpenCSV wallet (see module docs for the persistence model).
pub struct MemWallet {
    keys: Vec<OwnerSecret>,
    issuers: Vec<IssuerRecord>,
    assets: Vec<AssetGenesis>,
    coins: Vec<StoredCoin>,
    pending: HashMap<u64, Pending>,
    next_pending: u64,
}

/// Result of a `prove_*` call: the anchor record to publish plus the pending
/// transaction id to [`MemWallet::finalize`] once it anchors.
pub struct Proved {
    /// Pending-transaction id.
    pub pending_id: u64,
    /// The 64-byte anchor record, for the host to publish.
    pub anchor_record: [u8; 64],
    /// Coin ids this transaction will consume (empty for mints).
    pub spends: Vec<String>,
}

/// Successful verification outcome.
pub struct Verified {
    /// Per-asset credited totals.
    pub credits: Vec<CreditJson>,
    /// The credited coins.
    pub coins: Vec<CoinJson>,
    /// Anchor height of the verified transaction.
    pub height: u64,
    /// Anchor in-block position of the verified transaction.
    pub position: u32,
}

impl MemWallet {
    /// A fresh wallet with one owner key.
    pub fn create() -> Self {
        let mut wallet = Self::empty();
        wallet
            .keys
            .push(OwnerSecret::from_bytes(rand::rng().random()));
        wallet
    }

    fn empty() -> Self {
        Self {
            keys: Vec::new(),
            issuers: Vec::new(),
            assets: Vec::new(),
            coins: Vec::new(),
            pending: HashMap::new(),
            next_pending: 1,
        }
    }

    /// Restore a wallet from its persisted secret state.
    pub fn open(secrets_json: &str) -> Result<Self, OpError> {
        let secrets: SecretsJson =
            serde_json::from_str(secrets_json).map_err(|e| format!("secrets JSON: {e}"))?;
        if secrets.version != 1 {
            return Err(format!("unsupported secrets version {}", secrets.version));
        }
        let mut wallet = Self::empty();
        for s in &secrets.owner_secrets {
            wallet
                .keys
                .push(OwnerSecret::from_bytes(from_hex_array::<32>(
                    s,
                    "owner secret",
                )?));
        }
        for i in &secrets.issuers {
            wallet.issuers.push(IssuerRecord {
                isk: from_hex_array::<32>(&i.isk, "issuer secret")?,
                genesis: genesis_from_json(&i.genesis)?,
            });
        }
        for g in &secrets.assets {
            wallet.pin_asset(genesis_from_json(g)?);
        }
        for issuer in wallet.issuers.clone() {
            wallet.pin_asset(issuer.genesis);
        }
        Ok(wallet)
    }

    /// Export the secret state for the host's keystore.
    pub fn secrets_json(&self) -> SecretsJson {
        SecretsJson {
            version: 1,
            owner_secrets: self.keys.iter().map(|k| to_hex(k.0.as_bytes())).collect(),
            issuers: self
                .issuers
                .iter()
                .map(|i| IssuerJson {
                    isk: to_hex(&i.isk),
                    genesis: genesis_to_json(&i.genesis),
                })
                .collect(),
            assets: self.assets.iter().map(genesis_to_json).collect(),
        }
    }

    /// The wallet's owner public keys, hex.
    pub fn owners(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|k| to_hex(k.owner().as_bytes()))
            .collect()
    }

    /// Add a fresh owner key, returning its public key hex.
    pub fn keygen(&mut self) -> String {
        let secret = OwnerSecret::from_bytes(rand::rng().random());
        let owner = to_hex(secret.owner().as_bytes());
        self.keys.push(secret);
        owner
    }

    /// Create an issuer key and asset genesis for a 3-letter currency code,
    /// returning the new asset id hex.
    pub fn init_issuer(&mut self, currency: &str) -> Result<String, OpError> {
        let code: [u8; 3] = currency
            .as_bytes()
            .try_into()
            .map_err(|_| format!("currency code `{currency}` is not 3 bytes"))?;
        let seed: [u8; 32] = rand::rng().random();
        let (isk, ipk) = Ed25519IssuerSignature::keypair_from_seed(seed);
        let genesis = AssetGenesis {
            issuer_pk: ipk,
            currency_code: code,
            terms_hash: Digest::from_bytes([0u8; 32]),
            nonce: self.issuers.len() as u64 + 1,
        };
        let asset_id = genesis.asset_id();
        self.pin_asset(genesis.clone());
        self.issuers.push(IssuerRecord { isk, genesis });
        Ok(to_hex(asset_id.as_bytes()))
    }

    /// All coins, for the host's status view.
    pub fn list_coins(&self) -> Vec<CoinJson> {
        self.coins.iter().map(|s| self.coin_json(s)).collect()
    }

    /// Unspent balances per asset.
    pub fn balance(&self) -> Vec<CreditJson> {
        let mut out: Vec<CreditJson> = Vec::new();
        for stored in &self.coins {
            if stored.status != CoinStatus::Unspent {
                continue;
            }
            let id = to_hex(stored.coin.asset_id.as_bytes());
            match out.iter_mut().find(|c| c.asset_id == id) {
                Some(c) => c.amount += stored.coin.value,
                None => out.push(CreditJson {
                    asset_id: id,
                    currency: self.currency_of(&stored.coin.asset_id),
                    amount: stored.coin.value,
                }),
            }
        }
        out
    }

    /// Issuer-signed mint of `amounts` (1–2 outputs) to `to` (paper §4.4).
    /// This wallet must hold the issuer key for `asset_id`.
    pub fn prove_mint(
        &mut self,
        asset_id_hex: &str,
        to_owner_hex: &str,
        amounts: &[u64],
    ) -> Result<Proved, OpError> {
        let asset_id = parse_digest(asset_id_hex, "asset id")?;
        let to = parse_digest(to_owner_hex, "owner")?;
        let issuer = self
            .issuers
            .iter()
            .find(|i| i.genesis.asset_id() == asset_id)
            .ok_or_else(|| format!("this wallet does not issue asset {asset_id_hex}"))?
            .clone();
        let outputs = outputs_to_one_owner(&asset_id, to, amounts)?;
        let total = checked_total(amounts)?;
        let mint_nonce = random_digest();

        // Off-circuit issuer authorization (paper §4.4 item 1; the signature
        // is not yet carried in the consignment — see opencsv-pcd's caveats).
        let message = mint_signing_message(&asset_id, total, &mint_nonce);
        let sig = Ed25519IssuerSignature::sign(&issuer.isk, &message);
        if !Ed25519IssuerSignature::verify(&issuer.genesis.issuer_pk, &message, &sig) {
            return Err("issuer self-check failed".into());
        }

        let proof = opencsv_pcd::prove_genesis_mint(&asset_id, &mint_nonce, &outputs)
            .map_err(|e| e.to_string())?;
        let record = AnchorRecord::Mint {
            asset_id: asset_id.to_anchor(),
            value: total,
            mint_commit: mint_commit(&asset_id, total, &mint_nonce).to_anchor(),
        };
        Ok(self.push_pending(
            openings_of(&outputs),
            encode_coin_proof(&proof),
            Some(issuer.genesis),
            Vec::new(),
            record,
        ))
    }

    /// Spend exactly [`NODE_INPUTS`] coins (paper §4.5). `amounts[0]` pays
    /// `to`; an optional `amounts[1]` returns change to this wallet's first
    /// owner key. Amounts must sum to the input total (conservation).
    pub fn prove_transfer(
        &mut self,
        coin_ids: &[String],
        to_owner_hex: &str,
        amounts: &[u64],
    ) -> Result<Proved, OpError> {
        if coin_ids.len() != NODE_INPUTS {
            return Err(format!(
                "expected exactly {NODE_INPUTS} input coin ids, got {}",
                coin_ids.len()
            ));
        }
        let to = parse_digest(to_owner_hex, "owner")?;
        let stored: Vec<StoredCoin> = coin_ids
            .iter()
            .map(|p| self.find_coin(p).cloned())
            .collect::<Result<_, _>>()?;
        let ids: Vec<String> = stored.iter().map(StoredCoin::id).collect();
        let mut inputs = Vec::with_capacity(NODE_INPUTS);
        for s in &stored {
            if s.status == CoinStatus::Spent {
                return Err(format!("coin {} is already spent", s.id()));
            }
            let osk = self
                .secret_for(&s.coin.owner)
                .ok_or_else(|| format!("no secret for owner of coin {}", s.id()))?;
            inputs.push((s.coin, osk));
        }
        let asset_id = inputs[0].0.asset_id;
        if inputs.iter().any(|(c, _)| c.asset_id != asset_id) {
            return Err("input coins are not all of the same asset".into());
        }
        let input_total = checked_total(&inputs.iter().map(|(c, _)| c.value).collect::<Vec<_>>())?;
        let output_total = checked_total(amounts)?;
        if output_total != input_total {
            return Err(format!(
                "conservation: inputs total {input_total}, outputs total {output_total}"
            ));
        }
        let change_owner = self
            .keys
            .first()
            .ok_or("wallet has no owner key for change")?
            .owner();
        let outputs = outputs_with_change(&asset_id, to, change_owner, amounts)?;

        let predecessors: Vec<opencsv_pcd::CoinProof> = stored
            .iter()
            .map(|s| {
                decode_coin_proof(&s.proof)
                    .ok_or_else(|| format!("stored proof for coin {} does not decode", s.id()))
            })
            .collect::<Result<_, _>>()?;
        let inputs: [(Coin, OwnerSecret); NODE_INPUTS] =
            inputs.try_into().expect("length checked above");
        let proof = opencsv_pcd::prove_coin_transfer(
            &asset_id,
            &inputs,
            &outputs,
            [&predecessors[0], &predecessors[1]],
            [stored[0].selector, stored[1].selector],
        )
        .map_err(|e| e.to_string())?;

        let record = AnchorRecord::XferCompressed {
            nullifier_commit: nullifier_commit(&proof.statement.nullifiers).to_anchor(),
        };
        let aux = self.find_genesis(&asset_id).cloned();
        Ok(self.push_pending(
            openings_of(&outputs),
            encode_coin_proof(&proof),
            aux,
            ids,
            record,
        ))
    }

    /// Burn a coin back to the issuer (paper §4.6).
    pub fn prove_redeem(&mut self, coin_id: &str) -> Result<Proved, OpError> {
        let stored = self.find_coin(coin_id)?.clone();
        if stored.status == CoinStatus::Spent {
            return Err(format!("coin {} is already spent", stored.id()));
        }
        let coin = stored.coin;
        let osk = self
            .secret_for(&coin.owner)
            .ok_or_else(|| format!("no secret for owner of coin {}", stored.id()))?;
        let predecessor = decode_coin_proof(&stored.proof)
            .ok_or_else(|| format!("stored proof for coin {} does not decode", stored.id()))?;
        let proof =
            opencsv_pcd::prove_redeem(&coin.asset_id, &(coin, osk), &predecessor, stored.selector)
                .map_err(|e| e.to_string())?;

        let record = AnchorRecord::Redeem {
            asset_id: coin.asset_id.to_anchor(),
            value: coin.value,
            nullifier: proof.statement.nullifiers[0].to_anchor(),
        };
        let ids = vec![stored.id()];
        Ok(self.push_pending(Vec::new(), encode_coin_proof(&proof), None, ids, record))
    }

    /// Build the consignment for a proved transaction once the host knows
    /// where its anchor record landed, and mark the consumed coins spent.
    /// Returns the serialized consignment blob.
    pub fn finalize(
        &mut self,
        pending_id: u64,
        anchor_ref: AnchorRef,
    ) -> Result<(Vec<u8>, Vec<String>), OpError> {
        let pending = self
            .pending
            .remove(&pending_id)
            .ok_or_else(|| format!("unknown pending transaction {pending_id}"))?;
        let consignment = Consignment {
            coin_openings: pending.openings,
            proof: pending.proof,
            anchor_ref,
            aux: pending.aux,
        };
        for id in &pending.spent_ids {
            if let Some(c) = self.coins.iter_mut().find(|c| c.id() == *id) {
                c.status = CoinStatus::Spent;
            }
        }
        Ok((consignment.to_bytes(), pending.spent_ids))
    }

    /// Run the accept driver over a received consignment blob against an
    /// anchor snapshot; on success pin the asset and store the credited
    /// coins. Mirrors `opencsv-cli`'s `ops::receive`.
    pub fn verify(
        &mut self,
        blob: &[u8],
        chain: &SnapshotChain,
        required_confirmations: u64,
    ) -> Result<Result<Verified, String>, OpError> {
        let consignment = Consignment::from_bytes(blob).map_err(|e| e.to_string())?;
        let known_assets: Vec<AssetId> = self.assets.iter().map(AssetGenesis::asset_id).collect();
        let accepted = match accept(
            &consignment,
            chain,
            &opencsv_pcd::CoinProofVerifier,
            &AcceptParams {
                vk: COIN_VK,
                required_confirmations,
                recipient_secrets: &self.keys,
                known_assets: &known_assets,
            },
        ) {
            Ok(accepted) => accepted,
            Err(reason) => return Ok(Err(format!("{reason:?}"))),
        };

        if let Some(genesis) = &consignment.aux {
            self.pin_asset(genesis.clone());
        }
        let mut credits: Vec<CreditJson> = Vec::new();
        let mut coin_views = Vec::new();
        for coin in &accepted.coins {
            let selector = consignment
                .coin_openings
                .iter()
                .position(|o| o.to_coin() == *coin)
                .ok_or("accepted coin not among the openings")?;
            let mut stored = StoredCoin {
                coin: *coin,
                status: CoinStatus::Unspent,
                proof: consignment.proof.clone(),
                selector,
            };
            // Redelivery must not resurrect a coin we have spent since.
            if let Some(existing) = self.coins.iter().find(|c| c.id() == stored.id()) {
                stored.status = existing.status;
            }
            coin_views.push(self.coin_json(&stored));
            match self.coins.iter_mut().find(|c| c.id() == stored.id()) {
                Some(existing) => *existing = stored,
                None => self.coins.push(stored),
            }
            let id = to_hex(coin.asset_id.as_bytes());
            match credits.iter_mut().find(|c| c.asset_id == id) {
                Some(c) => c.amount += coin.value,
                None => credits.push(CreditJson {
                    asset_id: id,
                    currency: self.currency_of(&coin.asset_id),
                    amount: coin.value,
                }),
            }
        }
        Ok(Ok(Verified {
            credits,
            coins: coin_views,
            height: accepted.anchor.height,
            position: accepted.anchor.position,
        }))
    }

    /// Mark coins spent by id (host-side replay of persisted spend state).
    pub fn mark_spent(&mut self, coin_ids: &[String]) -> Result<(), OpError> {
        for id in coin_ids {
            let stored = self.find_coin_mut(id)?;
            stored.status = CoinStatus::Spent;
        }
        Ok(())
    }

    // -- internals ---------------------------------------------------------

    fn push_pending(
        &mut self,
        openings: Vec<CoinOpening>,
        proof: Vec<u8>,
        aux: Option<AssetGenesis>,
        spent_ids: Vec<String>,
        record: AnchorRecord,
    ) -> Proved {
        let pending_id = self.next_pending;
        self.next_pending += 1;
        let spends = spent_ids.clone();
        self.pending.insert(
            pending_id,
            Pending {
                openings,
                proof,
                aux,
                spent_ids,
            },
        );
        Proved {
            pending_id,
            anchor_record: record.to_bytes(),
            spends,
        }
    }

    fn pin_asset(&mut self, genesis: AssetGenesis) {
        let id = genesis.asset_id();
        if !self.assets.iter().any(|g| g.asset_id() == id) {
            self.assets.push(genesis);
        }
    }

    fn find_genesis(&self, asset_id: &AssetId) -> Option<&AssetGenesis> {
        self.assets.iter().find(|g| g.asset_id() == *asset_id)
    }

    fn currency_of(&self, asset_id: &AssetId) -> Option<String> {
        self.find_genesis(asset_id)
            .map(|g| String::from_utf8_lossy(&g.currency_code).into_owned())
    }

    fn secret_for(&self, owner: &Owner) -> Option<OwnerSecret> {
        self.keys.iter().find(|k| k.owner() == *owner).copied()
    }

    fn find_coin(&self, prefix: &str) -> Result<&StoredCoin, OpError> {
        let matches: Vec<&StoredCoin> = self
            .coins
            .iter()
            .filter(|c| c.id().starts_with(prefix))
            .collect();
        match matches.as_slice() {
            [coin] => Ok(coin),
            [] => Err(format!("no coin with id prefix {prefix}")),
            _ => Err(format!("coin id prefix {prefix} is ambiguous")),
        }
    }

    fn find_coin_mut(&mut self, prefix: &str) -> Result<&mut StoredCoin, OpError> {
        let matches: Vec<usize> = self
            .coins
            .iter()
            .enumerate()
            .filter(|(_, c)| c.id().starts_with(prefix))
            .map(|(i, _)| i)
            .collect();
        match matches.as_slice() {
            [i] => Ok(&mut self.coins[*i]),
            [] => Err(format!("no coin with id prefix {prefix}")),
            _ => Err(format!("coin id prefix {prefix} is ambiguous")),
        }
    }

    fn coin_json(&self, stored: &StoredCoin) -> CoinJson {
        CoinJson {
            id: stored.id(),
            asset_id: to_hex(stored.coin.asset_id.as_bytes()),
            currency: self.currency_of(&stored.coin.asset_id),
            value: stored.coin.value,
            unspent: stored.status == CoinStatus::Unspent,
        }
    }
}

/// Public supply of `asset_id` at the snapshot tip (paper §4.9).
pub fn audit(asset_id_hex: &str, chain: &SnapshotChain) -> Result<u64, OpError> {
    let asset_id = parse_digest(asset_id_hex, "asset id")?;
    opencsv_core::audit::supply(chain, &asset_id, chain.tip_height()).map_err(|e| e.to_string())
}

fn parse_digest(hex: &str, what: &str) -> Result<Digest, OpError> {
    Ok(Digest::from_bytes(from_hex_array::<32>(hex, what)?))
}

fn checked_total(amounts: &[u64]) -> Result<u64, OpError> {
    amounts.iter().try_fold(0u64, |acc, v| {
        acc.checked_add(*v)
            .ok_or_else(|| "amounts overflow u64".to_string())
    })
}

/// 1–2 amounts, all outputs to one owner (mint shape; missing second amount
/// pads a zero-value output).
fn outputs_to_one_owner(
    asset_id: &AssetId,
    owner: Owner,
    amounts: &[u64],
) -> Result<[Coin; NODE_OUTPUTS], OpError> {
    match amounts {
        [v] => Ok([coin(asset_id, *v, owner), coin(asset_id, 0, owner)]),
        [v1, v2] => Ok([coin(asset_id, *v1, owner), coin(asset_id, *v2, owner)]),
        _ => Err(format!(
            "expected 1–{NODE_OUTPUTS} amounts, got {}",
            amounts.len()
        )),
    }
}

/// Transfer shape: `amounts[0]` to the recipient, optional `amounts[1]` back
/// to `change_owner` (zero-value padding when absent).
fn outputs_with_change(
    asset_id: &AssetId,
    to: Owner,
    change_owner: Owner,
    amounts: &[u64],
) -> Result<[Coin; NODE_OUTPUTS], OpError> {
    match amounts {
        [v] => Ok([coin(asset_id, *v, to), coin(asset_id, 0, change_owner)]),
        [v1, v2] => Ok([coin(asset_id, *v1, to), coin(asset_id, *v2, change_owner)]),
        _ => Err(format!(
            "expected 1–{NODE_OUTPUTS} amounts, got {}",
            amounts.len()
        )),
    }
}

fn coin(asset_id: &AssetId, value: u64, owner: Owner) -> Coin {
    Coin {
        asset_id: *asset_id,
        value,
        owner,
        randomness: random_digest(),
    }
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
