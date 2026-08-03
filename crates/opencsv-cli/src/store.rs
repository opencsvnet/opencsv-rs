//! Wallet storage: a local directory with everything a client knows.
//!
//! Layout (all serde/bincode unless noted; **prototype-grade — secrets are
//! stored unencrypted, protect the directory yourself**):
//!
//! ```text
//! <wallet-dir>/
//! ├── keys.bin                 # Vec<OwnerSecret> — owner identities (SECRET)
//! ├── issuers.bin              # Vec<IssuerRecord> — issuer keys + geneses (SECRET)
//! ├── assets/<asset_id>.genesis     # pinned AssetGenesis (trust-on-first-use)
//! ├── coins/<commitment>.coin       # StoredCoin: coin + status + creating proof
//! ├── consignments/<h>-<p>-<txid>.bin  # raw received consignment blobs
//! └── chain.log                # FileAnchorChain (unless --chain points elsewhere)
//! ```
//!
//! The nullifier index is *not* stored: it is derived state, rebuilt by
//! replaying `chain.log` on open. Coin ids are the lowercase hex of the coin
//! commitment; user-facing commands accept unique prefixes.

use std::path::{Path, PathBuf};

use opencsv_core::chain::AnchorRef;
use opencsv_core::{AssetGenesis, AssetId, Coin, Owner, OwnerSecret};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{io_err, Error};
use crate::hexutil::to_hex;

const KEYS_FILE: &str = "keys.bin";
const ISSUERS_FILE: &str = "issuers.bin";
const ASSETS_DIR: &str = "assets";
const COINS_DIR: &str = "coins";
const CONSIGNMENTS_DIR: &str = "consignments";

/// An issuer keypair plus the asset genesis it controls.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerRecord {
    /// Poseidon-committed issuer seed. Legacy records may contain an Ed25519
    /// secret and are read/export-only because their genesis key will not
    /// match the AIR-native Poseidon derivation.
    pub isk: [u8; 32],
    /// The asset genesis whose Poseidon issuer commitment matches `isk`.
    pub genesis: AssetGenesis,
}

/// Local spend state of a received coin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoinStatus {
    /// Available to spend.
    Unspent,
    /// Consumed by one of this wallet's anchors (a spent nullifier cannot be
    /// re-anchored successfully — see paper §4.7 rule 1).
    Spent,
}

/// A received coin plus everything needed to spend it later.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCoin {
    /// The coin itself.
    pub coin: Coin,
    /// Local spend state.
    pub status: CoinStatus,
    /// The `encode_coin_proof` envelope of the proof that *created* this
    /// coin — decoded with `opencsv_pcd::decode_coin_proof` and presented as
    /// the in-circuit predecessor when spending.
    pub proof: Vec<u8>,
    /// Which output of the creating proof's statement this coin is (the
    /// predecessor output selector `k` of the transfer/redeem circuits).
    pub selector: usize,
    /// Where the creating transaction anchored (informational).
    pub anchor: AnchorRef,
}

impl StoredCoin {
    /// The coin's id: lowercase hex of its commitment.
    pub fn id(&self) -> String {
        to_hex(self.coin.commitment().as_bytes())
    }
}

/// A wallet directory and its decoded contents.
pub struct Wallet {
    dir: PathBuf,
    keys: Vec<OwnerSecret>,
    issuers: Vec<IssuerRecord>,
    assets: Vec<AssetGenesis>,
    coins: Vec<StoredCoin>,
}

impl Wallet {
    /// Open `dir`, loading whatever files exist (missing files start empty).
    /// The directory itself is created on the first write.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, Error> {
        let dir = dir.into();
        let keys = read_optional(&dir.join(KEYS_FILE))?.unwrap_or_default();
        let issuers = read_optional(&dir.join(ISSUERS_FILE))?.unwrap_or_default();
        let assets = read_dir_bincode(&dir.join(ASSETS_DIR))?;
        let coins = read_dir_bincode(&dir.join(COINS_DIR))?;
        Ok(Self {
            dir,
            keys,
            issuers,
            assets,
            coins,
        })
    }

    /// The wallet directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// All owner secrets (accept uses them for the ownership check).
    pub fn secrets(&self) -> &[OwnerSecret] {
        &self.keys
    }

    /// All issuer records held by this wallet.
    pub fn issuers(&self) -> &[IssuerRecord] {
        &self.issuers
    }

    /// All pinned asset geneses.
    pub fn assets(&self) -> &[AssetGenesis] {
        &self.assets
    }

    /// All stored coins (spent and unspent).
    pub fn coins(&self) -> &[StoredCoin] {
        &self.coins
    }

    /// The ids of all pinned assets.
    pub fn known_asset_ids(&self) -> Vec<AssetId> {
        self.assets.iter().map(AssetGenesis::asset_id).collect()
    }

    /// Add a freshly generated owner secret and persist the key file.
    pub fn add_key(&mut self, secret: OwnerSecret) -> Result<(), Error> {
        self.keys.push(secret);
        write_bincode(&self.dir.join(KEYS_FILE), &self.keys)
    }

    /// Add an issuer record and persist it; the genesis is also pinned.
    pub fn add_issuer(&mut self, record: IssuerRecord) -> Result<(), Error> {
        self.pin_asset(record.genesis.clone())?;
        self.issuers.push(record);
        write_bincode(&self.dir.join(ISSUERS_FILE), &self.issuers)
    }

    /// Pin an asset genesis (trust-on-first-use), persisted by asset id.
    /// Idempotent.
    pub fn pin_asset(&mut self, genesis: AssetGenesis) -> Result<(), Error> {
        let id = genesis.asset_id();
        if self.assets.iter().any(|g| g.asset_id() == id) {
            return Ok(());
        }
        self.assets.push(genesis.clone());
        write_bincode(
            &self
                .dir
                .join(ASSETS_DIR)
                .join(format!("{}.genesis", to_hex(id.as_bytes()))),
            &genesis,
        )
    }

    /// The pinned genesis for `asset_id`, if any.
    pub fn find_genesis(&self, asset_id: &AssetId) -> Option<&AssetGenesis> {
        self.assets.iter().find(|g| g.asset_id() == *asset_id)
    }

    /// The issuer record controlling `asset_id`, if this wallet is the issuer.
    pub fn issuer_for(&self, asset_id: &AssetId) -> Option<&IssuerRecord> {
        self.issuers
            .iter()
            .find(|r| r.genesis.asset_id() == *asset_id)
    }

    /// The owner secret behind `owner`, if it is one of this wallet's keys.
    pub fn secret_for(&self, owner: &Owner) -> Option<OwnerSecret> {
        self.keys.iter().find(|k| k.owner() == *owner).copied()
    }

    /// Insert or replace a stored coin (keyed by commitment) and persist it.
    pub fn store_coin(&mut self, stored: StoredCoin) -> Result<(), Error> {
        let id = stored.id();
        if let Some(existing) = self.coins.iter_mut().find(|c| c.id() == id) {
            *existing = stored.clone();
        } else {
            self.coins.push(stored.clone());
        }
        write_bincode(
            &self.dir.join(COINS_DIR).join(format!("{id}.coin")),
            &stored,
        )
    }

    /// Find the unique coin whose id starts with `prefix`.
    pub fn find_coin(&self, prefix: &str) -> Result<&StoredCoin, Error> {
        let matches: Vec<&StoredCoin> = self
            .coins
            .iter()
            .filter(|c| c.id().starts_with(prefix))
            .collect();
        match matches.as_slice() {
            [coin] => Ok(coin),
            [] => Err(Error::UnknownCoin(prefix.to_string())),
            _ => Err(Error::AmbiguousCoin(prefix.to_string())),
        }
    }

    /// Mark a coin spent (after anchoring a transfer/redeem consuming it).
    pub fn mark_spent(&mut self, coin_id: &str) -> Result<(), Error> {
        let mut stored = self.find_coin(coin_id)?.clone();
        stored.status = CoinStatus::Spent;
        self.store_coin(stored)
    }

    /// Persist a received consignment blob under `consignments/`.
    pub fn save_consignment(&self, name: &str, blob: &[u8]) -> Result<PathBuf, Error> {
        let path = self.dir.join(CONSIGNMENTS_DIR).join(name);
        write_bytes(&path, blob)?;
        Ok(path)
    }
}

/// Default file name for a stored consignment, derived from its anchor.
pub fn consignment_name(anchor: &AnchorRef) -> String {
    format!(
        "{}-{}-{}.bin",
        anchor.location.height,
        anchor.location.position,
        &to_hex(&anchor.txid)[..8],
    )
}

fn read_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, Error> {
    match std::fs::read(path) {
        Ok(bytes) => decode_bincode(path, &bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

fn read_dir_bincode<T: DeserializeOwned>(dir: &Path) -> Result<Vec<T>, Error> {
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_err(dir))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(dir)(e)),
    };
    paths.sort();
    paths
        .iter()
        .filter(|p| p.is_file())
        .map(|p| decode_bincode(p, &std::fs::read(p).map_err(io_err(p))?))
        .collect()
}

fn decode_bincode<T: DeserializeOwned>(path: &Path, bytes: &[u8]) -> Result<T, Error> {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| Error::Decode {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
}

fn write_bincode<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard()).map_err(|e| {
        Error::Decode {
            path: path.to_path_buf(),
            message: format!("serialization failed: {e}"),
        }
    })?;
    write_bytes(path, &bytes)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_err(path))?;
    }
    std::fs::write(path, bytes).map_err(io_err(path))
}
