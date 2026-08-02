//! Pure decision-logic kernel of opencsv-core (see crate README).
//!
//! The **verification surface** — `types`, `binding`, `record`, `scan`,
//! `batch`, `audit` — is written for Aeneas translation: loops only, no
//! serde/dyn/RNG, no generics beyond plain byte arrays and integers. The
//! `hash` module is the cryptographic boundary (translated as opaque).

pub mod audit;
pub mod batch;
pub mod binding;
pub mod hash;
pub mod record;
pub mod scan;
pub mod types;

pub use audit::{supply, SupplyError};
pub use batch::batch_occurrence;
pub use binding::{binding, truncate24};
pub use record::Record;
pub use scan::first_occurrence;
pub use types::{AssetId24, Ctx, Entry, Location, MintCommit, Payload, RawNf};
