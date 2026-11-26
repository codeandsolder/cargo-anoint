//! Read-only Cargo dependency modernization and Rust source audit.
//!
//! The reviewed suggestion catalog is authoritative; live metadata provides
//! optional context, never changes the catalog or rewrites project source.

pub mod advisories;
pub mod bs_detector;
pub mod code_audit;
pub mod feedback;
pub mod intel;
mod organization;
pub mod output;
pub mod parser;
pub mod policy;
pub mod suggestions;
pub mod updater;
