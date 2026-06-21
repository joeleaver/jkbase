pub mod config;
pub mod egress;
pub mod layers;
pub mod logs;
pub mod routing;
/// SigV4 now lives in the `jkbase-sigv4` leaf crate (so the tenant object-store
/// client can depend on just the signer, not this whole crate). Re-exported here
/// unchanged so every existing `jkbase_common::sigv4::…` call site still resolves
/// and there remains exactly ONE implementation (byte-identical, no divergence).
pub use jkbase_sigv4 as sigv4;
pub mod storage;
