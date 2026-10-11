//! `jkbase-objectstore` — the **tenant-facing** S3-compatible object store. This
//! is a tenant PRODUCT and must NEVER back the control plane (see the no-S3-for-
//! control-plane rule); it is entirely separate from `jkbase-substrate`.
//!
//! This module is the storage core: buckets + objects on the local filesystem,
//! streamed (never buffered) with S3-style MD5 etags and per-bucket isolation. The
//! HTTP API surface (PUT/GET/DELETE, multipart, presigned URLs) and tenant auth
//! are layered on top in their own cards.
//!
//! The S3 keyspace is flat (a key like `a/b` and `a/b/c` may both be objects),
//! which a hierarchical filesystem can't represent directly, so each key maps to a
//! single flat filename: `hex(key)` up to 125 bytes, a base64 of the key up to 186, and
//! beyond that (to the 1024-byte S3 limit, which no whole-key name fits) a SHA-256 of
//! the key plus its base64-encoded first 153 bytes. The original key + metadata live in
//! a sidecar. A name never contains `/` or starts with `.`, so traversal (`..`,
//! absolute paths) is structurally impossible.

pub mod cors;
mod http;
/// SigV4 lives in the `jkbase-sigv4` leaf crate (re-exported via `jkbase-common`) so the
/// object-store verify path, the agent's own-bucket sign path, AND the tenant-facing
/// `jkbase-objectstore-client` all share byte-identical canonicalization (no divergence).
/// Re-exported here so the existing `crate::sigv4::` / `jkbase_objectstore::sigv4` call
/// sites are unchanged. The tenant client itself lives in its own crate, depending only on
/// `jkbase-sigv4` + reqwest — never this engine crate.
pub use jkbase_common::sigv4;
mod store;
pub use http::router;
pub use sigv4::{presign, sign_header, verify_header, verify_presigned};
pub use cors::{CorsConfig, cors_config_to_xml, parse_cors_config_xml};
pub use store::{ListPage, ListV2Page, MultipartUpload, ObjectError, ObjectMeta, ObjectStore};
