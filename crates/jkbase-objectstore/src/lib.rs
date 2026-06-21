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
//! which a hierarchical filesystem can't represent directly, so each key is
//! hex-encoded into a single flat filename. The original key + metadata live in a
//! sidecar; listing reads the sidecars. Hex encoding also makes traversal (`..`,
//! absolute paths) structurally impossible.

mod http;
pub mod client;
/// SigV4 lives in `jkbase-common` so the object-store verify path and the agent's own-bucket
/// sign path share byte-identical canonicalization (no divergence). Re-exported here so the
/// existing `crate::sigv4::` / `jkbase_objectstore::sigv4` call sites are unchanged.
pub use jkbase_common::sigv4;
mod store;
pub use client::{ClientError, ObjectClient};
pub use http::router;
pub use sigv4::{presign, sign_header, verify_header, verify_presigned};
pub use store::{ListPage, ListV2Page, MultipartUpload, ObjectError, ObjectMeta, ObjectStore};
