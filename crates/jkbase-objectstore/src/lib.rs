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
mod store;
pub use http::router;
pub use store::{ObjectError, ObjectMeta, ObjectStore};
