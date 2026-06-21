//! Host implementation of the `jkbase:objectstore/store` capability — the typed own-bucket
//! binding a function imports. The guest names KEYS; the agent (host-side, in the tenant VM)
//! supplies the endpoint, the ephemeral credential, and the project scope, then issues a
//! SigV4-signed request to the host-pinned platform storage endpoint over the Zone-1
//! OWN-storage egress path (always allowed, survives `egress = false`). No credential ever
//! enters the guest's `process.env` (P0-OBJ-NOKEY); the WIT exposes no host/bucket/region
//! surface (P0-OBJ-SCOPE).
//!
//! A1 (this commit) wires bindgen + the linker with a FAIL-CLOSED stub so the import is
//! satisfiable and backward-compatible; the real SigV4 client lands in A3.

use crate::function_runtime::HostState;

wasmtime::component::bindgen!({
    path: "wit/objectstore.wit",
    world: "host-store",
    async: true,
});

pub use jkbase::objectstore::store::{Error as StoreError, ListPage};
use jkbase::objectstore::store::Host;

impl Host for HostState {
    async fn get(&mut self, _key: String) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::Internal)
    }
    async fn put(&mut self, _key: String, _body: Vec<u8>) -> Result<(), StoreError> {
        Err(StoreError::Internal)
    }
    async fn delete(&mut self, _key: String) -> Result<(), StoreError> {
        Err(StoreError::Internal)
    }
    async fn list_objects(
        &mut self,
        _prefix: String,
        _delimiter: Option<String>,
        _cursor: Option<String>,
    ) -> Result<ListPage, StoreError> {
        Err(StoreError::Internal)
    }
}

/// Register the `jkbase:objectstore/store` import on the component linker, supplying
/// `HostState` as the host. Called alongside the wasi + wasi:http linker setup. A component
/// that does NOT import the interface is unaffected (an extra linker definition is harmless).
pub fn add_to_linker(linker: &mut wasmtime::component::Linker<HostState>) -> wasmtime::Result<()> {
    jkbase::objectstore::store::add_to_linker::<HostState, HostState>(linker, |s| s)
}
