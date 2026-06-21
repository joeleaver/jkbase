//! Own-bucket-probe fixture: a `wasi:http` component that ALSO imports
//! `jkbase:objectstore/store` and exercises it, so the runtime integration test can prove
//! the typed binding resolves + the call reaches the agent's host impl end to end.
//!
//! On each request it does `put` then `get` on a fixed key and reports the typed outcome
//! (`ok` / the WIT error variant). In the in-process test (no live object store, no
//! credential) the calls reach the host and come back as a typed error — which still proves
//! the WIT plumbing (import resolved, linker wired, host impl invoked), distinct from a
//! trap or an unresolved import.

use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

// The store import — same package/version/interface as the agent's wit/objectstore.wit, so
// the component's import matches what the agent's linker supplies. Import-only guest world.
mod binding {
    wit_bindgen::generate!({
        inline: r#"
            package jkbase:objectstore@0.1.0;
            interface store {
                variant error { not-found, access-denied, quota-exceeded, too-large, invalid-key, internal }
                record object-meta { key: string, size: u64, etag: string, last-modified: u64 }
                record list-page { objects: list<object-meta>, common-prefixes: list<string>, next-cursor: option<string> }
                get: func(key: string) -> result<list<u8>, error>;
                put: func(key: string, body: list<u8>) -> result<_, error>;
                delete: func(key: string) -> result<_, error>;
                list-objects: func(prefix: string, delimiter: option<string>, cursor: option<string>) -> result<list-page, error>;
            }
            world guest-store { import store; }
        "#,
        world: "guest-store",
    });
}

use binding::jkbase::objectstore::store as store;

struct Component;
wasi::http::proxy::export!(Component);

fn err_name(e: &store::Error) -> &'static str {
    match e {
        store::Error::NotFound => "not-found",
        store::Error::AccessDenied => "access-denied",
        store::Error::QuotaExceeded => "quota-exceeded",
        store::Error::TooLarge => "too-large",
        store::Error::InvalidKey => "invalid-key",
        store::Error::Internal => "internal",
    }
}

impl wasi::exports::http::incoming_handler::Guest for Component {
    fn handle(_request: IncomingRequest, outparam: ResponseOutparam) {
        let put = match store::put("probe/k.txt", b"hello-own-bucket") {
            Ok(()) => "ok".to_string(),
            Err(e) => err_name(&e).to_string(),
        };
        let get = match store::get("probe/k.txt") {
            Ok(b) => format!("ok:{}", b.len()),
            Err(e) => err_name(&e).to_string(),
        };
        let body_text = format!("STORE put={put} get={get}\n");

        let headers = Fields::new();
        let _ = headers.set(&"content-type".to_string(), &[b"text/plain".to_vec()]);
        let response = OutgoingResponse::new(headers);
        let _ = response.set_status_code(200);
        let body = response.body().expect("response body");
        ResponseOutparam::set(outparam, Ok(response));
        let out = body.write().expect("body stream");
        out.blocking_write_and_flush(body_text.as_bytes())
            .expect("write body");
        drop(out);
        OutgoingBody::finish(body, None).expect("finish body");
    }
}
