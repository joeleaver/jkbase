//! Minimal jkbase Rust function: a `wasi:http` component.
//!
//! A function exports `wasi:http/incoming-handler` (the `wasi:http/proxy` world) — the
//! same ABI every jkbase language target compiles to. Write your logic in `handle`; the
//! platform builds this to a component server-side (`cargo build --release --target
//! wasm32-wasip2`) and runs it in the per-project microVM.
//!
//! Available today: the request, response, compute, and project **secrets** as env vars.
//! NOT available yet: outbound network (`fetch`) and object-store access — those arrive
//! together in the host-mediated outbound-I/O work; until then an outbound request is
//! denied by the platform (demonstrated by the `egress` line below).

use wasi::http::types::{
    Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse,
    ResponseOutparam, Scheme,
};

struct Component;

wasi::http::proxy::export!(Component);

impl wasi::exports::http::incoming_handler::Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        let method = format!("{:?}", request.method());
        let path = request.path_with_query().unwrap_or_else(|| "/".to_string());
        let egress = probe_egress();
        // Project secrets are injected as env vars (empty until the secrets phase wires
        // the host side). Echoing one demonstrates the capability without leaking on a
        // shared resource — it is this project's own secret.
        let demo = std::env::var("DEMO_SECRET").unwrap_or_else(|_| "<unset>".to_string());

        let body_text = format!(
            "hello from a wasi:http component\nmethod={method}\npath={path}\negress={egress}\nDEMO_SECRET={demo}\n"
        );

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

/// Attempt an outbound request. The platform denies all egress today, so this reports
/// `DENIED` (the host rejects `send_request` before any socket opens).
fn probe_egress() -> &'static str {
    let req = OutgoingRequest::new(Fields::new());
    let _ = req.set_method(&Method::Get);
    let _ = req.set_scheme(Some(&Scheme::Https));
    let _ = req.set_authority(Some("example.com"));
    let _ = req.set_path_with_query(Some("/"));
    match wasi::http::outgoing_handler::handle(req, None) {
        Ok(_) => "ALLOWED",
        Err(_) => "DENIED",
    }
}
