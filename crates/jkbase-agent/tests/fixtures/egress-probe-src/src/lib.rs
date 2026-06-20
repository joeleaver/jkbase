//! Egress-probe fixture for the on-box egress e2e (`function_egress_e2e`).
//!
//! Issues ONE outbound request to a target supplied by request headers and reports the
//! gate's verdict in the response body, so a single VM boot can drive every egress case
//! (allow / sandbox-deny / platform-deny / DNS-rebind / ipv6-refuse) by varying headers:
//!   x-egress-scheme:    "http" | "https"  (default https)
//!   x-egress-authority: "host[:port]"      (default example.com)
//!   x-egress-path:      "/..."             (default /)
//! Body: `RESULT:ALLOWED:<status>` when the outbound future resolves to a response, else
//! `RESULT:DENIED` (the host gate refused, or the outbound errored).

use wasi::http::types::{
    Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse,
    ResponseOutparam, Scheme,
};

struct Component;

wasi::http::proxy::export!(Component);

impl wasi::exports::http::incoming_handler::Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        let hdrs = request.headers();
        let get = |name: &str| -> Option<String> {
            hdrs.get(&name.to_string())
                .into_iter()
                .next()
                .and_then(|v| String::from_utf8(v).ok())
        };
        let scheme = get("x-egress-scheme").unwrap_or_else(|| "https".to_string());
        let authority = get("x-egress-authority").unwrap_or_else(|| "example.com".to_string());
        let path = get("x-egress-path").unwrap_or_else(|| "/".to_string());

        let result = probe(&scheme, &authority, &path);
        let body_text = format!("RESULT:{result}\n");

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

/// Issue the outbound request and AWAIT the future — the gate's verdict surfaces only on
/// resolution (like real `wasi:http`). `ALLOWED:<status>` on a response, `DENIED` otherwise.
fn probe(scheme: &str, authority: &str, path: &str) -> String {
    let req = OutgoingRequest::new(Fields::new());
    let _ = req.set_method(&Method::Get);
    let sc = if scheme == "http" { Scheme::Http } else { Scheme::Https };
    let _ = req.set_scheme(Some(&sc));
    let _ = req.set_authority(Some(authority));
    let _ = req.set_path_with_query(Some(path));

    let future = match wasi::http::outgoing_handler::handle(req, None) {
        Ok(f) => f,
        Err(_) => return "DENIED".to_string(),
    };
    future.subscribe().block();
    match future.get() {
        Some(Ok(Ok(response))) => format!("ALLOWED:{}", response.status()),
        _ => "DENIED".to_string(),
    }
}
