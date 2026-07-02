//! Per-bucket CORS configuration: the S3 `CORSConfiguration` model, its (hand-
//! rolled, house-style) XML wire form, and the origin/method/header matching the
//! front uses to answer preflight `OPTIONS` and stamp `Access-Control-*` on actual
//! responses.
//!
//! Stored as a JSON sidecar (see `store.rs`), never trusted as a security boundary:
//! a bucket's CORS policy only governs which *browser origins* may read the tenant's
//! OWN bucket — it never crosses a tenant edge, so lenient parsing is safe (a
//! malformed rule just fails to grant, it can't grant someone else's data).

use serde::{Deserialize, Serialize};

/// Upper bounds on a stored config. It's the tenant's own bucket, so these only
/// exist to keep one absurd `PutBucketCors` from bloating the sidecar / matching
/// loop — not as a tenant boundary.
const MAX_RULES: usize = 100;
const MAX_LIST: usize = 100;
/// 30 days — S3 caps browser preflight caching well under this anyway.
const MAX_AGE_CEILING: u64 = 30 * 24 * 3600;
/// The only methods S3 CORS rules may name.
const VALID_METHODS: [&str; 5] = ["GET", "PUT", "POST", "DELETE", "HEAD"];

/// One `<CORSRule>`. Lists are stored verbatim (origins/headers case-sensitive on
/// the wire, matched per S3 rules below).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorsRule {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

/// A bucket's ordered CORS rules (first match wins, mirroring S3).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorsConfig {
    pub rules: Vec<CorsRule>,
}

/// What a matched preflight grants — copied onto the `204` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightGrant {
    /// The exact `Origin` to echo, or `*` when the rule allows all origins.
    pub allow_origin: String,
    /// Comma-joined methods the rule permits.
    pub allow_methods: String,
    /// The requested headers, echoed back (S3 reflects the client's ask).
    pub allow_headers: Option<String>,
    pub max_age: Option<u64>,
    /// `true` when `allow_origin` is a specific origin (⇒ response must `Vary: Origin`).
    pub vary_origin: bool,
}

/// What a matched actual (non-preflight) request grants — stamped onto the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActualGrant {
    pub allow_origin: String,
    pub expose_headers: Option<String>,
    pub vary_origin: bool,
}

impl CorsConfig {
    /// Match a browser preflight: the first rule whose origin allows `origin`, whose
    /// methods include `req_method`, and whose headers allow EVERY requested header.
    /// `None` ⇒ deny (the front returns 403 with no `Access-Control-*`, so the browser
    /// blocks the real request).
    pub fn match_preflight(
        &self,
        origin: &str,
        req_method: &str,
        req_headers: &[String],
    ) -> Option<PreflightGrant> {
        let m = req_method.trim().to_ascii_uppercase();
        for rule in &self.rules {
            let Some(star) = rule.origin_grant(origin) else {
                continue;
            };
            if !rule
                .allowed_methods
                .iter()
                .any(|am| am.trim().eq_ignore_ascii_case(&m))
            {
                continue;
            }
            if !req_headers.iter().all(|h| rule.header_allowed(h)) {
                continue;
            }
            return Some(PreflightGrant {
                allow_origin: if star { "*".into() } else { origin.to_string() },
                allow_methods: rule
                    .allowed_methods
                    .iter()
                    .map(|s| s.trim().to_ascii_uppercase())
                    .collect::<Vec<_>>()
                    .join(", "),
                allow_headers: (!req_headers.is_empty()).then(|| req_headers.join(", ")),
                max_age: rule.max_age_seconds,
                vary_origin: !star,
            });
        }
        None
    }

    /// Match an actual request: the first rule whose origin allows `origin` and whose
    /// methods include `method`. Used to stamp `Access-Control-Allow-Origin` /
    /// `-Expose-Headers` on the real GET/PUT/… response.
    pub fn match_actual(&self, origin: &str, method: &str) -> Option<ActualGrant> {
        let m = method.trim().to_ascii_uppercase();
        for rule in &self.rules {
            let Some(star) = rule.origin_grant(origin) else {
                continue;
            };
            if !rule
                .allowed_methods
                .iter()
                .any(|am| am.trim().eq_ignore_ascii_case(&m))
            {
                continue;
            }
            return Some(ActualGrant {
                allow_origin: if star { "*".into() } else { origin.to_string() },
                expose_headers: (!rule.expose_headers.is_empty())
                    .then(|| rule.expose_headers.join(", ")),
                vary_origin: !star,
            });
        }
        None
    }
}

impl CorsRule {
    /// `Some(is_star)` when this rule's origins allow `origin`: `is_star` is true only
    /// for a bare `*` allow-all (⇒ the response may echo `*` instead of the origin).
    fn origin_grant(&self, origin: &str) -> Option<bool> {
        let mut star = false;
        let mut matched = false;
        for pat in &self.allowed_origins {
            if pat == "*" {
                star = true;
                matched = true;
            } else if origin_pattern_matches(pat, origin) {
                matched = true;
            }
        }
        matched.then_some(star)
    }

    /// A requested header is allowed if any `AllowedHeader` is `*` or matches it
    /// (case-insensitive, with S3's single-`*` wildcard). Header names are
    /// case-insensitive per HTTP.
    fn header_allowed(&self, header: &str) -> bool {
        let h = header.trim();
        self.allowed_headers.iter().any(|pat| {
            let pat = pat.trim();
            pat == "*" || wildcard_match_ci(pat, h)
        })
    }
}

/// S3 `AllowedOrigin` matching: exact, or a SINGLE `*` wildcard splitting into a
/// prefix + suffix (`https://*.example.com`). Origins are compared as-is (the scheme
/// + host a browser sends are already normalized lowercase).
fn origin_pattern_matches(pattern: &str, origin: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == origin,
        // Reject a second `*` (S3 permits at most one) — treat as no match.
        Some((pre, post)) if !post.contains('*') => {
            origin.len() >= pre.len() + post.len()
                && origin.starts_with(pre)
                && origin.ends_with(post)
        }
        Some(_) => false,
    }
}

/// Case-insensitive exact-or-single-`*`-wildcard match (for `AllowedHeader`).
fn wildcard_match_ci(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern.eq_ignore_ascii_case(value),
        Some((pre, post)) if !post.contains('*') => {
            value.len() >= pre.len() + post.len()
                && value.get(..pre.len()).is_some_and(|s| s.eq_ignore_ascii_case(pre))
                && value
                    .get(value.len() - post.len()..)
                    .is_some_and(|s| s.eq_ignore_ascii_case(post))
        }
        Some(_) => false,
    }
}

// ---- S3 XML wire form -----------------------------------------------------

/// Parse an S3 `PutBucketCors` body. Lenient by design (see module docs): scans
/// `<CORSRule>` blocks and collects the repeated child tags. Returns `Err` only for
/// input a tenant would want rejected: no rules, an over-limit list, or a method S3
/// doesn't allow — so a typo'd policy fails loudly instead of silently not working.
pub fn parse_cors_config_xml(xml: &str) -> Result<CorsConfig, String> {
    let mut rules = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<CORSRule>") {
        rest = &rest[i + "<CORSRule>".len()..];
        let end = rest.find("</CORSRule>").ok_or("unterminated <CORSRule>")?;
        let block = &rest[..end];
        rest = &rest[end + "</CORSRule>".len()..];

        let rule = CorsRule {
            allowed_origins: collect_tags(block, "AllowedOrigin"),
            allowed_methods: collect_tags(block, "AllowedMethod"),
            allowed_headers: collect_tags(block, "AllowedHeader"),
            expose_headers: collect_tags(block, "ExposeHeader"),
            max_age_seconds: collect_tags(block, "MaxAgeSeconds")
                .first()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|n| n.min(MAX_AGE_CEILING)),
        };
        if rule.allowed_origins.is_empty() {
            return Err("<CORSRule> requires at least one <AllowedOrigin>".into());
        }
        if rule.allowed_methods.is_empty() {
            return Err("<CORSRule> requires at least one <AllowedMethod>".into());
        }
        for meth in &rule.allowed_methods {
            let u = meth.trim().to_ascii_uppercase();
            if !VALID_METHODS.contains(&u.as_str()) {
                return Err(format!("invalid <AllowedMethod>: {meth}"));
            }
        }
        if rule.allowed_origins.len() > MAX_LIST
            || rule.allowed_methods.len() > MAX_LIST
            || rule.allowed_headers.len() > MAX_LIST
            || rule.expose_headers.len() > MAX_LIST
        {
            return Err("too many entries in a <CORSRule>".into());
        }
        rules.push(rule);
        if rules.len() > MAX_RULES {
            return Err("too many <CORSRule> entries".into());
        }
    }
    if rules.is_empty() {
        return Err("CORSConfiguration requires at least one <CORSRule>".into());
    }
    Ok(CorsConfig { rules })
}

/// Serialize to the S3 `GetBucketCors` XML form.
pub fn cors_config_to_xml(cfg: &CorsConfig) -> String {
    let mut x = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for r in &cfg.rules {
        x.push_str("<CORSRule>");
        for o in &r.allowed_origins {
            x.push_str(&format!("<AllowedOrigin>{}</AllowedOrigin>", xml_escape(o)));
        }
        for m in &r.allowed_methods {
            x.push_str(&format!("<AllowedMethod>{}</AllowedMethod>", xml_escape(m)));
        }
        for h in &r.allowed_headers {
            x.push_str(&format!("<AllowedHeader>{}</AllowedHeader>", xml_escape(h)));
        }
        for e in &r.expose_headers {
            x.push_str(&format!("<ExposeHeader>{}</ExposeHeader>", xml_escape(e)));
        }
        if let Some(age) = r.max_age_seconds {
            x.push_str(&format!("<MaxAgeSeconds>{age}</MaxAgeSeconds>"));
        }
        x.push_str("</CORSRule>");
    }
    x.push_str("</CORSConfiguration>");
    x
}

/// All `<tag>…</tag>` inner texts in document order (unescaped), trimmed & non-empty.
fn collect_tags(block: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = block;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        let Some(j) = rest.find(&close) else { break };
        let val = xml_unescape(rest[..j].trim());
        if !val.is_empty() {
            out.push(val);
        }
        rest = &rest[j + close.len()..];
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(xml: &str) -> CorsConfig {
        parse_cors_config_xml(xml).unwrap()
    }

    const SAMPLE: &str = "<CORSConfiguration><CORSRule>\
        <AllowedOrigin>https://app.example.com</AllowedOrigin>\
        <AllowedOrigin>https://*.play.dev</AllowedOrigin>\
        <AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>\
        <AllowedHeader>*</AllowedHeader>\
        <ExposeHeader>ETag</ExposeHeader><ExposeHeader>Content-Range</ExposeHeader>\
        <MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>";

    #[test]
    fn parses_all_fields() {
        let c = cfg(SAMPLE);
        assert_eq!(c.rules.len(), 1);
        let r = &c.rules[0];
        assert_eq!(r.allowed_origins.len(), 2);
        assert_eq!(r.allowed_methods, ["GET", "PUT"]);
        assert_eq!(r.expose_headers, ["ETag", "Content-Range"]);
        assert_eq!(r.max_age_seconds, Some(3600));
    }

    #[test]
    fn roundtrips_through_xml() {
        let c = cfg(SAMPLE);
        assert_eq!(cfg(&cors_config_to_xml(&c)), c);
    }

    #[test]
    fn preflight_allows_exact_and_wildcard_origin() {
        let c = cfg(SAMPLE);
        assert!(
            c.match_preflight("https://app.example.com", "GET", &[])
                .is_some()
        );
        assert!(
            c.match_preflight("https://x.play.dev", "put", &["content-type".into()])
                .is_some()
        );
    }

    #[test]
    fn preflight_denies_bad_origin_method_or_header() {
        let c = cfg(SAMPLE);
        assert!(c.match_preflight("https://evil.com", "GET", &[]).is_none());
        assert!(
            c.match_preflight("https://app.example.com", "DELETE", &[])
                .is_none()
        );
        // A rule allowing `*` headers still accepts any requested header.
        assert!(
            c.match_preflight("https://app.example.com", "GET", &["x-anything".into()])
                .is_some()
        );
    }

    #[test]
    fn header_wildcard_is_scoped_when_not_star() {
        let c = cfg("<CORSRule><AllowedOrigin>*</AllowedOrigin>\
            <AllowedMethod>GET</AllowedMethod>\
            <AllowedHeader>x-amz-*</AllowedHeader></CORSRule>");
        // `*` origin ⇒ echo `*`, no Vary.
        let g = c.match_preflight("https://any.example", "GET", &["x-amz-date".into()]);
        assert_eq!(g.as_ref().unwrap().allow_origin, "*");
        assert!(!g.unwrap().vary_origin);
        assert!(
            c.match_preflight("https://any.example", "GET", &["authorization".into()])
                .is_none()
        );
    }

    #[test]
    fn actual_match_exposes_headers_and_varies() {
        let c = cfg(SAMPLE);
        let g = c.match_actual("https://app.example.com", "GET").unwrap();
        assert_eq!(g.allow_origin, "https://app.example.com");
        assert!(g.vary_origin);
        assert_eq!(g.expose_headers.as_deref(), Some("ETag, Content-Range"));
    }

    #[test]
    fn rejects_empty_or_invalid() {
        assert!(parse_cors_config_xml("<CORSConfiguration></CORSConfiguration>").is_err());
        assert!(
            parse_cors_config_xml(
                "<CORSRule><AllowedOrigin>*</AllowedOrigin>\
                 <AllowedMethod>TRACE</AllowedMethod></CORSRule>"
            )
            .is_err()
        );
        assert!(
            parse_cors_config_xml("<CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule>")
                .is_err()
        );
    }

    #[test]
    fn escapes_and_unescapes_origins() {
        let c = cfg("<CORSRule><AllowedOrigin>https://a.example?x=1&amp;y=2</AllowedOrigin>\
            <AllowedMethod>GET</AllowedMethod></CORSRule>");
        assert_eq!(c.rules[0].allowed_origins[0], "https://a.example?x=1&y=2");
        assert!(cors_config_to_xml(&c).contains("&amp;y=2"));
    }
}
