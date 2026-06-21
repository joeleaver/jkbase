//! Minimal XML extraction for the S3 responses this client consumes.
//!
//! The server's responses (see `jkbase-objectstore::http`) are machine-generated with a
//! fixed shape — `ListBucketResult`, `Error`, `InitiateMultipartUploadResult`, … — so
//! targeted tag extraction is sufficient and keeps the dependency footprint tiny (no XML
//! parser dragged into a tenant app). We never *emit* attacker-influenced XML and only
//! read fields by exact tag name, so this is not a general-purpose parser.

/// Inner text of the first `<name>…</name>`, entity-unescaped. `None` if absent.
pub(crate) fn tag(xml: &str, name: &str) -> Option<String> {
    inner(xml, name).map(|(s, _)| unescape(s))
}

/// Inner text of every `<name>…</name>` in document order, entity-unescaped.
pub(crate) fn tags(xml: &str, name: &str) -> Vec<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        match rest.find(&close) {
            Some(j) => {
                out.push(unescape(&rest[..j]));
                rest = &rest[j + close.len()..];
            }
            None => break,
        }
    }
    out
}

/// Raw inner XML (NOT unescaped) of every `<name>…</name>` block in document order —
/// used to iterate repeated record wrappers like `<Contents>` / `<Upload>` and then pull
/// their child tags.
pub(crate) fn blocks<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        match rest.find(&close) {
            Some(j) => {
                out.push(&rest[..j]);
                rest = &rest[j + close.len()..];
            }
            None => break,
        }
    }
    out
}

/// The slice between the first `<name>` and its `</name>`, plus the byte offset just
/// past the close tag (for callers that want to keep scanning).
fn inner<'a>(xml: &'a str, name: &str) -> Option<(&'a str, usize)> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let i = xml.find(&open)? + open.len();
    let j = xml[i..].find(&close)? + i;
    Some((&xml[i..j], j + close.len()))
}

/// Reverse of the server's `xml_escape` (`&amp; &lt; &gt; &quot;`), tolerating the few
/// other common entities. Single left-to-right pass so escaped text can't be
/// double-decoded (`&amp;lt;` → `&lt;`, never `<`).
pub(crate) fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(amp) = rest.find('&') {
            out.push_str(&rest[..amp]);
            rest = &rest[amp..];
            let (decoded, consumed) = if let Some(r) = rest.strip_prefix("&amp;") {
                ('&', rest.len() - r.len())
            } else if let Some(r) = rest.strip_prefix("&lt;") {
                ('<', rest.len() - r.len())
            } else if let Some(r) = rest.strip_prefix("&gt;") {
                ('>', rest.len() - r.len())
            } else if let Some(r) = rest.strip_prefix("&quot;") {
                ('"', rest.len() - r.len())
            } else if let Some(r) = rest.strip_prefix("&#39;").or_else(|| rest.strip_prefix("&apos;")) {
                ('\'', rest.len() - r.len())
            } else {
                // A bare '&' that isn't a known entity — emit it literally and move on.
                out.push('&');
                rest = &rest['&'.len_utf8()..];
                continue;
            };
            out.push(decoded);
            rest = &rest[consumed..];
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

/// Strip one layer of surrounding double-quotes (S3 ETags are quoted; we expose the raw
/// hex). A value without both quotes is returned unchanged.
pub(crate) fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_tags_and_blocks() {
        let xml = "<ListBucketResult><Contents><Key>a/b</Key><Size>3</Size></Contents>\
                   <Contents><Key>a/c</Key><Size>4</Size></Contents>\
                   <IsTruncated>true</IsTruncated></ListBucketResult>";
        assert_eq!(tag(xml, "IsTruncated").as_deref(), Some("true"));
        let bs = blocks(xml, "Contents");
        assert_eq!(bs.len(), 2);
        assert_eq!(tag(bs[0], "Key").as_deref(), Some("a/b"));
        assert_eq!(tag(bs[1], "Size").as_deref(), Some("4"));
        assert_eq!(tags(xml, "Key"), vec!["a/b".to_string(), "a/c".to_string()]);
    }

    #[test]
    fn unescapes_entities_without_double_decoding() {
        assert_eq!(unescape("a &amp; b &lt;x&gt; &quot;q&quot;"), "a & b <x> \"q\"");
        assert_eq!(unescape("&amp;lt;"), "&lt;"); // not double-decoded
        assert_eq!(unescape("plain"), "plain");
        assert_eq!(unescape("trailing &"), "trailing &");
    }

    #[test]
    fn strips_etag_quotes() {
        assert_eq!(strip_quotes("\"deadbeef\""), "deadbeef");
        assert_eq!(strip_quotes("deadbeef"), "deadbeef");
        assert_eq!(strip_quotes("\""), "\"");
    }

    #[test]
    fn key_with_escaped_chars_round_trips() {
        // Server xml_escapes keys; a key containing '&' and '<' comes back decoded.
        let xml = "<Contents><Key>a&amp;b/&lt;c&gt;</Key></Contents>";
        assert_eq!(tag(xml, "Key").as_deref(), Some("a&b/<c>"));
    }
}
