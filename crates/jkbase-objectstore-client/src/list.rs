//! Listing: one page, eager auto-paging, and a lazy auto-paging [`Stream`].
//!
//! The server emits S3 `ListBucketResult` XML with V2 pagination
//! (`IsTruncated` / `NextContinuationToken`) and optional delimiter folding
//! (`CommonPrefixes`). `max-keys` is clamped server-side to `1..=1000`.

use crate::xml::strip_quotes;
use crate::{ObjectClient, ReqBody, Result, xml};
use reqwest::Method;

/// Query options for [`ObjectClient::list_objects`].
#[derive(Debug, Clone, Default)]
pub struct ListObjectsOptions {
    /// Restrict to keys starting with this prefix.
    pub prefix: Option<String>,
    /// Fold keys sharing a delimiter into `common_prefixes` (e.g. `/` for "folders").
    pub delimiter: Option<String>,
    /// Page size (server clamps to `1..=1000`; default 1000).
    pub max_keys: Option<u32>,
    /// Resume from a previous page's `next_continuation_token`.
    pub continuation_token: Option<String>,
}

impl ListObjectsOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn prefix(mut self, p: impl Into<String>) -> Self {
        self.prefix = Some(p.into());
        self
    }
    pub fn delimiter(mut self, d: impl Into<String>) -> Self {
        self.delimiter = Some(d.into());
        self
    }
    pub fn max_keys(mut self, n: u32) -> Self {
        self.max_keys = Some(n);
        self
    }
    pub fn continuation_token(mut self, t: impl Into<String>) -> Self {
        self.continuation_token = Some(t.into());
        self
    }
}

/// One object in a listing.
#[derive(Debug, Clone)]
pub struct ObjectEntry {
    pub key: String,
    /// Raw hex MD5 ETag (quotes stripped).
    pub etag: Option<String>,
    pub size: u64,
    /// `LastModified` ISO-8601 string, verbatim.
    pub last_modified: Option<String>,
}

/// One page of a listing.
#[derive(Debug, Clone)]
pub struct ListPage {
    pub objects: Vec<ObjectEntry>,
    /// Folded common prefixes (only when a delimiter was given).
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    /// Token to fetch the next page (present iff `is_truncated`).
    pub next_continuation_token: Option<String>,
    /// `KeyCount` the server reported for this page.
    pub key_count: usize,
    /// The effective (clamped) `MaxKeys` the server used.
    pub max_keys: u32,
}

impl ObjectClient {
    /// Fetch one page of object listings.
    pub async fn list_objects(&self, bucket: &str, opts: &ListObjectsOptions) -> Result<ListPage> {
        let mut q: Vec<(String, String)> = Vec::new();
        if let Some(p) = opts.prefix.as_deref().filter(|p| !p.is_empty()) {
            q.push(("prefix".into(), p.into()));
        }
        if let Some(d) = opts.delimiter.as_deref().filter(|d| !d.is_empty()) {
            q.push(("delimiter".into(), d.into()));
        }
        if let Some(mk) = opts.max_keys {
            q.push(("max-keys".into(), mk.to_string()));
        }
        if let Some(t) = opts.continuation_token.as_deref().filter(|t| !t.is_empty()) {
            q.push(("continuation-token".into(), t.into()));
        }
        let resp = self.send(Method::GET, &format!("/{bucket}"), &q, None, ReqBody::Empty).await?;
        let body = resp.text().await?;
        Ok(parse_list_page(&body))
    }

    /// Eagerly walk every page and collect all objects under `prefix` (flat — no
    /// delimiter). Use [`list_objects_paged`](Self::list_objects_paged) to stream lazily.
    pub async fn list_all(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectEntry>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut opts = ListObjectsOptions::new().max_keys(1000);
            if !prefix.is_empty() {
                opts = opts.prefix(prefix);
            }
            if let Some(t) = &token {
                opts = opts.continuation_token(t.clone());
            }
            let page = self.list_objects(bucket, &opts).await?;
            out.extend(page.objects);
            // Truncated-but-no-token would loop forever — stop instead.
            match (page.is_truncated, page.next_continuation_token) {
                (true, Some(t)) => token = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Convenience: just the keys, auto-paged.
    pub async fn list_all_keys(&self, bucket: &str, prefix: &str) -> Result<Vec<String>> {
        Ok(self.list_all(bucket, prefix).await?.into_iter().map(|o| o.key).collect())
    }

    /// A lazy auto-paging stream of [`ListPage`]s, honouring the delimiter in `opts`.
    /// Each `.next().await` fetches one page; iteration stops at the last page.
    ///
    /// ```no_run
    /// # async fn d(s3: &jkbase_objectstore_client::ObjectClient) -> Result<(), jkbase_objectstore_client::Error> {
    /// use futures_util::StreamExt;
    /// use jkbase_objectstore_client::ListObjectsOptions;
    /// let mut pages = Box::pin(s3.list_objects_paged("b", ListObjectsOptions::new().prefix("img/")));
    /// while let Some(page) = pages.next().await { for o in page?.objects { println!("{}", o.key); } }
    /// # Ok(()) }
    /// ```
    pub fn list_objects_paged<'a>(
        &'a self,
        bucket: &'a str,
        opts: ListObjectsOptions,
    ) -> impl futures_util::Stream<Item = Result<ListPage>> + 'a {
        let ListObjectsOptions { prefix, delimiter, max_keys, continuation_token } = opts;
        // State: `Some(token)` = fetch next with this continuation token; `None` = done.
        let init: Option<Option<String>> = Some(continuation_token);
        futures_util::stream::try_unfold(init, move |state| {
            let prefix = prefix.clone();
            let delimiter = delimiter.clone();
            async move {
                let token = match state {
                    Some(t) => t,
                    None => return Ok::<Option<(ListPage, Option<Option<String>>)>, crate::Error>(None),
                };
                let page = self
                    .list_objects(bucket, &ListObjectsOptions { prefix, delimiter, max_keys, continuation_token: token })
                    .await?;
                let next = match (page.is_truncated, &page.next_continuation_token) {
                    (true, Some(t)) => Some(Some(t.clone())),
                    _ => None,
                };
                Ok(Some((page, next)))
            }
        })
    }
}

/// Parse a `ListBucketResult` body into a [`ListPage`].
fn parse_list_page(body: &str) -> ListPage {
    let is_truncated = xml::tag(body, "IsTruncated").as_deref() == Some("true");
    let next_continuation_token =
        xml::tag(body, "NextContinuationToken").or_else(|| xml::tag(body, "NextMarker"));
    let max_keys = xml::tag(body, "MaxKeys").and_then(|s| s.parse().ok()).unwrap_or(1000);
    let common_prefixes = xml::blocks(body, "CommonPrefixes")
        .iter()
        .filter_map(|b| xml::tag(b, "Prefix"))
        .collect();
    let objects: Vec<ObjectEntry> = xml::blocks(body, "Contents")
        .iter()
        .map(|b| ObjectEntry {
            key: xml::tag(b, "Key").unwrap_or_default(),
            etag: xml::tag(b, "ETag").map(|e| strip_quotes(&e)),
            size: xml::tag(b, "Size").and_then(|s| s.parse().ok()).unwrap_or(0),
            last_modified: xml::tag(b, "LastModified"),
        })
        .collect();
    let key_count = xml::tag(body, "KeyCount").and_then(|s| s.parse().ok()).unwrap_or(objects.len());
    ListPage { objects, common_prefixes, is_truncated, next_continuation_token, key_count, max_keys }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_truncated_page() {
        let body = "<?xml version=\"1.0\"?><ListBucketResult><Name>b</Name><Prefix>img/</Prefix>\
            <MaxKeys>2</MaxKeys><KeyCount>2</KeyCount><IsTruncated>true</IsTruncated>\
            <NextContinuationToken>img/b</NextContinuationToken><NextMarker>img/b</NextMarker>\
            <Contents><Key>img/a</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;d41d&quot;</ETag><Size>10</Size></Contents>\
            <Contents><Key>img/b</Key><LastModified>2026-01-02T00:00:00.000Z</LastModified><ETag>&quot;abcd&quot;</ETag><Size>20</Size></Contents>\
            </ListBucketResult>";
        let page = parse_list_page(body);
        assert!(page.is_truncated);
        assert_eq!(page.next_continuation_token.as_deref(), Some("img/b"));
        assert_eq!(page.max_keys, 2);
        assert_eq!(page.key_count, 2);
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "img/a");
        assert_eq!(page.objects[0].etag.as_deref(), Some("d41d"));
        assert_eq!(page.objects[1].size, 20);
        assert!(page.common_prefixes.is_empty());
    }

    #[test]
    fn parses_delimiter_folding() {
        let body = "<ListBucketResult><Name>b</Name><Delimiter>/</Delimiter><MaxKeys>1000</MaxKeys>\
            <KeyCount>2</KeyCount><IsTruncated>false</IsTruncated>\
            <Contents><Key>top.txt</Key><Size>1</Size></Contents>\
            <CommonPrefixes><Prefix>img/</Prefix></CommonPrefixes>\
            <CommonPrefixes><Prefix>doc/</Prefix></CommonPrefixes></ListBucketResult>";
        let page = parse_list_page(body);
        assert!(!page.is_truncated);
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "top.txt");
        assert_eq!(page.common_prefixes, vec!["img/".to_string(), "doc/".to_string()]);
        // The top-level <Prefix> (none here) must never leak into common_prefixes.
    }
}
