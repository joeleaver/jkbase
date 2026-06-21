//! Multipart uploads: initiate → upload parts → complete (or abort), plus listing
//! pending uploads.
//!
//! The engine concatenates parts in the order given to `complete`, keyed by part number
//! (it does not require per-part ETags), so [`MultipartUpload`] tracks the parts you've
//! uploaded and sends them in ascending part-number order on completion.

use crate::objects::etag_of;
use crate::xml::strip_quotes;
use crate::{Error, ObjectClient, ReqBody, Result, object_path, validate_object_key, xml};
use bytes::Bytes;
use reqwest::Method;

/// A pending multipart upload listed by [`ObjectClient::list_multipart_uploads`].
#[derive(Debug, Clone)]
pub struct PendingUpload {
    pub key: String,
    pub upload_id: String,
    /// `Initiated` ISO-8601 string, verbatim.
    pub initiated: Option<String>,
}

/// An in-progress multipart upload. Upload parts, then [`complete`](Self::complete) or
/// [`abort`](Self::abort).
pub struct MultipartUpload<'a> {
    client: &'a ObjectClient,
    bucket: String,
    key: String,
    upload_id: String,
    /// (part_number, etag) in upload order; sorted by part number on completion.
    parts: Vec<(u32, String)>,
}

impl ObjectClient {
    /// Initiate a multipart upload, returning a handle bound to this client.
    pub async fn create_multipart(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
    ) -> Result<MultipartUpload<'_>> {
        validate_object_key(key)?;
        let resp = self
            .send(
                Method::POST,
                &object_path(bucket, key),
                &[("uploads".into(), String::new())],
                Some(content_type),
                ReqBody::Empty,
            )
            .await?;
        let body = resp.text().await?;
        let upload_id =
            xml::tag(&body, "UploadId").ok_or_else(|| Error::Decode("InitiateMultipartUpload: no UploadId".into()))?;
        Ok(MultipartUpload {
            client: self,
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id,
            parts: Vec::new(),
        })
    }

    /// List the pending multipart uploads in a bucket.
    pub async fn list_multipart_uploads(&self, bucket: &str) -> Result<Vec<PendingUpload>> {
        let resp = self
            .send(Method::GET, &format!("/{bucket}"), &[("uploads".into(), String::new())], None, ReqBody::Empty)
            .await?;
        let body = resp.text().await?;
        Ok(xml::blocks(&body, "Upload")
            .iter()
            .map(|b| PendingUpload {
                key: xml::tag(b, "Key").unwrap_or_default(),
                upload_id: xml::tag(b, "UploadId").unwrap_or_default(),
                initiated: xml::tag(b, "Initiated"),
            })
            .collect())
    }
}

impl MultipartUpload<'_> {
    /// The server-assigned upload id.
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    /// Upload one part (in-memory). Part numbers should be ascending and unique; the
    /// engine concatenates them in the order passed to `complete`.
    pub async fn upload_part(&mut self, part_number: u32, body: impl Into<Bytes>) -> Result<()> {
        let q = vec![
            ("uploadId".into(), self.upload_id.clone()),
            ("partNumber".into(), part_number.to_string()),
        ];
        let resp = self
            .client
            .send(Method::PUT, &object_path(&self.bucket, &self.key), &q, None, ReqBody::Bytes(body.into()))
            .await?;
        self.parts.push((part_number, etag_of(resp.headers())));
        Ok(())
    }

    /// Upload one part by streaming its body (no buffering). `content_length` is the part's
    /// exact byte length (the server requires a declared length for each part).
    pub async fn upload_part_stream(
        &mut self,
        part_number: u32,
        body: impl Into<reqwest::Body>,
        content_length: u64,
    ) -> Result<()> {
        let q = vec![
            ("uploadId".into(), self.upload_id.clone()),
            ("partNumber".into(), part_number.to_string()),
        ];
        let resp = self
            .client
            .send(
                Method::PUT,
                &object_path(&self.bucket, &self.key),
                &q,
                None,
                ReqBody::Stream(body.into(), content_length),
            )
            .await?;
        self.parts.push((part_number, etag_of(resp.headers())));
        Ok(())
    }

    /// Complete the upload, concatenating parts in ascending part-number order. Returns
    /// the final object's raw hex MD5 ETag.
    pub async fn complete(mut self) -> Result<String> {
        self.parts.sort_by_key(|(n, _)| *n);
        let mut body = String::from("<CompleteMultipartUpload>");
        for (n, _etag) in &self.parts {
            body.push_str(&format!("<Part><PartNumber>{n}</PartNumber></Part>"));
        }
        body.push_str("</CompleteMultipartUpload>");
        let resp = self
            .client
            .send(
                Method::POST,
                &object_path(&self.bucket, &self.key),
                &[("uploadId".into(), self.upload_id.clone())],
                Some("application/xml"),
                ReqBody::Bytes(Bytes::from(body)),
            )
            .await?;
        let xml_body = resp.text().await?;
        // A success body always carries <ETag>; its absence means a truncated/garbled
        // response, not an empty hash — error rather than hand back Ok("") (mirrors
        // create_multipart's UploadId handling).
        xml::tag(&xml_body, "ETag")
            .map(|e| strip_quotes(&e))
            .ok_or_else(|| Error::Decode("CompleteMultipartUpload: no ETag".into()))
    }

    /// Abort the upload, discarding any staged parts.
    pub async fn abort(self) -> Result<()> {
        self.client
            .send(
                Method::DELETE,
                &object_path(&self.bucket, &self.key),
                &[("uploadId".into(), self.upload_id.clone())],
                None,
                ReqBody::Empty,
            )
            .await?;
        Ok(())
    }
}
