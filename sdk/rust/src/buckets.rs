//! Bucket operations: create, delete, existence check, list.

use crate::{Error, ObjectClient, ReqBody, Result, xml};
use reqwest::Method;

impl ObjectClient {
    /// Create a bucket. `Err(..).code() == BucketAlreadyExists` if it already exists.
    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        self.send(
            Method::PUT,
            &format!("/{bucket}"),
            &[],
            None,
            ReqBody::Empty,
        )
        .await?;
        Ok(())
    }

    /// Delete an (empty) bucket. `Err(..).code() == BucketNotEmpty` if it still holds objects.
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        self.send(
            Method::DELETE,
            &format!("/{bucket}"),
            &[],
            None,
            ReqBody::Empty,
        )
        .await?;
        Ok(())
    }

    /// Whether a bucket exists (HEAD), mapping a 404 to `Ok(false)` rather than an error.
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        match self
            .send(
                Method::HEAD,
                &format!("/{bucket}"),
                &[],
                None,
                ReqBody::Empty,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(Error::Api { status: 404, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// List the names of all buckets owned by these credentials.
    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        let resp = self
            .send(Method::GET, "/", &[], None, ReqBody::Empty)
            .await?;
        let body = resp.text().await?;
        Ok(xml::tags(&body, "Name"))
    }
}
