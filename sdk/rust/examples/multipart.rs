//! Multipart upload against a live jkbase object store.
//!
//! ```text
//! JKBASE_S3_ENDPOINT=https://storage.jkbase.app \
//! JKBASE_S3_ACCESS_KEY=JKBA... \
//! JKBASE_S3_SECRET=...        \
//! cargo run -p jkbase-objectstore-client --example multipart
//! ```

use jkbase_objectstore_client::ObjectClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::var("JKBASE_S3_ENDPOINT")?;
    let access_key = std::env::var("JKBASE_S3_ACCESS_KEY")?;
    let secret = std::env::var("JKBASE_S3_SECRET")?;

    let s3 = ObjectClient::new(endpoint, access_key, secret);
    let bucket = "sdk-example";
    if !s3.bucket_exists(bucket).await? {
        s3.create_bucket(bucket).await?;
    }

    // Initiate, upload a few parts, then complete (parts are concatenated in order).
    let mut upload = s3
        .create_multipart(bucket, "report.bin", "application/octet-stream")
        .await?;
    println!("upload id: {}", upload.upload_id());
    for (n, chunk) in [
        (1, vec![b'A'; 64]),
        (2, vec![b'B'; 32]),
        (3, vec![b'C'; 16]),
    ] {
        upload.upload_part(n, chunk).await?;
        println!("uploaded part {n}");
    }
    let etag = upload.complete().await?;
    println!("completed; final etag {etag}");

    let assembled = s3.get_object_bytes(bucket, "report.bin").await?;
    println!("assembled object is {} bytes", assembled.len());

    s3.delete_object(bucket, "report.bin").await?;
    Ok(())
}
