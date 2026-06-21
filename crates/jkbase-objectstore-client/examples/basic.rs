//! Basic round-trip against a live jkbase object store.
//!
//! ```text
//! JKBASE_S3_ENDPOINT=https://storage.jkbase.app \
//! JKBASE_S3_ACCESS_KEY=JKBA... \
//! JKBASE_S3_SECRET=...        \
//! cargo run -p jkbase-objectstore-client --example basic
//! ```

use jkbase_objectstore_client::{ListObjectsOptions, ObjectClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::var("JKBASE_S3_ENDPOINT")?;
    let access_key = std::env::var("JKBASE_S3_ACCESS_KEY")?;
    let secret = std::env::var("JKBASE_S3_SECRET")?;

    let s3 = ObjectClient::new(endpoint, access_key, secret);
    let bucket = "sdk-example";

    if !s3.bucket_exists(bucket).await? {
        s3.create_bucket(bucket).await?;
        println!("created bucket {bucket}");
    }

    let etag = s3.put_object(bucket, "greeting.txt", b"hello from rust".to_vec(), "text/plain").await?;
    println!("put greeting.txt (etag {etag})");

    let body = s3.get_object_bytes(bucket, "greeting.txt").await?;
    println!("got back: {}", String::from_utf8_lossy(&body));

    print!("listing: ");
    let page = s3.list_objects(bucket, &ListObjectsOptions::new()).await?;
    for o in &page.objects {
        print!("{} ({}B) ", o.key, o.size);
    }
    println!();

    let url = s3.presigned_get(bucket, "greeting.txt", 300);
    println!("presigned GET (5 min): {url}");

    s3.delete_object(bucket, "greeting.txt").await?;
    println!("deleted greeting.txt");
    Ok(())
}
