# jkbase-objectstore-client

A lean, tenant-facing Rust client for the [jkbase](../../README.md) S3-compatible object
store (`storage.{your-domain}`).

It signs every request with AWS SigV4 via the shared [`jkbase-sigv4`](../jkbase-sigv4)
crate — the *same* canonicalisation the server verifies — so your app can read and write
its buckets without pulling in an AWS SDK or any jkbase server code. The only runtime
dependencies are `reqwest` and the tiny signer.

```toml
[dependencies]
jkbase-objectstore-client = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quickstart

```rust
use jkbase_objectstore_client::ObjectClient;

#[tokio::main]
async fn main() -> Result<(), jkbase_objectstore_client::Error> {
    // The endpoint + the object-store credentials you issued with
    // `jkbase access-key issue` (or the console Storage tab).
    let s3 = ObjectClient::new("https://storage.jkbase.app", "JKBA…", "secret…");

    s3.create_bucket("assets").await?;
    s3.put_object("assets", "hello.txt", b"hi".to_vec(), "text/plain").await?;

    let body = s3.get_object_bytes("assets", "hello.txt").await?;
    assert_eq!(&body[..], b"hi");

    for key in s3.list_all_keys("assets", "").await? {
        println!("{key}");
    }
    Ok(())
}
```

## What it does

| Area | API |
|---|---|
| **Buckets** | `create_bucket`, `delete_bucket`, `bucket_exists`, `list_buckets` |
| **Objects** | `put_object`, `put_object_stream`, `get_object` → [`GetObject`], `get_object_bytes`, `head_object`, `delete_object` |
| **Listing** | `list_objects(ListObjectsOptions)` (prefix, delimiter, `max_keys`, continuation token), `list_all` / `list_all_keys` (eager auto-page), `list_objects_paged` (lazy auto-paging `Stream`) |
| **Multipart** | `create_multipart` → [`MultipartUpload`] `upload_part` / `upload_part_stream` → `complete` / `abort`; `list_multipart_uploads` |
| **Presigned URLs** | `presigned_get`, `presigned_put` (credential-free, time-limited links) |
| **Errors** | typed [`S3ErrorCode`] with `Error::is_not_found()` / `is_quota()` / `is_retryable()` |

### Streaming

`put_object_stream` takes any `reqwest::Body` (a `wrap_stream`ed `Stream`, a file, …) plus
the exact `content_length`, and uploads without buffering (the server requires a declared
length for object writes). `get_object().into_stream()` yields the body in chunks:

```rust
use futures_util::StreamExt;
let got = s3.get_object("assets", "big.bin").await?;
let mut stream = got.into_stream();
while let Some(chunk) = stream.next().await {
    let bytes = chunk?;
    // write to disk / hash / forward …
}
```

> Note: streaming uploads sign with `UNSIGNED-PAYLOAD` (hashing a stream would force it
> back into memory). For in-memory uploads you can opt into payload binding with
> `ObjectClient::new(..).with_payload_signing(true)` — the server then rejects a body
> that doesn't match its signed SHA-256.

### Pagination

```rust
use futures_util::StreamExt;
use jkbase_objectstore_client::ListObjectsOptions;

let mut pages = Box::pin(s3.list_objects_paged("assets", ListObjectsOptions::new().prefix("img/")));
while let Some(page) = pages.next().await {
    let page = page?;
    for o in page.objects { println!("{} ({} bytes)", o.key, o.size); }
}
```

### Typed errors

```rust
match s3.head_object("assets", "missing").await {
    Ok(meta) => println!("{:?}", meta),
    Err(e) if e.is_not_found() => println!("not there"),
    Err(e) if e.is_quota() => println!("over quota"),
    Err(e) => return Err(e),
}
```

## Advanced: the `aws-sdk-s3` escape hatch

The service is S3-compatible (path-style addressing, static access keys, single region),
so if you already depend on the AWS Rust SDK — or need a feature this crate doesn't cover
— point `aws-sdk-s3` at the endpoint instead:

```rust
use aws_sdk_s3::config::{Credentials, Region};

let creds = Credentials::new("JKBA…", "secret…", None, None, "jkbase");
let conf = aws_sdk_s3::config::Builder::new()
    .region(Region::new("us-east-1"))
    .endpoint_url("https://storage.jkbase.app")
    .credentials_provider(creds)
    .force_path_style(true) // jkbase uses path-style (/{bucket}/{key}), not vhost-style
    .build();
let s3 = aws_sdk_s3::Client::from_conf(conf);

s3.put_object().bucket("assets").key("hello.txt").body(b"hi".to_vec().into()).send().await?;
```

That pulls in the full AWS SDK and its dependency tree; this crate exists for the lean,
zero-AWS-dep happy path.

## License

MIT OR Apache-2.0
