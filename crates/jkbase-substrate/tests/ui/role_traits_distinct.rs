// A `BlobStore` (R4) is NOT a `DataDiskProvider` (R3); passing one where the other
// is required must be a type error. If this ever compiles, the seam has collapsed.
use jkbase_substrate::{BlobStore, DataDiskProvider};
use std::sync::Arc;

fn needs_data_disk(_provider: Arc<dyn DataDiskProvider>) {}

fn check(blob: Arc<dyn BlobStore>) {
    needs_data_disk(blob);
}

fn main() {}
