//! Typed errors mapping the S3 `<Code>` set the jkbase object store emits.

use crate::xml;

/// The S3 `<Code>` from an error body, mapped to a typed variant. Covers everything
/// the engine ([`jkbase-objectstore`]) and the productized server front emit; any
/// other code is preserved verbatim in [`S3ErrorCode::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum S3ErrorCode {
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    BucketAlreadyExists,
    BucketNotEmpty,
    InvalidBucketName,
    InvalidArgument,
    RequestTimeout,
    /// An object write reached the server without a declared length (HTTP 411). The
    /// client sets one for buffered and length-declared streaming uploads.
    MissingContentLength,
    /// `x-amz-content-sha256` did not match the uploaded bytes.
    ContentSha256Mismatch,
    /// Storage-byte quota exceeded (HTTP 507).
    QuotaExceeded,
    /// Per-project object-count cap reached (HTTP 507).
    TooManyObjects,
    /// Per-project bucket-count cap reached.
    TooManyBuckets,
    /// Server asked the client to back off.
    SlowDown,
    AccessDenied,
    InternalError,
    /// A code not in the set above, kept verbatim.
    Other(String),
}

impl S3ErrorCode {
    /// The canonical S3 code string.
    pub fn as_str(&self) -> &str {
        match self {
            S3ErrorCode::NoSuchBucket => "NoSuchBucket",
            S3ErrorCode::NoSuchKey => "NoSuchKey",
            S3ErrorCode::NoSuchUpload => "NoSuchUpload",
            S3ErrorCode::BucketAlreadyExists => "BucketAlreadyExists",
            S3ErrorCode::BucketNotEmpty => "BucketNotEmpty",
            S3ErrorCode::InvalidBucketName => "InvalidBucketName",
            S3ErrorCode::InvalidArgument => "InvalidArgument",
            S3ErrorCode::RequestTimeout => "RequestTimeout",
            S3ErrorCode::MissingContentLength => "MissingContentLength",
            S3ErrorCode::ContentSha256Mismatch => "XAmzContentSHA256Mismatch",
            S3ErrorCode::QuotaExceeded => "QuotaExceeded",
            S3ErrorCode::TooManyObjects => "TooManyObjects",
            S3ErrorCode::TooManyBuckets => "TooManyBuckets",
            S3ErrorCode::SlowDown => "SlowDown",
            S3ErrorCode::AccessDenied => "AccessDenied",
            S3ErrorCode::InternalError => "InternalError",
            S3ErrorCode::Other(s) => s,
        }
    }

    fn from_code(s: &str) -> Self {
        match s {
            "NoSuchBucket" => S3ErrorCode::NoSuchBucket,
            "NoSuchKey" => S3ErrorCode::NoSuchKey,
            "NoSuchUpload" => S3ErrorCode::NoSuchUpload,
            "BucketAlreadyExists" => S3ErrorCode::BucketAlreadyExists,
            "BucketNotEmpty" => S3ErrorCode::BucketNotEmpty,
            "InvalidBucketName" => S3ErrorCode::InvalidBucketName,
            "InvalidArgument" => S3ErrorCode::InvalidArgument,
            "RequestTimeout" => S3ErrorCode::RequestTimeout,
            "MissingContentLength" => S3ErrorCode::MissingContentLength,
            "XAmzContentSHA256Mismatch" => S3ErrorCode::ContentSha256Mismatch,
            "QuotaExceeded" => S3ErrorCode::QuotaExceeded,
            "TooManyObjects" => S3ErrorCode::TooManyObjects,
            "TooManyBuckets" => S3ErrorCode::TooManyBuckets,
            "SlowDown" => S3ErrorCode::SlowDown,
            "AccessDenied" => S3ErrorCode::AccessDenied,
            "InternalError" => S3ErrorCode::InternalError,
            other => S3ErrorCode::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for S3ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that can go wrong talking to the object store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Transport / connection failure — no valid HTTP response was obtained.
    #[error("http transport: {0}")]
    Transport(#[from] reqwest::Error),
    /// The server returned a non-2xx status, usually with an S3 XML error body.
    #[error("object store {status} {code}: {message}")]
    Api {
        status: u16,
        code: S3ErrorCode,
        message: String,
    },
    /// A 2xx response whose body wasn't the expected shape.
    #[error("malformed response: {0}")]
    Decode(String),
    /// The client refused to send a request because the object key has a `.`/`..` path
    /// segment HTTP clients normalize away — the signed and sent paths would differ. Pick
    /// a key without bare dot segments.
    #[error("invalid object key: {0}")]
    InvalidKey(String),
}

impl Error {
    /// The typed S3 code, when this is an API error.
    pub fn code(&self) -> Option<&S3ErrorCode> {
        match self {
            Error::Api { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The HTTP status, when this is an API error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// A missing bucket / key / upload — the common "not found" cases.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self.code(),
            Some(S3ErrorCode::NoSuchBucket | S3ErrorCode::NoSuchKey | S3ErrorCode::NoSuchUpload)
        )
    }

    /// A quota / resource-cap rejection (byte, object-count, or bucket-count).
    pub fn is_quota(&self) -> bool {
        matches!(
            self.code(),
            Some(S3ErrorCode::QuotaExceeded | S3ErrorCode::TooManyObjects | S3ErrorCode::TooManyBuckets)
        )
    }

    /// Whether a retry with backoff is reasonable: an explicit SlowDown, a 5xx, or a
    /// transport timeout/connect error. Quota/cap rejections (also 5xx — 507) and other
    /// 4xx are NOT retryable: they won't change on retry.
    pub fn is_retryable(&self) -> bool {
        match self.code() {
            Some(S3ErrorCode::SlowDown) => true,
            Some(
                S3ErrorCode::QuotaExceeded | S3ErrorCode::TooManyObjects | S3ErrorCode::TooManyBuckets,
            ) => false,
            _ => match self {
                Error::Api { status, .. } => *status >= 500,
                Error::Transport(e) => e.is_timeout() || e.is_connect(),
                Error::Decode(_) | Error::InvalidKey(_) => false,
            },
        }
    }
}

/// The crate result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Parse a non-2xx response into a typed [`Error::Api`]. Falls back to a
/// status-derived code when the body isn't the expected `<Error>` XML (e.g. a
/// bodyless HEAD 404).
pub(crate) fn parse_api_error(status: u16, body: &str) -> Error {
    let code = xml::tag(body, "Code")
        .map(|c| S3ErrorCode::from_code(&c))
        .unwrap_or_else(|| default_code_for_status(status));
    let message = xml::tag(body, "Message").unwrap_or_else(|| {
        if body.trim().is_empty() {
            code.as_str().to_string()
        } else {
            // Cap a stray non-XML body so a hostile/huge error page can't bloat the error.
            body.chars().take(512).collect()
        }
    });
    Error::Api { status, code, message }
}

/// Best-effort code when a response carries no `<Code>` (bodyless errors).
fn default_code_for_status(status: u16) -> S3ErrorCode {
    match status {
        403 => S3ErrorCode::AccessDenied,
        404 => S3ErrorCode::NoSuchKey,
        408 => S3ErrorCode::RequestTimeout,
        411 => S3ErrorCode::MissingContentLength,
        429 => S3ErrorCode::SlowDown,
        507 => S3ErrorCode::QuotaExceeded,
        s if s >= 500 => S3ErrorCode::InternalError,
        _ => S3ErrorCode::Other(format!("HTTP {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_s3_error_body() {
        let body = "<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code><Message>missing: a/b</Message></Error>";
        let e = parse_api_error(404, body);
        assert_eq!(e.code(), Some(&S3ErrorCode::NoSuchKey));
        assert_eq!(e.status(), Some(404));
        assert!(e.is_not_found());
        match e {
            Error::Api { message, .. } => assert_eq!(message, "missing: a/b"),
            _ => panic!("expected Api"),
        }
    }

    #[test]
    fn quota_and_retry_classification() {
        let e = parse_api_error(507, "<Error><Code>TooManyObjects</Code><Message>cap</Message></Error>");
        assert!(e.is_quota());
        assert!(!e.is_retryable()); // a quota cap is not worth retrying
        let e = parse_api_error(503, "<Error><Code>SlowDown</Code><Message>busy</Message></Error>");
        assert!(e.is_retryable());
    }

    #[test]
    fn bodyless_error_falls_back_to_status() {
        let e = parse_api_error(404, "");
        assert_eq!(e.code(), Some(&S3ErrorCode::NoSuchKey));
        assert!(e.is_not_found());
    }

    #[test]
    fn unknown_code_is_preserved() {
        let e = parse_api_error(400, "<Error><Code>WeirdNewCode</Code><Message>x</Message></Error>");
        assert_eq!(e.code(), Some(&S3ErrorCode::Other("WeirdNewCode".to_string())));
    }
}
