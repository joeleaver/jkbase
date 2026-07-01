//! The managed-DB reach-plane connection **preamble** — the first bytes a reach
//! client (the `jkbase db proxy` sidecar, or a future TLS-capable `@rhypedb/client`)
//! sends inside the TLS session, consumed by the edge and invisible to rhypedb.
//!
//! Wire format (all integers big-endian), bounded at every field so the public
//! `:443` accept path can't be slow-loris'd or memory-amplified by an unauthenticated
//! peer ([R6]):
//!
//! ```text
//!   "JKDB"  | version:u8 | akid_len:u8  | akid[akid_len]
//!           | secret_len:u16 | secret[secret_len]
//!           | exporter_len:u8 | exporter[exporter_len]
//! ```
//!
//! - `akid` + `secret` carry the owner-held DB access key — the edge does an O(1)
//!   lookup by `akid` then a const-time fingerprint compare of `secret` ([R2]/[R4]).
//! - `exporter` is the client's RFC 9266 `tls-exporter` value for THIS TLS session.
//!   The edge re-derives the same value from its side of the session and const-time
//!   compares: a preamble captured on one session can't be replayed on another
//!   ([R-replay]). The raw secret never recomputes anything server-side (the edge
//!   holds only its fingerprint), so the exporter MUST travel alongside it.
//!
//! Parsing is a pure function over a byte buffer (no I/O, no allocation of the input)
//! so it is exhaustively unit-testable; [`read_preamble`] is the thin async wrapper
//! that accumulates bytes up to [`MAX_PREAMBLE_LEN`] and hands back any bytes the
//! client pipelined *after* the preamble for the relay to forward ([R-relay]).

use tokio::io::{AsyncRead, AsyncReadExt};

/// The ALPN protocol a reach client negotiates to select the DB relay branch on the
/// shared `:443` listener (D3). The edge advertises it alongside `http/1.1`; a
/// connection that negotiates it is demuxed to the DB path (after the SNI + auth
/// checks), everything else stays HTTP.
pub const DB_ALPN: &[u8] = b"jkbase-db";

/// Protocol marker. Distinct from the S3/DB *akid* prefixes — this is the wire magic.
pub const PREAMBLE_MAGIC: &[u8; 4] = b"JKDB";
/// Current preamble version. Bump only on a wire-incompatible change.
pub const PREAMBLE_VERSION: u8 = 1;

/// Caps. A DB akid is `JKBD`+16 hex = 20 chars; a secret is `jkbd_`+240-bit b64 ≈ 45
/// chars; the RFC 9266 exporter is 32 bytes. The caps are generous headroom, NOT tight
/// fits — but every field is bounded so a hostile peer can't claim a huge length.
pub const MAX_AKID_LEN: usize = 64;
pub const MAX_SECRET_LEN: usize = 256;
pub const MAX_EXPORTER_LEN: usize = 64;
/// The largest a complete, in-bounds preamble can be — the hard read ceiling.
pub const MAX_PREAMBLE_LEN: usize =
    4 + 1 + 1 + MAX_AKID_LEN + 2 + MAX_SECRET_LEN + 1 + MAX_EXPORTER_LEN;

/// A label per RFC 9266 §3 for the `tls-exporter` channel binding (TLS 1.3 uses an
/// empty context and a 32-octet output). The edge derives this from its
/// `ServerConnection`; the client derives the identical value from its side.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
/// Octets of exported keying material (RFC 9266 fixes this at 32 for the binding).
pub const EXPORTER_LEN: usize = 32;

/// A validated preamble. `secret` is sensitive (verify then drop); `exporter` is the
/// session-binding value to compare against the edge's own export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    pub akid: String,
    pub secret: String,
    pub exporter: Vec<u8>,
}

/// Result of a parse attempt over a (possibly partial) buffer.
#[derive(Debug)]
pub enum PreambleParse {
    /// A full, in-bounds preamble was read; `consumed` bytes belong to it and anything
    /// after is pipelined client data to forward to the backend ([R-relay]).
    Complete { preamble: Preamble, consumed: usize },
    /// The buffer holds a valid prefix but not yet a whole preamble — read more.
    Incomplete,
}

/// A fatal, fail-closed parse/read error. Every arm ⇒ drop the connection, touch no
/// backend (the §2 step sequence).
#[derive(Debug, PartialEq, Eq)]
pub enum PreambleError {
    /// First bytes are not `"JKDB"` — not a DB reach client.
    BadMagic,
    /// Unknown version byte.
    BadVersion(u8),
    /// A length field is zero or exceeds its cap (slow-loris / amplification guard).
    BadLength,
    /// `akid`/`secret` were not valid UTF-8 (they are ASCII tokens).
    NonUtf8,
    /// Peer closed before sending a complete preamble.
    Eof,
    /// Underlying socket read error.
    Io,
}

impl std::fmt::Display for PreambleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreambleError::BadMagic => write!(f, "bad preamble magic"),
            PreambleError::BadVersion(v) => write!(f, "unsupported preamble version {v}"),
            PreambleError::BadLength => write!(f, "preamble length field out of bounds"),
            PreambleError::NonUtf8 => write!(f, "preamble akid/secret not utf-8"),
            PreambleError::Eof => write!(f, "connection closed before preamble complete"),
            PreambleError::Io => write!(f, "read error during preamble"),
        }
    }
}

/// Parse a preamble from `buf`. Pure: no I/O, returns [`PreambleParse::Incomplete`] if
/// `buf` is a valid-so-far prefix, an error on anything malformed/out-of-bounds. A
/// length that exceeds its cap is rejected IMMEDIATELY (before waiting for the claimed
/// bytes), so a hostile peer can't make us buffer toward a huge declared size.
pub fn parse_preamble(buf: &[u8]) -> Result<PreambleParse, PreambleError> {
    // magic(4) + version(1) + akid_len(1)
    if buf.len() < 6 {
        return Ok(PreambleParse::Incomplete);
    }
    if &buf[0..4] != PREAMBLE_MAGIC {
        return Err(PreambleError::BadMagic);
    }
    if buf[4] != PREAMBLE_VERSION {
        return Err(PreambleError::BadVersion(buf[4]));
    }
    let akid_len = buf[5] as usize;
    if akid_len == 0 || akid_len > MAX_AKID_LEN {
        return Err(PreambleError::BadLength);
    }

    // akid + secret_len(2)
    let secret_len_at = 6 + akid_len;
    if buf.len() < secret_len_at + 2 {
        return Ok(PreambleParse::Incomplete);
    }
    let akid = std::str::from_utf8(&buf[6..secret_len_at]).map_err(|_| PreambleError::NonUtf8)?;
    let secret_len = u16::from_be_bytes([buf[secret_len_at], buf[secret_len_at + 1]]) as usize;
    if secret_len == 0 || secret_len > MAX_SECRET_LEN {
        return Err(PreambleError::BadLength);
    }

    // secret + exporter_len(1)
    let secret_at = secret_len_at + 2;
    let exporter_len_at = secret_at + secret_len;
    if buf.len() < exporter_len_at + 1 {
        return Ok(PreambleParse::Incomplete);
    }
    let secret = std::str::from_utf8(&buf[secret_at..exporter_len_at])
        .map_err(|_| PreambleError::NonUtf8)?;
    let exporter_len = buf[exporter_len_at] as usize;
    if exporter_len == 0 || exporter_len > MAX_EXPORTER_LEN {
        return Err(PreambleError::BadLength);
    }

    // exporter
    let exporter_at = exporter_len_at + 1;
    let end = exporter_at + exporter_len;
    if buf.len() < end {
        return Ok(PreambleParse::Incomplete);
    }

    Ok(PreambleParse::Complete {
        preamble: Preamble {
            akid: akid.to_string(),
            secret: secret.to_string(),
            exporter: buf[exporter_at..end].to_vec(),
        },
        consumed: end,
    })
}

/// Read and parse the preamble off `stream`, returning it plus any bytes the client
/// pipelined after it (to be written to the backend before relaying — [R-relay]).
///
/// Accumulates at most [`MAX_PREAMBLE_LEN`] preamble bytes; a peer that dribbles or
/// never completes is bounded by that ceiling AND must be wrapped in a caller-supplied
/// deadline (`tokio::time::timeout`) — the slow-loris guard ([R6]). Never opens a
/// backend: the caller does auth on the returned preamble FIRST.
pub async fn read_preamble<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(Preamble, Vec<u8>), PreambleError> {
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    let mut chunk = [0u8; 512];
    loop {
        // Try to parse what we have BEFORE reading more, so a pipelined preamble+query
        // in one segment completes immediately and the query becomes leftover.
        if let PreambleParse::Complete { preamble, consumed } = parse_preamble(&buf)? {
            return Ok((preamble, buf[consumed..].to_vec()));
        }
        if buf.len() >= MAX_PREAMBLE_LEN {
            // In-bounds fields can't exceed this; still Incomplete ⇒ malformed/stall.
            return Err(PreambleError::BadLength);
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| PreambleError::Io)?;
        if n == 0 {
            return Err(PreambleError::Eof);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Build the preamble wire bytes (used by tests today and the CLI sidecar later).
/// Returns `None` if a field exceeds its cap.
pub fn encode_preamble(akid: &str, secret: &str, exporter: &[u8]) -> Option<Vec<u8>> {
    if akid.is_empty()
        || akid.len() > MAX_AKID_LEN
        || secret.is_empty()
        || secret.len() > MAX_SECRET_LEN
        || exporter.is_empty()
        || exporter.len() > MAX_EXPORTER_LEN
    {
        return None;
    }
    let mut out = Vec::with_capacity(9 + akid.len() + secret.len() + exporter.len());
    out.extend_from_slice(PREAMBLE_MAGIC);
    out.push(PREAMBLE_VERSION);
    out.push(akid.len() as u8);
    out.extend_from_slice(akid.as_bytes());
    out.extend_from_slice(&(secret.len() as u16).to_be_bytes());
    out.extend_from_slice(secret.as_bytes());
    out.push(exporter.len() as u8);
    out.extend_from_slice(exporter);
    Some(out)
}

/// Constant-time byte equality — for the `tls-exporter` channel-binding compare, so a
/// near-miss can't be timed out (mirrors the control-plane `ct_eq` discipline).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (String, String, Vec<u8>) {
        (
            "JKBD0123456789ABCDEF".to_string(),
            "jkbd_AAAABBBBCCCCDDDDEEEEFFFF".to_string(),
            vec![7u8; EXPORTER_LEN],
        )
    }

    #[test]
    fn round_trip_parses_all_fields() {
        let (akid, secret, exp) = sample();
        let bytes = encode_preamble(&akid, &secret, &exp).unwrap();
        match parse_preamble(&bytes).unwrap() {
            PreambleParse::Complete { preamble, consumed } => {
                assert_eq!(preamble.akid, akid);
                assert_eq!(preamble.secret, secret);
                assert_eq!(preamble.exporter, exp);
                assert_eq!(consumed, bytes.len());
            }
            PreambleParse::Incomplete => panic!("should be complete"),
        }
    }

    #[test]
    fn pipelined_bytes_are_leftover() {
        let (akid, secret, exp) = sample();
        let mut bytes = encode_preamble(&akid, &secret, &exp).unwrap();
        bytes.extend_from_slice(b"PIPELINED-QUERY-BYTES");
        match parse_preamble(&bytes).unwrap() {
            PreambleParse::Complete { consumed, .. } => {
                assert_eq!(&bytes[consumed..], b"PIPELINED-QUERY-BYTES");
            }
            PreambleParse::Incomplete => panic!("should be complete"),
        }
    }

    #[test]
    fn truncated_at_each_stage_is_incomplete_not_error() {
        let (akid, secret, exp) = sample();
        let full = encode_preamble(&akid, &secret, &exp).unwrap();
        // Every strict prefix is a valid-so-far Incomplete (never a spurious error).
        for cut in 0..full.len() {
            assert!(
                matches!(parse_preamble(&full[..cut]), Ok(PreambleParse::Incomplete)),
                "prefix of len {cut} should be Incomplete"
            );
        }
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        assert_eq!(
            parse_preamble(b"XXXX\x01\x01a..").unwrap_err(),
            PreambleError::BadMagic
        );
        // Right magic, wrong version.
        let mut b = encode_preamble("ak", "se", &[1u8; 32]).unwrap();
        b[4] = 9;
        assert_eq!(
            parse_preamble(&b).unwrap_err(),
            PreambleError::BadVersion(9)
        );
    }

    #[test]
    fn oversized_lengths_rejected_immediately() {
        // akid_len claims 0xFF (> MAX) — rejected from just the 6-byte header, without
        // waiting for the claimed bytes.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(PREAMBLE_MAGIC);
        hdr.push(PREAMBLE_VERSION);
        hdr.push(0xFF);
        assert_eq!(parse_preamble(&hdr).unwrap_err(), PreambleError::BadLength);

        // secret_len claims 0xFFFF (> MAX) — rejected as soon as the u16 is readable.
        let mut b = Vec::new();
        b.extend_from_slice(PREAMBLE_MAGIC);
        b.push(PREAMBLE_VERSION);
        b.push(2);
        b.extend_from_slice(b"ak");
        b.extend_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(parse_preamble(&b).unwrap_err(), PreambleError::BadLength);

        // Zero-length akid is invalid.
        let mut z = Vec::new();
        z.extend_from_slice(PREAMBLE_MAGIC);
        z.push(PREAMBLE_VERSION);
        z.push(0);
        assert_eq!(parse_preamble(&z).unwrap_err(), PreambleError::BadLength);
    }

    #[test]
    fn encode_rejects_oversized_fields() {
        assert!(encode_preamble(&"a".repeat(MAX_AKID_LEN + 1), "s", &[1]).is_none());
        assert!(encode_preamble("a", &"s".repeat(MAX_SECRET_LEN + 1), &[1]).is_none());
        assert!(encode_preamble("a", "s", &[1u8; MAX_EXPORTER_LEN + 1]).is_none());
        assert!(encode_preamble("", "s", &[1]).is_none());
    }

    #[tokio::test]
    async fn read_preamble_returns_preamble_and_leftover() {
        use tokio::io::AsyncWriteExt;
        let (akid, secret, exp) = sample();
        let mut bytes = encode_preamble(&akid, &secret, &exp).unwrap();
        bytes.extend_from_slice(b"AFTER");

        let (mut a, mut b) = tokio::io::duplex(4096);
        // Write in two chunks to exercise the accumulate loop.
        let split = bytes.len() / 2;
        let w = tokio::spawn(async move {
            a.write_all(&bytes[..split]).await.unwrap();
            tokio::task::yield_now().await;
            a.write_all(&bytes[split..]).await.unwrap();
        });
        let (got, leftover) = read_preamble(&mut b).await.unwrap();
        assert_eq!(got.akid, akid);
        assert_eq!(got.secret, secret);
        assert_eq!(got.exporter, exp);
        assert_eq!(leftover, b"AFTER");
        w.await.unwrap();
    }

    #[tokio::test]
    async fn read_preamble_eof_before_complete_errors() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let part = encode_preamble("ak", "se", &[1u8; 32]).unwrap();
        let half = part.len() / 2;
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(&part[..half]).await.unwrap();
            // drop `a` → EOF
        });
        assert_eq!(read_preamble(&mut b).await.unwrap_err(), PreambleError::Eof);
    }

    #[test]
    fn ct_eq_matches_only_identical() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
