//! Edge-side glue for the managed-DB reach-plane connection **preamble**.
//!
//! The wire format itself — magic/version/caps, the [`Preamble`] type, [`parse_preamble`],
//! [`encode_preamble`], [`ct_eq`], the ALPN + exporter constants — lives in
//! `jkbase_common::db_preamble` so the sidecar (`jkbase-cli`) and this edge share ONE
//! definition (a drift there would be a silent auth bypass). Everything is re-exported here
//! so existing edge call sites (`crate::db_preamble::…`) resolve unchanged.
//!
//! The only thing that stays here is [`read_preamble`], the async accumulate-loop that reads
//! off a live socket — it pulls in `tokio` I/O, which the pure shared crate deliberately
//! does not.

pub use jkbase_common::db_preamble::{
    ct_eq, encode_preamble, parse_preamble, Preamble, PreambleError, PreambleParse, DB_ALPN,
    EXPORTER_LABEL, EXPORTER_LEN, MAX_AKID_LEN, MAX_EXPORTER_LEN, MAX_PREAMBLE_LEN, MAX_SECRET_LEN,
    PREAMBLE_MAGIC, PREAMBLE_VERSION,
};

use tokio::io::{AsyncRead, AsyncReadExt};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_preamble_returns_preamble_and_leftover() {
        use tokio::io::AsyncWriteExt;
        let akid = "JKBD0123456789ABCDEF";
        let secret = "jkbd_AAAABBBBCCCCDDDDEEEEFFFF";
        let exp = vec![7u8; EXPORTER_LEN];
        let mut bytes = encode_preamble(akid, secret, &exp).unwrap();
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
}
