//! Shared L4 UDP **transit wire contract** — the per-datagram authenticated frame the host
//! relay wraps around every host→guest datagram and the in-VM agent verifies + strips (and
//! symmetrically on the return path). Lives here so there is exactly ONE definition: a
//! divergence between how the host *seals* and the agent *opens* would be a silent auth
//! bypass on an untrusted host↔guest L2 seam where a co-tenant can address (or spoof toward)
//! the agent's transit listener (design §3(a-auth), P0-L4-11/-13).
//!
//! Pure byte handling — no I/O, no tokio — so it is exhaustively unit-testable, exactly like
//! [`crate::db_preamble`]. **Anti-replay is NOT here:** the per-`(flow_id, epoch)`
//! monotonic-nonce high-water window (P0-L4-13) is flow-table state the caller owns; this
//! module only does deterministic seal/open + a const-time tag compare. The MAC is
//! HMAC-SHA256 (the pure-Rust RustCrypto pair the SigV4 signer already uses — builds for the
//! agent's musl target), truncated to 128 bits on the wire.
//!
//! **Direction binding (P0-L4-11):** the two legs share one per-VM transit secret but keep
//! SEPARATE, independent nonce windows (host→agent and agent→host). Without domain separation
//! a frame captured on one leg carries a MAC that is *also* valid on the other leg, so an L2
//! co-tenant could replay a host→agent frame back at the host's return path (or vice versa) —
//! it would pass the tag check and then be admitted by the OTHER leg's fresh nonce window
//! (cross-direction replay). So the MAC is bound to an [`L4Dir`] byte the receiver supplies
//! from context (each leg only ever *opens* one direction); it is NEVER on the wire (no
//! header-length change) — the receiver already knows which way a datagram is flowing, so a
//! wrong-direction frame simply fails the tag and is dropped.

use crate::db_preamble::ct_eq;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Truncated HMAC-SHA256 tag length on the wire (128-bit — ample for a keyed MAC, and half
/// the header budget of a full SHA-256).
pub const L4_TAG_LEN: usize = 16;

/// Fixed authenticated-header length: `flow_id(4) ‖ epoch(4) ‖ nonce(8) ‖ tag(16)`, big-endian.
/// The payload (one client datagram) follows verbatim — one framed record per datagram, no
/// coalescing (P0-L4-7). The direction byte is authenticated but NOT transmitted, so this is
/// unchanged by direction binding.
pub const L4_HEADER_LEN: usize = 4 + 4 + 8 + L4_TAG_LEN; // 32

/// Which leg of the transit seam a frame belongs to. Mixed into the MAC as domain separation
/// so a frame sealed for one leg cannot be replayed onto the other (P0-L4-11). Never on the
/// wire — the receiver passes the direction it *expects* to `open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Dir {
    /// Host relay → in-VM agent (the forward leg).
    HostToAgent,
    /// In-VM agent → host relay (the return/reply leg).
    AgentToHost,
}

impl L4Dir {
    /// The domain-separation byte fed into the MAC. Distinct, non-zero constants.
    #[inline]
    fn as_byte(self) -> u8 {
        match self {
            L4Dir::HostToAgent => 0x01,
            L4Dir::AgentToHost => 0x02,
        }
    }
}

/// The authenticated, replay-scoping header of one transit datagram.
///
/// - `flow_id` — the reply-demux key `relay_bidirectional` lacks (the host maps it back to the
///   client `SocketAddr`).
/// - `epoch` — bumped when the host rebinds a flow-id (e.g. across a socket-reconcile), so a
///   stale in-flight datagram from a prior binding is rejected rather than mis-delivered.
/// - `nonce` — per-`(flow_id, epoch)` monotonic counter; the receiver drops a nonce at or
///   below its high-water mark (caller-enforced anti-replay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L4TransitHeader {
    pub flow_id: u32,
    pub epoch: u32,
    pub nonce: u64,
}

/// The 128-bit tag over `dir ‖ flow_id ‖ epoch ‖ nonce ‖ payload` (all big-endian). HMAC
/// accepts a key of any length, so `new_from_slice` cannot fail. The direction byte is a
/// leading domain-separation prefix (P0-L4-11).
fn tag(secret: &[u8], dir: L4Dir, hdr: &L4TransitHeader, payload: &[u8]) -> [u8; L4_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&[dir.as_byte()]);
    mac.update(&hdr.flow_id.to_be_bytes());
    mac.update(&hdr.epoch.to_be_bytes());
    mac.update(&hdr.nonce.to_be_bytes());
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut t = [0u8; L4_TAG_LEN];
    t.copy_from_slice(&full[..L4_TAG_LEN]);
    t
}

/// Seal one datagram into `out`: `header ‖ payload`, MAC bound to `dir`. `out` is cleared first
/// and grown to fit, so a single reusable buffer can be handed in per pump loop (no per-datagram
/// alloc).
pub fn seal(secret: &[u8], dir: L4Dir, hdr: L4TransitHeader, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(L4_HEADER_LEN + payload.len());
    out.extend_from_slice(&hdr.flow_id.to_be_bytes());
    out.extend_from_slice(&hdr.epoch.to_be_bytes());
    out.extend_from_slice(&hdr.nonce.to_be_bytes());
    out.extend_from_slice(&tag(secret, dir, &hdr, payload));
    out.extend_from_slice(payload);
}

/// Open a sealed frame: verify the tag (const-time, bound to `dir`) and return `(header,
/// payload)`. `dir` is the direction the CALLER expects (each leg opens exactly one): a frame
/// sealed for the other leg fails the tag → `None` (cross-direction replay defense, P0-L4-11).
///
/// **Fail-closed**: `None` on a short frame or a bad/wrong-direction tag — the caller drops the
/// datagram and nothing reaches loopback. The returned payload borrows `frame` (no copy). The
/// caller still enforces the nonce anti-replay window (this function is stateless).
pub fn open<'a>(secret: &[u8], dir: L4Dir, frame: &'a [u8]) -> Option<(L4TransitHeader, &'a [u8])> {
    if frame.len() < L4_HEADER_LEN {
        return None;
    }
    let flow_id = u32::from_be_bytes(frame[0..4].try_into().ok()?);
    let epoch = u32::from_be_bytes(frame[4..8].try_into().ok()?);
    let nonce = u64::from_be_bytes(frame[8..16].try_into().ok()?);
    let wire_tag = &frame[16..L4_HEADER_LEN];
    let payload = &frame[L4_HEADER_LEN..];
    let hdr = L4TransitHeader {
        flow_id,
        epoch,
        nonce,
    };
    // Const-time compare so a near-miss tag isn't distinguishable by timing.
    if !ct_eq(wire_tag, &tag(secret, dir, &hdr, payload)) {
        return None;
    }
    Some((hdr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"jkbl_test_transit_secret_value_0001";

    fn hdr() -> L4TransitHeader {
        L4TransitHeader {
            flow_id: 0xDEADBEEF,
            epoch: 7,
            nonce: 0x0102_0304_0506_0708,
        }
    }

    #[test]
    fn seal_open_round_trips_header_and_payload() {
        let payload = b"the quick brown fox jumps over 9987";
        let mut buf = Vec::new();
        seal(SECRET, L4Dir::HostToAgent, hdr(), payload, &mut buf);
        assert_eq!(buf.len(), L4_HEADER_LEN + payload.len());
        let (h, p) = open(SECRET, L4Dir::HostToAgent, &buf).expect("valid frame opens");
        assert_eq!(h, hdr());
        assert_eq!(p, payload);
    }

    #[test]
    fn empty_payload_round_trips() {
        let mut buf = Vec::new();
        seal(SECRET, L4Dir::AgentToHost, hdr(), b"", &mut buf);
        assert_eq!(buf.len(), L4_HEADER_LEN);
        let (h, p) = open(SECRET, L4Dir::AgentToHost, &buf).unwrap();
        assert_eq!(h, hdr());
        assert!(p.is_empty());
    }

    #[test]
    fn tampered_payload_fails_closed() {
        let payload = b"voice frame";
        let mut buf = Vec::new();
        seal(SECRET, L4Dir::HostToAgent, hdr(), payload, &mut buf);
        // Flip one payload byte — the tag no longer matches.
        *buf.last_mut().unwrap() ^= 0x01;
        assert!(open(SECRET, L4Dir::HostToAgent, &buf).is_none());
    }

    #[test]
    fn tampered_header_fails_closed() {
        let mut buf = Vec::new();
        seal(SECRET, L4Dir::HostToAgent, hdr(), b"x", &mut buf);
        buf[0] ^= 0x01; // flip a flow_id byte (covered by the MAC)
        assert!(open(SECRET, L4Dir::HostToAgent, &buf).is_none());
    }

    #[test]
    fn wrong_secret_fails_closed() {
        let mut buf = Vec::new();
        seal(SECRET, L4Dir::HostToAgent, hdr(), b"payload", &mut buf);
        assert!(open(b"a-different-secret", L4Dir::HostToAgent, &buf).is_none());
    }

    #[test]
    fn wrong_direction_fails_closed() {
        // P0-L4-11: a frame sealed for one leg must NOT open on the other, even with the same
        // secret + header + payload — this is the cross-direction-replay defense. Both legs
        // share one secret and keep independent nonce windows, so without this a host→agent
        // frame replayed at the host's return path would pass the tag and be admitted.
        let payload = b"same bytes both ways";
        let mut buf = Vec::new();
        seal(SECRET, L4Dir::HostToAgent, hdr(), payload, &mut buf);
        assert!(open(SECRET, L4Dir::AgentToHost, &buf).is_none());
        // And symmetrically.
        let mut buf2 = Vec::new();
        seal(SECRET, L4Dir::AgentToHost, hdr(), payload, &mut buf2);
        assert!(open(SECRET, L4Dir::HostToAgent, &buf2).is_none());
        // The two directions produce different tags for identical inputs.
        assert_ne!(&buf[16..L4_HEADER_LEN], &buf2[16..L4_HEADER_LEN]);
    }

    #[test]
    fn short_frame_is_none_not_panic() {
        for n in 0..L4_HEADER_LEN {
            assert!(
                open(SECRET, L4Dir::HostToAgent, &vec![0u8; n]).is_none(),
                "len {n}"
            );
        }
    }

    #[test]
    fn distinct_nonces_produce_distinct_tags() {
        // The nonce is authenticated, so two frames differing only in nonce have different
        // tags — a replayer can't lift a tag from one nonce onto another.
        let mut a = Vec::new();
        let mut b = Vec::new();
        seal(SECRET, L4Dir::HostToAgent, hdr(), b"same", &mut a);
        let mut h2 = hdr();
        h2.nonce += 1;
        seal(SECRET, L4Dir::HostToAgent, h2, b"same", &mut b);
        assert_ne!(&a[16..L4_HEADER_LEN], &b[16..L4_HEADER_LEN]);
    }
}
