use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils::hex_dump;

/// Maximum time window (120 seconds in milliseconds) allowed for sequence timestamps.
const MAX_TIME_WINDOW_MS: u64 = 120_000;

/// Maximum cache size for tracked sequence numbers before pruning.
const MAX_SEEN_SEQS_CAPACITY: usize = 10_000;

/// Normalizes a user-provided secret passcode so Linux CLI (including bash `"Ready\!"` escaping
/// or quoted strings) and Android UI inputs always derive the exact same Tunnel ID and HMAC key.
pub fn normalize_secret(passcode: &str) -> String {
    let mut s = passcode.trim();
    while s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s = s[1..s.len() - 1].trim();
    }
    s.replace("\\!", "!")
}

/// Computes an HMAC-SHA256 signature for the given payload using the provided passcode.
pub fn compute_auth(passcode: &str, payload: &str) -> String {
    let normalized = normalize_secret(passcode);
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, normalized.as_bytes());
    let tag = ring::hmac::sign(&s_key, payload.as_bytes());
    hex_dump(tag.as_ref())
}

/// Verifies whether the provided signature matches the HMAC-SHA256 of the payload
/// using constant-time `ring::hmac::verify` to prevent timing side-channel attacks.
pub fn verify_auth(passcode: &str, payload: &str, signature: &str) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 32];
    for (i, chunk) in signature.as_bytes().chunks_exact(2).enumerate() {
        let Ok(hex_str) = std::str::from_utf8(chunk) else {
            return false;
        };
        let Ok(byte) = u8::from_str_radix(hex_str, 16) else {
            return false;
        };
        sig_bytes[i] = byte;
    }
    let normalized = normalize_secret(passcode);
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, normalized.as_bytes());
    ring::hmac::verify(&s_key, payload.as_bytes(), &sig_bytes).is_ok()
}

static LAST_SEQ: AtomicU64 = AtomicU64::new(0);

/// Generates a strictly monotonically increasing 64-bit sequence number:
/// - Upper 54 bits: Millisecond timestamp since UNIX Epoch.
/// - Lower 10 bits: Sub-millisecond counter, advancing smoothly even during >1024/ms bursts.
pub fn next_seq() -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let candidate_base = now_ms << 10;

    loop {
        let prev = LAST_SEQ.load(Ordering::Relaxed);
        let next = if candidate_base > prev {
            candidate_base | 1
        } else {
            prev + 1
        };
        if LAST_SEQ
            .compare_exchange_weak(prev, next, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return next;
        }
    }
}

/// Filter that guards against replay attacks using a sliding timestamp window and sequence deduplication.
#[derive(Debug, Clone)]
pub struct ReplayFilter {
    seen_seqs: HashSet<u64>,
}

impl ReplayFilter {
    /// Creates a new, empty `ReplayFilter`.
    pub fn new() -> Self {
        Self {
            seen_seqs: HashSet::new(),
        }
    }

    /// Verifies the sequence number against clock skew and past seen packets.
    /// Returns `true` if the packet is fresh and unseen; `false` if replayed or expired.
    pub fn check_and_add(&mut self, seq: u64) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let pkt_time_ms = seq >> 10;

        // Verify window within 120 seconds of local clock
        if pkt_time_ms > now_ms + MAX_TIME_WINDOW_MS
            || now_ms.saturating_sub(pkt_time_ms) > MAX_TIME_WINDOW_MS
        {
            return false;
        }

        // Check if duplicate sequence
        if self.seen_seqs.contains(&seq) {
            return false;
        }

        self.seen_seqs.insert(seq);

        // Prune stale sequence numbers when cache exceeds capacity
        if self.seen_seqs.len() > MAX_SEEN_SEQS_CAPACITY {
            self.seen_seqs.retain(|&s| {
                let time_ms = s >> 10;
                now_ms.saturating_sub(time_ms) <= MAX_TIME_WINDOW_MS
            });
        }

        true
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Derives a deterministic, 16-character hex tunnel ID from a passcode/secret.
pub fn derive_tunnel_id(passcode: &str) -> String {
    let normalized = normalize_secret(passcode);
    let digest = ring::digest::digest(&ring::digest::SHA256, normalized.as_bytes());
    hex_dump(&digest.as_ref()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_computation_and_verification() {
        let passcode = "super_secret";
        let payload = "REG:4f8a12bc34de5678:8080:IDLE:123456";
        let hmac = compute_auth(passcode, payload);
        assert!(!hmac.is_empty());
        assert!(verify_auth(passcode, payload, &hmac));
        assert!(!verify_auth("wrong_passcode", payload, &hmac));
        assert!(!verify_auth(passcode, "different_payload", &hmac));
    }

    #[test]
    fn test_derive_tunnel_id() {
        let id1 = derive_tunnel_id("my_secret_code");
        let id2 = derive_tunnel_id("my_secret_code");
        let id3 = derive_tunnel_id("other_secret");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
        assert_ne!(id1, id3);

        // Verify "Ready!" produces 91213ceb7548b8dc consistently across raw, bash-escaped, and quoted inputs
        assert_eq!(derive_tunnel_id("Ready!"), "91213ceb7548b8dc");
        assert_eq!(derive_tunnel_id(r"Ready\!"), "91213ceb7548b8dc");
        assert_eq!(derive_tunnel_id(r#""Ready!""#), "91213ceb7548b8dc");
        assert_eq!(derive_tunnel_id(r#""Ready\!""#), "91213ceb7548b8dc");
        assert_eq!(derive_tunnel_id("'Ready!'"), "91213ceb7548b8dc");
        assert_eq!(derive_tunnel_id(" Ready! "), "91213ceb7548b8dc");
    }

    #[test]
    fn test_replay_filter_detection() {
        let mut filter = ReplayFilter::new();
        let seq1 = next_seq();
        let seq2 = next_seq();

        // First presentation succeeds
        assert!(filter.check_and_add(seq1));
        assert!(filter.check_and_add(seq2));

        // Replay of same sequence must be rejected
        assert!(!filter.check_and_add(seq1));
        assert!(!filter.check_and_add(seq2));

        // Ancient sequence (>120s ago) must be rejected
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ancient_seq = ((now_ms - 200_000) << 10) | 1;
        assert!(!filter.check_and_add(ancient_seq));

        // Future sequence (>120s in future) must be rejected
        let future_seq = ((now_ms + 200_000) << 10) | 1;
        assert!(!filter.check_and_add(future_seq));
    }
}
