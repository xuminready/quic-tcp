use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils::hex_dump;

/// Maximum time window (120 seconds in milliseconds) allowed for sequence timestamps.
const MAX_TIME_WINDOW_MS: u64 = 120_000;

/// Maximum cache size for tracked sequence numbers before pruning.
const MAX_SEEN_SEQS_CAPACITY: usize = 10_000;

/// Computes an HMAC-SHA256 signature for the given payload using the provided passcode.
pub fn compute_auth(passcode: &str, payload: &str) -> String {
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, passcode.as_bytes());
    let tag = ring::hmac::sign(&s_key, payload.as_bytes());
    hex_dump(tag.as_ref())
}

/// Verifies whether the provided signature matches the HMAC-SHA256 of the payload.
pub fn verify_auth(passcode: &str, payload: &str, signature: &str) -> bool {
    let expected = compute_auth(passcode, payload);
    expected == signature
}

static SEQ_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a monotonically increasing 64-bit sequence number:
/// - Upper 54 bits: Millisecond timestamp since UNIX Epoch.
/// - Lower 10 bits: Atomic incrementing counter modulo 1024.
pub fn next_seq() -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cnt = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed) % 1024;
    (now_ms << 10) | cnt
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
        if pkt_time_ms > now_ms + MAX_TIME_WINDOW_MS || now_ms.saturating_sub(pkt_time_ms) > MAX_TIME_WINDOW_MS {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_computation_and_verification() {
        let passcode = "super_secret";
        let payload = "REG:srv1:8080:IDLE:pass1:123456";
        let hmac = compute_auth(passcode, payload);
        assert!(!hmac.is_empty());
        assert!(verify_auth(passcode, payload, &hmac));
        assert!(!verify_auth("wrong_passcode", payload, &hmac));
        assert!(!verify_auth(passcode, "different_payload", &hmac));
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
