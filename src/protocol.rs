use crate::auth::{compute_auth, next_seq, verify_auth};
use std::net::SocketAddr;

/// Registration message sent by `quic-to-tcp` servers to `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerReg {
    pub tunnel_id: String,
    pub tcp_port: u16,
    pub status: String,
    pub tunnel_code: String,
    pub seq: u64,
    pub hmac: String,
}

impl ServerReg {
    pub fn new_signed(tunnel_id: &str, tcp_port: u16, status: &str, tunnel_code: &str) -> String {
        let seq = next_seq();
        let payload = format!(
            "REG:{}:{}:{}:{}:{}",
            tunnel_id, tcp_port, status, tunnel_code, seq
        );
        let hmac = compute_auth(tunnel_code, &payload);
        format!(
            "REG {} {} {} {} {} {}",
            tunnel_id, tcp_port, status, tunnel_code, seq, hmac
        )
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 7 && parts[0] == "REG" {
            Some(Self {
                tunnel_id: parts[1].to_string(),
                tcp_port: parts[2].parse().ok()?,
                status: parts[3].to_string(),
                tunnel_code: parts[4].to_string(),
                seq: parts[5].parse().ok()?,
                hmac: parts[6].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, tunnel_code: &str) -> bool {
        let payload = format!(
            "REG:{}:{}:{}:{}:{}",
            self.tunnel_id, self.tcp_port, self.status, self.tunnel_code, self.seq
        );
        verify_auth(tunnel_code, &payload, &self.hmac)
    }
}

/// Server registration acknowledgment sent by `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegOk {
    pub seq: u64,
    pub hmac: String,
}

impl RegOk {
    pub fn new_signed(tunnel_code: &str) -> String {
        let seq = next_seq();
        let payload = format!("REG_OK:{}", seq);
        let hmac = compute_auth(tunnel_code, &payload);
        format!("REG_OK {} {}", seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "REG_OK" {
            Some(Self {
                seq: parts[1].parse().ok()?,
                hmac: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, tunnel_code: &str) -> bool {
        let payload = format!("REG_OK:{}", self.seq);
        verify_auth(tunnel_code, &payload, &self.hmac)
    }
}

/// Status update message sent by `quic-to-tcp` to `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatusMsg {
    pub tunnel_id: String,
    pub status: String,
    pub seq: u64,
    pub hmac: String,
}

impl ServerStatusMsg {
    pub fn new_signed(tunnel_id: &str, status: &str, tunnel_code: &str) -> String {
        let seq = next_seq();
        let payload = format!("STATUS:{}:{}:{}", tunnel_id, status, seq);
        let hmac = compute_auth(tunnel_code, &payload);
        format!("STATUS {} {} {} {}", tunnel_id, status, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "STATUS" {
            Some(Self {
                tunnel_id: parts[1].to_string(),
                status: parts[2].to_string(),
                seq: parts[3].parse().ok()?,
                hmac: parts[4].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, tunnel_code: &str) -> bool {
        let payload = format!("STATUS:{}:{}:{}", self.tunnel_id, self.status, self.seq);
        verify_auth(tunnel_code, &payload, &self.hmac)
    }
}

/// Client connection request sent by `tcp-to-quic` to `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConn {
    pub tunnel_id: String,
    pub seq: u64,
    pub hmac: String,
}

impl ClientConn {
    pub fn new_signed(tunnel_id: &str, tunnel_code: &str) -> String {
        let seq = next_seq();
        let payload = format!("CONN:{}:{}", tunnel_id, seq);
        let hmac = compute_auth(tunnel_code, &payload);
        format!("CONN {} {} {}", tunnel_id, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "CONN" {
            Some(Self {
                tunnel_id: parts[1].to_string(),
                seq: parts[2].parse().ok()?,
                hmac: parts[3].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, tunnel_code: &str) -> bool {
        let payload = format!("CONN:{}:{}", self.tunnel_id, self.seq);
        verify_auth(tunnel_code, &payload, &self.hmac)
    }
}

/// Client reset request sent by `tcp-to-quic` to restart hole punching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReset {
    pub tunnel_id: String,
    pub seq: u64,
    pub hmac: String,
}

impl ClientReset {
    pub fn new_signed(tunnel_id: &str, tunnel_code: &str) -> String {
        let seq = next_seq();
        let payload = format!("RESET:{}:{}", tunnel_id, seq);
        let hmac = compute_auth(tunnel_code, &payload);
        format!("RESET {} {} {}", tunnel_id, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "RESET" {
            Some(Self {
                tunnel_id: parts[1].to_string(),
                seq: parts[2].parse().ok()?,
                hmac: parts[3].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, tunnel_code: &str) -> bool {
        let payload = format!("RESET:{}:{}", self.tunnel_id, self.seq);
        verify_auth(tunnel_code, &payload, &self.hmac)
    }
}

/// Hole punching coordination command sent by `rendezvous-server` to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchSignal {
    /// Sent to server: `PUNCH <client_addr> passive <seq> <hmac>`
    Passive {
        client_addr: SocketAddr,
        seq: u64,
        hmac: String,
    },
    /// Sent to client: `PUNCH <server_addr> active <seq> <hmac>`
    Active {
        server_addr: SocketAddr,
        seq: u64,
        hmac: String,
    },
}

impl PunchSignal {
    pub fn new_passive_signed(client_addr: SocketAddr, tunnel_code: &str) -> String {
        let client_addr = crate::utils::normalize_socket_addr(client_addr);
        let seq = next_seq();
        let payload = format!("PUNCH:{}:passive:{}", client_addr, seq);
        let hmac = compute_auth(tunnel_code, &payload);
        format!("PUNCH {} passive {} {}", client_addr, seq, hmac)
    }

    pub fn new_active_signed(server_addr: SocketAddr, tunnel_code: &str) -> String {
        let server_addr = crate::utils::normalize_socket_addr(server_addr);
        let seq = next_seq();
        let payload = format!("PUNCH:{}:active:{}", server_addr, seq);
        let hmac = compute_auth(tunnel_code, &payload);
        format!("PUNCH {} active {} {}", server_addr, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.is_empty() || parts[0] != "PUNCH" {
            return None;
        }

        if parts.len() >= 5 && parts[2] == "passive" {
            let addr: SocketAddr = parts[1].parse().ok()?;
            Some(PunchSignal::Passive {
                client_addr: crate::utils::normalize_socket_addr(addr),
                seq: parts[3].parse().ok()?,
                hmac: parts[4].to_string(),
            })
        } else if parts.len() >= 5 && parts[2] == "active" {
            let addr: SocketAddr = parts[1].parse().ok()?;
            Some(PunchSignal::Active {
                server_addr: crate::utils::normalize_socket_addr(addr),
                seq: parts[3].parse().ok()?,
                hmac: parts[4].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, tunnel_code: &str) -> bool {
        match self {
            PunchSignal::Passive {
                client_addr,
                seq,
                hmac,
            } => {
                let client_addr = crate::utils::normalize_socket_addr(*client_addr);
                let payload = format!("PUNCH:{}:passive:{}", client_addr, seq);
                verify_auth(tunnel_code, &payload, hmac)
            }
            PunchSignal::Active {
                server_addr,
                seq,
                hmac,
            } => {
                let server_addr = crate::utils::normalize_socket_addr(*server_addr);
                let payload = format!("PUNCH:{}:active:{}", server_addr, seq);
                verify_auth(tunnel_code, &payload, hmac)
            }
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            PunchSignal::Passive { seq, .. } | PunchSignal::Active { seq, .. } => *seq,
        }
    }
}

/// UDP Hole Punching probe message exchanged directly between peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerProbe {
    Punch(u64, String),
    Ack(u64, String),
    AckAck(u64, String),
}

impl PeerProbe {
    pub fn new_punch(passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PEER_PUNCH:{}", seq);
        let hmac = compute_auth(passcode, &payload);
        format!("PEER_PUNCH {} {}", seq, hmac)
    }

    pub fn new_ack(passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PEER_PUNCH_ACK:{}", seq);
        let hmac = compute_auth(passcode, &payload);
        format!("PEER_PUNCH_ACK {} {}", seq, hmac)
    }

    pub fn new_ack_ack(passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PEER_PUNCH_ACK_ACK:{}", seq);
        let hmac = compute_auth(passcode, &payload);
        format!("PEER_PUNCH_ACK_ACK {} {}", seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 3 {
            let seq = parts[1].parse().ok()?;
            let hmac = parts[2].to_string();
            match parts[0] {
                "PEER_PUNCH" => Some(PeerProbe::Punch(seq, hmac)),
                "PEER_PUNCH_ACK" => Some(PeerProbe::Ack(seq, hmac)),
                "PEER_PUNCH_ACK_ACK" => Some(PeerProbe::AckAck(seq, hmac)),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            PeerProbe::Punch(seq, _) => *seq,
            PeerProbe::Ack(seq, _) => *seq,
            PeerProbe::AckAck(seq, _) => *seq,
        }
    }

    pub fn verify(&self, passcode: &str) -> bool {
        match self {
            PeerProbe::Punch(seq, hmac) => {
                let payload = format!("PEER_PUNCH:{}", seq);
                verify_auth(passcode, &payload, hmac)
            }
            PeerProbe::Ack(seq, hmac) => {
                let payload = format!("PEER_PUNCH_ACK:{}", seq);
                verify_auth(passcode, &payload, hmac)
            }
            PeerProbe::AckAck(seq, hmac) => {
                let payload = format!("PEER_PUNCH_ACK_ACK:{}", seq);
                verify_auth(passcode, &payload, hmac)
            }
        }
    }
}

/// Release message sent by `tcp-to-quic` to `quic-to-tcp` when the client exits,
/// instructing the server to release the session and transition back to IDLE on `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRelease {
    pub seq: u64,
    pub hmac: String,
}

impl PeerRelease {
    pub fn new_signed(passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PEER_RELEASE:{}", seq);
        let hmac = compute_auth(passcode, &payload);
        format!("PEER_RELEASE {} {}", seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "PEER_RELEASE" {
            Some(Self {
                seq: parts[1].parse().ok()?,
                hmac: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, passcode: &str) -> bool {
        let payload = format!("PEER_RELEASE:{}", self.seq);
        verify_auth(passcode, &payload, &self.hmac)
    }
}

/// Acknowledgment sent by `quic-to-tcp` to `tcp-to-quic` upon receiving `PeerRelease`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReleaseAck {
    pub seq: u64,
    pub hmac: String,
}

impl PeerReleaseAck {
    pub fn new_signed(passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PEER_RELEASE_ACK:{}", seq);
        let hmac = compute_auth(passcode, &payload);
        format!("PEER_RELEASE_ACK {} {}", seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "PEER_RELEASE_ACK" {
            Some(Self {
                seq: parts[1].parse().ok()?,
                hmac: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, passcode: &str) -> bool {
        let payload = format!("PEER_RELEASE_ACK:{}", self.seq);
        verify_auth(passcode, &payload, &self.hmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_reg_roundtrip() {
        let encoded = ServerReg::new_signed("4f8a12bc34de5678", 8080, "IDLE", "my_tunnel_secret");
        let parsed = ServerReg::parse(&encoded).expect("Must parse");
        assert_eq!(parsed.tunnel_id, "4f8a12bc34de5678");
        assert_eq!(parsed.tcp_port, 8080);
        assert_eq!(parsed.status, "IDLE");
        assert_eq!(parsed.tunnel_code, "my_tunnel_secret");
        assert!(parsed.verify("my_tunnel_secret"));
        assert!(!parsed.verify("wrong_secret"));
    }

    #[test]
    fn test_client_conn_roundtrip() {
        let encoded = ClientConn::new_signed("4f8a12bc34de5678", "my_tunnel_secret");
        let parsed = ClientConn::parse(&encoded).expect("Must parse");
        assert_eq!(parsed.tunnel_id, "4f8a12bc34de5678");
        assert!(parsed.verify("my_tunnel_secret"));
        assert!(!parsed.verify("wrong_secret"));
    }

    #[test]
    fn test_punch_signals_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let p_enc = PunchSignal::new_passive_signed(addr, "my_tunnel_secret");
        let p_parsed = PunchSignal::parse(&p_enc).expect("Must parse passive");
        assert!(p_parsed.verify("my_tunnel_secret"));

        let a_enc = PunchSignal::new_active_signed(addr, "my_tunnel_secret");
        let a_parsed = PunchSignal::parse(&a_enc).expect("Must parse active");
        assert!(a_parsed.verify("my_tunnel_secret"));
    }

    #[test]
    fn test_peer_probes_roundtrip() {
        let punch = PeerProbe::new_punch("pass123");
        let parsed_punch = PeerProbe::parse(&punch).expect("Must parse punch");
        assert!(parsed_punch.verify("pass123"));

        let ack = PeerProbe::new_ack("pass123");
        let parsed_ack = PeerProbe::parse(&ack).expect("Must parse ack");
        assert!(parsed_ack.verify("pass123"));

        let ack_ack = PeerProbe::new_ack_ack("pass123");
        let parsed_ack_ack = PeerProbe::parse(&ack_ack).expect("Must parse ack_ack");
        assert!(parsed_ack_ack.verify("pass123"));
    }

    #[test]
    fn test_peer_release_roundtrip() {
        let rel = PeerRelease::new_signed("pass123");
        let parsed_rel = PeerRelease::parse(&rel).expect("Must parse release");
        assert!(parsed_rel.verify("pass123"));
        assert!(!parsed_rel.verify("wrong"));

        let ack = PeerReleaseAck::new_signed("pass123");
        let parsed_ack = PeerReleaseAck::parse(&ack).expect("Must parse release ack");
        assert!(parsed_ack.verify("pass123"));
        assert!(!parsed_ack.verify("wrong"));
    }
}
