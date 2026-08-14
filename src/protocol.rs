use std::net::SocketAddr;
use crate::auth::{compute_auth, next_seq, verify_auth};

/// Registration message sent by `quic-to-tcp` servers to `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerReg {
    pub name: String,
    pub tcp_port: u16,
    pub status: String,
    pub server_passcode: String,
    pub seq: u64,
    pub hmac: String,
}

impl ServerReg {
    pub fn new_signed(
        name: &str,
        tcp_port: u16,
        status: &str,
        server_passcode: &str,
        rendezvous_passcode: &str,
    ) -> String {
        let seq = next_seq();
        let payload = format!("REG:{}:{}:{}:{}:{}", name, tcp_port, status, server_passcode, seq);
        let hmac = compute_auth(rendezvous_passcode, &payload);
        format!("REG {} {} {} {} {} {}", name, tcp_port, status, server_passcode, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 7 && parts[0] == "REG" {
            Some(Self {
                name: parts[1].to_string(),
                tcp_port: parts[2].parse().ok()?,
                status: parts[3].to_string(),
                server_passcode: parts[4].to_string(),
                seq: parts[5].parse().ok()?,
                hmac: parts[6].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, rendezvous_passcode: &str) -> bool {
        let payload = format!(
            "REG:{}:{}:{}:{}:{}",
            self.name, self.tcp_port, self.status, self.server_passcode, self.seq
        );
        verify_auth(rendezvous_passcode, &payload, &self.hmac)
    }
}

/// Server registration acknowledgment sent by `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegOk {
    pub seq: u64,
    pub hmac: String,
}

impl RegOk {
    pub fn new_signed(rendezvous_passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("REG_OK:{}", seq);
        let hmac = compute_auth(rendezvous_passcode, &payload);
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

    pub fn verify(&self, rendezvous_passcode: &str) -> bool {
        let payload = format!("REG_OK:{}", self.seq);
        verify_auth(rendezvous_passcode, &payload, &self.hmac)
    }
}

/// Status update message sent by `quic-to-tcp` to `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatusMsg {
    pub name: String,
    pub status: String,
    pub seq: u64,
    pub hmac: String,
}

impl ServerStatusMsg {
    pub fn new_signed(name: &str, status: &str, rendezvous_passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("STATUS:{}:{}:{}", name, status, seq);
        let hmac = compute_auth(rendezvous_passcode, &payload);
        format!("STATUS {} {} {} {}", name, status, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 5 && parts[0] == "STATUS" {
            Some(Self {
                name: parts[1].to_string(),
                status: parts[2].to_string(),
                seq: parts[3].parse().ok()?,
                hmac: parts[4].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, rendezvous_passcode: &str) -> bool {
        let payload = format!("STATUS:{}:{}:{}", self.name, self.status, self.seq);
        verify_auth(rendezvous_passcode, &payload, &self.hmac)
    }
}

/// Client connection request sent by `tcp-to-quic` to `rendezvous-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConn {
    pub target_tcp_port: u16,
    pub seq: u64,
    pub hmac: String,
}

impl ClientConn {
    pub fn new_signed(target_tcp_port: u16, server_passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("CONN:{}:{}", target_tcp_port, seq);
        let hmac = compute_auth(server_passcode, &payload);
        format!("CONN {} {} {}", target_tcp_port, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "CONN" {
            Some(Self {
                target_tcp_port: parts[1].parse().ok()?,
                seq: parts[2].parse().ok()?,
                hmac: parts[3].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, server_passcode: &str) -> bool {
        let payload = format!("CONN:{}:{}", self.target_tcp_port, self.seq);
        verify_auth(server_passcode, &payload, &self.hmac)
    }
}

/// Client reset request sent by `tcp-to-quic` to restart hole punching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReset {
    pub target_tcp_port: u16,
    pub seq: u64,
    pub hmac: String,
}

impl ClientReset {
    pub fn new_signed(target_tcp_port: u16, server_passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("RESET:{}:{}", target_tcp_port, seq);
        let hmac = compute_auth(server_passcode, &payload);
        format!("RESET {} {} {}", target_tcp_port, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "RESET" {
            Some(Self {
                target_tcp_port: parts[1].parse().ok()?,
                seq: parts[2].parse().ok()?,
                hmac: parts[3].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, server_passcode: &str) -> bool {
        let payload = format!("RESET:{}:{}", self.target_tcp_port, self.seq);
        verify_auth(server_passcode, &payload, &self.hmac)
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
    /// Sent to client: `PUNCH <server_addr> active <server_name> <seq> <hmac>`
    Active {
        server_addr: SocketAddr,
        server_name: String,
        seq: u64,
        hmac: String,
    },
}

impl PunchSignal {
    pub fn new_passive_signed(client_addr: SocketAddr, server_passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PUNCH:{}:passive:{}", client_addr, seq);
        let hmac = compute_auth(server_passcode, &payload);
        format!("PUNCH {} passive {} {}", client_addr, seq, hmac)
    }

    pub fn new_active_signed(server_addr: SocketAddr, server_name: &str, server_passcode: &str) -> String {
        let seq = next_seq();
        let payload = format!("PUNCH:{}:active:{}:{}", server_addr, server_name, seq);
        let hmac = compute_auth(server_passcode, &payload);
        format!("PUNCH {} active {} {} {}", server_addr, server_name, seq, hmac)
    }

    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        if parts.is_empty() || parts[0] != "PUNCH" {
            return None;
        }

        if parts.len() >= 5 && parts[2] == "passive" {
            Some(PunchSignal::Passive {
                client_addr: parts[1].parse().ok()?,
                seq: parts[3].parse().ok()?,
                hmac: parts[4].to_string(),
            })
        } else if parts.len() >= 6 && parts[2] == "active" {
            Some(PunchSignal::Active {
                server_addr: parts[1].parse().ok()?,
                server_name: parts[3].to_string(),
                seq: parts[4].parse().ok()?,
                hmac: parts[5].to_string(),
            })
        } else {
            None
        }
    }

    pub fn verify(&self, server_passcode: &str) -> bool {
        match self {
            PunchSignal::Passive { client_addr, seq, hmac } => {
                let payload = format!("PUNCH:{}:passive:{}", client_addr, seq);
                verify_auth(server_passcode, &payload, hmac)
            }
            PunchSignal::Active { server_addr, server_name, seq, hmac } => {
                let payload = format!("PUNCH:{}:active:{}:{}", server_addr, server_name, seq);
                verify_auth(server_passcode, &payload, hmac)
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_reg_roundtrip() {
        let encoded = ServerReg::new_signed("srv1", 8080, "IDLE", "srv_pass", "rdv_pass");
        let parsed = ServerReg::parse(&encoded).expect("Must parse");
        assert_eq!(parsed.name, "srv1");
        assert_eq!(parsed.tcp_port, 8080);
        assert_eq!(parsed.status, "IDLE");
        assert_eq!(parsed.server_passcode, "srv_pass");
        assert!(parsed.verify("rdv_pass"));
        assert!(!parsed.verify("wrong_rdv_pass"));
    }

    #[test]
    fn test_client_conn_roundtrip() {
        let encoded = ClientConn::new_signed(8080, "srv_pass");
        let parsed = ClientConn::parse(&encoded).expect("Must parse");
        assert_eq!(parsed.target_tcp_port, 8080);
        assert!(parsed.verify("srv_pass"));
        assert!(!parsed.verify("wrong_pass"));
    }

    #[test]
    fn test_punch_signals_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let p_enc = PunchSignal::new_passive_signed(addr, "srv_pass");
        let p_parsed = PunchSignal::parse(&p_enc).expect("Must parse passive");
        assert!(p_parsed.verify("srv_pass"));

        let a_enc = PunchSignal::new_active_signed(addr, "srv1", "srv_pass");
        let a_parsed = PunchSignal::parse(&a_enc).expect("Must parse active");
        assert!(a_parsed.verify("srv_pass"));
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
}
