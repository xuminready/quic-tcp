use ring::rand::{SecureRandom, SystemRandom};
use std::net;
use std::sync::OnceLock;

const HMAC_TAG_LEN: usize = 32;

fn token_hmac_key() -> &'static ring::hmac::Key {
    static KEY: OnceLock<ring::hmac::Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key_bytes = [0u8; 32];
        let _ = SystemRandom::new().fill(&mut key_bytes);
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes)
    })
}

pub fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::with_capacity(6 + 16 + hdr.dcid.len() + HMAC_TAG_LEN);
    token.extend_from_slice(b"quiche");

    match src.ip() {
        std::net::IpAddr::V4(a) => token.extend_from_slice(&a.octets()),
        std::net::IpAddr::V6(a) => token.extend_from_slice(&a.octets()),
    }

    token.extend_from_slice(&hdr.dcid);
    let tag = ring::hmac::sign(token_hmac_key(), &token);
    token.extend_from_slice(tag.as_ref());
    token
}

pub fn validate_token<'a>(
    src: &net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 + HMAC_TAG_LEN {
        return None;
    }

    let (payload, tag) = token.split_at(token.len() - HMAC_TAG_LEN);
    if ring::hmac::verify(token_hmac_key(), payload, tag).is_err() {
        return None;
    }

    if &payload[..6] != b"quiche" {
        return None;
    }

    let payload = &payload[6..];
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if payload.len() < addr.len() || &payload[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&payload[addr.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_mint_and_validate() {
        let src: net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let dcid_bytes = [1, 2, 3, 4];
        let scid_bytes = [5, 6, 7, 8];

        let mut raw_header = Vec::new();
        raw_header.push(0xC0); // Initial flags
        raw_header.extend_from_slice(&quiche::PROTOCOL_VERSION.to_be_bytes());
        raw_header.push(dcid_bytes.len() as u8);
        raw_header.extend_from_slice(&dcid_bytes);
        raw_header.push(scid_bytes.len() as u8);
        raw_header.extend_from_slice(&scid_bytes);
        raw_header.push(0); // Token length (0)
        raw_header.push(0); // Length (0)
        raw_header.extend_from_slice(&[0, 0, 0, 0]); // Packet number

        let hdr = quiche::Header::from_slice(&mut raw_header, quiche::MAX_CONN_ID_LEN).unwrap();

        let token = mint_token(&hdr, &src);
        assert!(!token.is_empty());

        let validated_dcid = validate_token(&src, &token).unwrap();
        assert_eq!(validated_dcid, hdr.dcid);

        // Validation should fail with a different source address
        let wrong_src: net::SocketAddr = "127.0.0.2:12345".parse().unwrap();
        assert!(validate_token(&wrong_src, &token).is_none());

        // Validation should fail with corrupt token
        let mut corrupt_token = token.clone();
        if let Some(last) = corrupt_token.last_mut() {
            *last ^= 0xFF;
        }
        assert_ne!(validate_token(&src, &corrupt_token), Some(hdr.dcid));
    }
}
