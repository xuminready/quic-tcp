use std::net;

pub fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();
    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);
    token
}

pub fn validate_token<'a>(
    src: &net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 || &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
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
