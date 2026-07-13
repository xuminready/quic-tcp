use std::io;

pub fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

pub fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

pub fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("")
}

pub fn next_token(current: &mut mio::Token) -> mio::Token {
    let next = current.0;
    current.0 += 1;
    mio::Token(next)
}

pub fn next_stream_id(current: &mut u64) -> u64 {
    const MAX_STREAM_ID: u64 = (1 << 62) - 1;
    if *current > MAX_STREAM_ID - 4 {
        log::warn!("Stream ID space exhausted. Resetting to 0.");
        *current = 0;
    }
    let next = *current;
    *current += 4;
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump() {
        assert_eq!(hex_dump(&[0x01, 0x02, 0x0f, 0x10, 0xff]), "01020f10ff");
        assert_eq!(hex_dump(&[]), "");
    }

    #[test]
    fn test_next_token() {
        let mut token = mio::Token(10);
        assert_eq!(next_token(&mut token), mio::Token(10));
        assert_eq!(next_token(&mut token), mio::Token(11));
        assert_eq!(token, mio::Token(12));
    }

    #[test]
    fn test_next_stream_id() {
        let mut id = 0;
        assert_eq!(next_stream_id(&mut id), 0);
        assert_eq!(next_stream_id(&mut id), 4);

        let mut limit_id = ((1 << 62) - 1) - 2;
        // Since limit_id > MAX_STREAM_ID - 4, this call resets it to 0 and returns 0
        assert_eq!(next_stream_id(&mut limit_id), 0);
        // The subsequent call returns 4
        assert_eq!(next_stream_id(&mut limit_id), 4);
    }
}
