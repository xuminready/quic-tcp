pub mod config;
pub mod p2p;
pub mod session;
pub mod token;
pub mod utils;

pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const TCP_TOKEN: mio::Token = mio::Token(0);
pub const UDP_TOKEN: mio::Token = mio::Token(1);

// Re-exports for convenience
pub use config::get_quic_config;
pub use p2p::{perform_hole_punching, run_client_p2p_handshake, run_server_p2p_handshake};
pub use session::{FlushStatus, PartialWrite, Session, flush_quic_to_udp};
pub use token::{mint_token, validate_token};
pub use utils::{hex_dump, interrupted, next_stream_id, next_token, would_block};
