pub mod auth;
pub mod config;
pub mod p2p;
pub mod protocol;
pub mod session;
pub mod token;
pub mod utils;

pub const MAX_DATAGRAM_SIZE: usize = 1450;
pub const TCP_TOKEN: mio::Token = mio::Token(0);
pub const UDP_TOKEN: mio::Token = mio::Token(1);

// Re-exports for convenience
pub use auth::{compute_auth, derive_tunnel_id, next_seq, verify_auth, ReplayFilter};
pub use config::get_quic_config;
pub use p2p::{
    perform_hole_punching, reconnect_client_p2p_handshake, run_client_p2p_handshake,
    run_server_p2p_handshake, send_server_keepalive, send_server_status,
    server_handle_reconnect_punch,
};
pub use protocol::{
    ClientConn, ClientReset, PeerProbe, PunchSignal, RegOk, ServerReg, ServerStatusMsg,
};
pub use session::{FlushStatus, PartialWrite, Session, flush_quic_to_udp};
pub use token::{mint_token, validate_token};
pub use utils::{
    bind_tcp_listener, hex_dump, interrupted, next_stream_id, next_token, normalize_socket_addr,
    optimize_tcp_stream, optimize_udp_socket, would_block,
};