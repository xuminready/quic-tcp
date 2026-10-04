use crate::MAX_DATAGRAM_SIZE;

pub fn get_quic_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config
        .set_application_protos(&[b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"])
        .unwrap();
    let datagram_size = std::env::var("QUIC_MAX_DATAGRAM_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(MAX_DATAGRAM_SIZE);
    config.set_max_recv_udp_payload_size(datagram_size);
    config.set_max_send_udp_payload_size(datagram_size);
    config.set_initial_max_data(1_000_000_000); // 1 GB initial data
    config.set_initial_max_stream_data_bidi_local(250_000_000); // 250 MB stream window
    config.set_initial_max_stream_data_bidi_remote(250_000_000);
    config.set_initial_max_stream_data_uni(250_000_000);
    config.set_initial_max_streams_bidi(10_000);
    config.set_initial_max_streams_uni(10_000);
    config.set_max_connection_window(250_000_000);
    config.set_max_stream_window(250_000_000);
    config.set_ack_delay_exponent(3);
    config.set_max_ack_delay(25);
    config.set_active_connection_id_limit(10);
    config.set_disable_active_migration(true);
    config.set_max_idle_timeout(60000);
    config.enable_pacing(false);
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);
    config
}
