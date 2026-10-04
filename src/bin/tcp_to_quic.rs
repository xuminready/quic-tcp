use quic_tcp::install_shutdown_handlers;
use quic_tcp::tcp_to_quic::{ClientMode, run_tcp_to_quic};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    install_shutdown_handlers();

    let args: Vec<String> = std::env::args().collect();
    let mode = match ClientMode::from_args(&args) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&args[0]);
            return Ok(());
        }
    };

    run_tcp_to_quic(mode)
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!(
        "  {} [direct] <Local_TCP_IP:Port> <Remote_UDP_IP:Port> [Secret_Code]",
        bin_name
    );
    eprintln!(
        "  Example: {} 127.0.0.1:7070 127.0.0.1:4433 my_secret",
        bin_name
    );
    eprintln!();
    eprintln!("Usage (P2P Mode):");
    eprintln!(
        "  {} p2p <Rendezvous_Server_IP:Port> <Local_TCP_IP:Port> [Secret_Code]",
        bin_name
    );
    eprintln!(
        "  Example: {} p2p 1.2.3.4:5050 127.0.0.1:7070 my_secret",
        bin_name
    );
}
