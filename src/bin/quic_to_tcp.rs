use quic_tcp::install_shutdown_handlers;
use quic_tcp::quic_to_tcp::{ServerMode, run_quic_to_tcp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    install_shutdown_handlers();

    let args: Vec<String> = std::env::args().collect();
    let mode = match ServerMode::from_args(&args) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&args[0]);
            return Ok(());
        }
    };

    run_quic_to_tcp(mode)
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!(
        "  {} [direct] <Local_UDP_IP:Port> <Remote_TCP_IP:Port> [Secret_Code]",
        bin_name
    );
    eprintln!(
        "  Example: {} 127.0.0.1:4433 127.0.0.1:8080 my_secret",
        bin_name
    );
    eprintln!();
    eprintln!("Usage (P2P Mode):");
    eprintln!(
        "  {} p2p <Rendezvous_Server_IP:Port> <Remote_TCP_IP:Port> [Secret_Code]",
        bin_name
    );
    eprintln!(
        "  Example: {} p2p 1.2.3.4:5050 127.0.0.1:8080 my_secret",
        bin_name
    );
}
