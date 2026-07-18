//! Deterministic local traffic fixture used only by V0 validation.

#![forbid(unsafe_code)]

mod tcp;
mod udp;

use std::env;
use std::process::ExitCode;

const MAX_FIXTURE_BYTES: u64 = 1_073_741_824;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    TcpServer { bind: String },
    TcpClient { target: String, bytes: u64 },
    UdpServer { bind: String },
    UdpClient { target: String, bytes: u64 },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&arguments)? {
        Command::TcpServer { bind } => tcp::run_server(&bind),
        Command::TcpClient { target, bytes } => tcp::run_client(&target, bytes),
        Command::UdpServer { bind } => udp::run_server(&bind),
        Command::UdpClient { target, bytes } => udp::run_client(&target, bytes),
    }
}

fn parse_command(arguments: &[String]) -> Result<Command, String> {
    match arguments {
        [command, flag, bind] if command == "tcp-server" && flag == "--bind" => {
            Ok(Command::TcpServer { bind: bind.clone() })
        }
        [command, target_flag, target, bytes_flag, bytes]
            if command == "tcp-client" && target_flag == "--target" && bytes_flag == "--bytes" =>
        {
            Ok(Command::TcpClient {
                target: target.clone(),
                bytes: parse_bytes(bytes)?,
            })
        }
        [command, flag, bind] if command == "udp-server" && flag == "--bind" => {
            Ok(Command::UdpServer { bind: bind.clone() })
        }
        [command, target_flag, target, bytes_flag, bytes]
            if command == "udp-client" && target_flag == "--target" && bytes_flag == "--bytes" =>
        {
            Ok(Command::UdpClient {
                target: target.clone(),
                bytes: parse_bytes(bytes)?,
            })
        }
        _ => Err(
            "usage: procnet-fixture <tcp-server|udp-server> --bind <IP-socket-address> | \
             <tcp-client|udp-client> --target <IP-socket-address> --bytes <1..1073741824>"
                .to_owned(),
        ),
    }
}

fn parse_bytes(value: &str) -> Result<u64, String> {
    let bytes = value
        .parse::<u64>()
        .map_err(|error| format!("invalid --bytes value: {error}"))?;
    if bytes == 0 || bytes > MAX_FIXTURE_BYTES {
        return Err(format!("--bytes must be between 1 and {MAX_FIXTURE_BYTES}"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_command};

    #[test]
    fn parses_documented_tcp_client_contract() {
        let arguments = [
            "tcp-client".to_owned(),
            "--target".to_owned(),
            "127.0.0.1:39001".to_owned(),
            "--bytes".to_owned(),
            "52428800".to_owned(),
        ];
        assert_eq!(
            parse_command(&arguments),
            Ok(Command::TcpClient {
                target: "127.0.0.1:39001".to_owned(),
                bytes: 52_428_800,
            })
        );
    }

    #[test]
    fn rejects_zero_or_unbounded_byte_counts() {
        for bytes in ["0", "1073741825"] {
            let arguments = [
                "tcp-client".to_owned(),
                "--target".to_owned(),
                "127.0.0.1:39001".to_owned(),
                "--bytes".to_owned(),
                bytes.to_owned(),
            ];
            assert!(parse_command(&arguments).is_err());
        }
    }

    #[test]
    fn parses_documented_udp_contract() {
        let server = [
            "udp-server".to_owned(),
            "--bind".to_owned(),
            "127.0.0.1:39002".to_owned(),
        ];
        assert_eq!(
            parse_command(&server),
            Ok(Command::UdpServer {
                bind: "127.0.0.1:39002".to_owned()
            })
        );

        let client = [
            "udp-client".to_owned(),
            "--target".to_owned(),
            "127.0.0.1:39002".to_owned(),
            "--bytes".to_owned(),
            "10485760".to_owned(),
        ];
        assert_eq!(
            parse_command(&client),
            Ok(Command::UdpClient {
                target: "127.0.0.1:39002".to_owned(),
                bytes: 10_485_760,
            })
        );
    }

    #[test]
    fn accepts_bracketed_ipv6_fixture_addresses() {
        let server = [
            "tcp-server".to_owned(),
            "--bind".to_owned(),
            "[::1]:39004".to_owned(),
        ];
        assert_eq!(
            parse_command(&server),
            Ok(Command::TcpServer {
                bind: "[::1]:39004".to_owned()
            })
        );
    }
}
