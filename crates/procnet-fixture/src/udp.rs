use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DATAGRAM_SIZE: usize = 60_000;
const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run_server(bind: &str) -> Result<(), String> {
    let bind_address = parse_socket_address(bind, "--bind")?;
    let socket = UdpSocket::bind(bind_address)
        .map_err(|error| format!("cannot bind UDP server to {bind_address}: {error}"))?;
    socket
        .set_read_timeout(Some(SERVER_IDLE_TIMEOUT))
        .map_err(|error| format!("cannot configure UDP server timeout: {error}"))?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("cannot read UDP server address: {error}"))?;
    println!(
        "FIXTURE_UDP_SERVER_READY pid={} bind={} started_unix_ms={}",
        process::id(),
        local,
        unix_millis()?
    );

    let started = unix_millis()?;
    let mut peer = None;
    let mut datagrams = 0_u64;
    let mut bytes_received = 0_u64;
    let mut bytes_sent = 0_u64;
    let mut buffer = vec![0_u8; DATAGRAM_SIZE];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((received, source)) => {
                if peer.is_some_and(|expected| expected != source) {
                    return Err(format!(
                        "UDP fixture received an unexpected second peer: {source}"
                    ));
                }
                peer = Some(source);
                let sent = socket
                    .send_to(&buffer[..received], source)
                    .map_err(|error| format!("UDP server echo failed: {error}"))?;
                if sent != received {
                    return Err(format!(
                        "UDP server sent {sent} of {received} datagram bytes"
                    ));
                }
                datagrams += 1;
                bytes_received += received as u64;
                bytes_sent += sent as u64;
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(error) => return Err(format!("UDP server receive failed: {error}")),
        }
    }

    let peer = peer.ok_or_else(|| "UDP server timed out before receiving traffic".to_owned())?;
    println!(
        "FIXTURE_UDP_SERVER_RESULT test_id={} pid={} local={} peer={} datagrams={} \
         bytes_received={} bytes_sent={} started_unix_ms={} ended_unix_ms={}",
        test_id(peer, local),
        process::id(),
        local,
        peer,
        datagrams,
        bytes_received,
        bytes_sent,
        started,
        unix_millis()?
    );
    Ok(())
}

pub fn run_client(target: &str, planned_bytes: u64) -> Result<(), String> {
    let target = parse_socket_address(target, "--target")?;
    let client_bind = if target.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let socket =
        UdpSocket::bind(client_bind).map_err(|error| format!("cannot bind UDP client: {error}"))?;
    socket
        .connect(target)
        .map_err(|error| format!("cannot connect UDP client to {target}: {error}"))?;
    socket
        .set_read_timeout(Some(CLIENT_RESPONSE_TIMEOUT))
        .map_err(|error| format!("cannot configure UDP client timeout: {error}"))?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("cannot read UDP client address: {error}"))?;
    let peer = socket
        .peer_addr()
        .map_err(|error| format!("cannot read UDP client peer: {error}"))?;
    let started = unix_millis()?;
    let mut datagrams = 0_u64;
    let mut bytes_sent = 0_u64;
    let mut bytes_received = 0_u64;
    let mut send_buffer = vec![0_u8; DATAGRAM_SIZE];
    let mut receive_buffer = vec![0_u8; DATAGRAM_SIZE];

    while bytes_sent < planned_bytes {
        let length = usize::try_from((planned_bytes - bytes_sent).min(DATAGRAM_SIZE as u64))
            .map_err(|error| format!("invalid UDP datagram length: {error}"))?;
        fill_pattern(&mut send_buffer[..length], bytes_sent);
        let sent = socket
            .send(&send_buffer[..length])
            .map_err(|error| format!("UDP client send failed: {error}"))?;
        if sent != length {
            return Err(format!("UDP client sent {sent} of {length} datagram bytes"));
        }
        let received = socket
            .recv(&mut receive_buffer)
            .map_err(|error| format!("UDP client receive failed: {error}"))?;
        if received != length {
            return Err(format!(
                "UDP echo length mismatch: expected {length}, got {received}"
            ));
        }
        verify_pattern(&receive_buffer[..received], bytes_received)?;
        datagrams += 1;
        bytes_sent += sent as u64;
        bytes_received += received as u64;
    }

    println!(
        "FIXTURE_UDP_CLIENT_RESULT test_id={} pid={} local={} peer={} planned_bytes={} \
         datagrams={} bytes_sent={} bytes_received={} verified=true started_unix_ms={} \
         ended_unix_ms={}",
        test_id(local, peer),
        process::id(),
        local,
        peer,
        planned_bytes,
        datagrams,
        bytes_sent,
        bytes_received,
        started,
        unix_millis()?
    );
    Ok(())
}

fn fill_pattern(buffer: &mut [u8], offset: u64) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = pattern_byte(offset + index as u64);
    }
}

fn verify_pattern(buffer: &[u8], offset: u64) -> Result<(), String> {
    for (index, actual) in buffer.iter().copied().enumerate() {
        let position = offset + index as u64;
        let expected = pattern_byte(position);
        if actual != expected {
            return Err(format!(
                "UDP echo verification failed at byte {position}: expected {expected}, got {actual}"
            ));
        }
    }
    Ok(())
}

const fn pattern_byte(position: u64) -> u8 {
    ((position.wrapping_mul(47).wrapping_add(29)) % 251) as u8
}

fn parse_socket_address(value: &str, option: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid {option} IP socket address: {error}"))
}

fn test_id(client: SocketAddr, server: SocketAddr) -> String {
    format!(
        "udp{}-{client}-{server}",
        if client.is_ipv4() { "4" } else { "6" }
    )
}

fn unix_millis() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{fill_pattern, verify_pattern};

    #[test]
    fn udp_pattern_is_stable_and_detects_corruption() {
        let mut bytes = vec![0_u8; 60_001];
        fill_pattern(&mut bytes, 0);
        assert!(verify_pattern(&bytes, 0).is_ok());
        bytes[60_000] ^= 1;
        assert!(verify_pattern(&bytes, 0).is_err());
    }
}
