use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const CHUNK_SIZE: usize = 64 * 1024;

pub fn run_server(bind: &str) -> Result<(), String> {
    let bind_address = parse_socket_address(bind, "--bind")?;
    let listener = TcpListener::bind(bind_address)
        .map_err(|error| format!("cannot bind TCP server to {bind_address}: {error}"))?;
    let actual_bind = listener
        .local_addr()
        .map_err(|error| format!("cannot read TCP server address: {error}"))?;
    println!(
        "FIXTURE_TCP_SERVER_READY pid={} bind={} started_unix_ms={}",
        process::id(),
        actual_bind,
        unix_millis()?
    );

    let (mut stream, peer) = listener
        .accept()
        .map_err(|error| format!("TCP server accept failed: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("cannot configure accepted TCP stream: {error}"))?;
    let local = stream
        .local_addr()
        .map_err(|error| format!("cannot read accepted local address: {error}"))?;
    let test_id = test_id(peer, local);
    let started = unix_millis()?;
    let mut bytes_received = 0_u64;
    let mut bytes_sent = 0_u64;
    let mut buffer = vec![0_u8; CHUNK_SIZE];

    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("TCP server read failed: {error}"))?;
        if read == 0 {
            break;
        }
        bytes_received = bytes_received
            .checked_add(read as u64)
            .ok_or_else(|| "TCP server received-byte counter overflow".to_owned())?;
        stream
            .write_all(&buffer[..read])
            .map_err(|error| format!("TCP server echo failed: {error}"))?;
        bytes_sent = bytes_sent
            .checked_add(read as u64)
            .ok_or_else(|| "TCP server sent-byte counter overflow".to_owned())?;
    }

    println!(
        "FIXTURE_TCP_SERVER_RESULT test_id={test_id} pid={} local={} peer={} \
         bytes_received={} bytes_sent={} started_unix_ms={} ended_unix_ms={}",
        process::id(),
        local,
        peer,
        bytes_received,
        bytes_sent,
        started,
        unix_millis()?
    );
    Ok(())
}

pub fn run_client(target: &str, planned_bytes: u64) -> Result<(), String> {
    let target_address = parse_socket_address(target, "--target")?;
    let mut writer = TcpStream::connect(target_address)
        .map_err(|error| format!("cannot connect to TCP server at {target_address}: {error}"))?;
    writer
        .set_nodelay(true)
        .map_err(|error| format!("cannot configure TCP client stream: {error}"))?;
    let local = writer
        .local_addr()
        .map_err(|error| format!("cannot read TCP client local address: {error}"))?;
    let peer = writer
        .peer_addr()
        .map_err(|error| format!("cannot read TCP client peer address: {error}"))?;
    let test_id = test_id(local, peer);
    let started = unix_millis()?;
    let reader = writer
        .try_clone()
        .map_err(|error| format!("cannot clone TCP client stream: {error}"))?;
    let reader_thread = thread::spawn(move || receive_and_verify(reader, planned_bytes));

    let bytes_sent = send_pattern(&mut writer, planned_bytes)?;
    writer
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("cannot finish TCP client upload: {error}"))?;
    let bytes_received = reader_thread
        .join()
        .map_err(|_| "TCP client receive thread panicked".to_owned())??;

    println!(
        "FIXTURE_TCP_CLIENT_RESULT test_id={test_id} pid={} local={} peer={} planned_bytes={} \
         bytes_sent={} bytes_received={} verified=true started_unix_ms={} ended_unix_ms={}",
        process::id(),
        local,
        peer,
        planned_bytes,
        bytes_sent,
        bytes_received,
        started,
        unix_millis()?
    );
    Ok(())
}

fn send_pattern(stream: &mut TcpStream, planned_bytes: u64) -> Result<u64, String> {
    let mut sent = 0_u64;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    while sent < planned_bytes {
        let length = usize::try_from((planned_bytes - sent).min(CHUNK_SIZE as u64))
            .map_err(|error| format!("invalid TCP write length: {error}"))?;
        fill_pattern(&mut buffer[..length], sent);
        stream
            .write_all(&buffer[..length])
            .map_err(|error| format!("TCP client write failed: {error}"))?;
        sent += length as u64;
    }
    Ok(sent)
}

fn receive_and_verify(mut stream: TcpStream, planned_bytes: u64) -> Result<u64, String> {
    let mut received = 0_u64;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    while received < planned_bytes {
        let remaining = usize::try_from((planned_bytes - received).min(CHUNK_SIZE as u64))
            .map_err(|error| format!("invalid TCP read length: {error}"))?;
        let read = stream
            .read(&mut buffer[..remaining])
            .map_err(|error| format!("TCP client read failed: {error}"))?;
        if read == 0 {
            return Err(format!(
                "TCP echo ended after {received} of {planned_bytes} bytes"
            ));
        }
        verify_pattern(&buffer[..read], received)?;
        received += read as u64;
    }
    Ok(received)
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
                "TCP echo verification failed at byte {position}: expected {expected}, got {actual}"
            ));
        }
    }
    Ok(())
}

const fn pattern_byte(position: u64) -> u8 {
    ((position.wrapping_mul(31).wrapping_add(17)) % 251) as u8
}

fn parse_socket_address(value: &str, option: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid {option} IP socket address: {error}"))
}

fn test_id(client: SocketAddr, server: SocketAddr) -> String {
    format!(
        "tcp{}-{client}-{server}",
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
    fn pattern_is_stable_across_chunk_boundaries() {
        let mut whole = vec![0_u8; 131_089];
        fill_pattern(&mut whole, 0);

        let mut second_chunk = vec![0_u8; whole.len() - 65_536];
        fill_pattern(&mut second_chunk, 65_536);
        assert_eq!(&whole[65_536..], second_chunk);
        assert!(verify_pattern(&whole, 0).is_ok());
    }

    #[test]
    fn verification_detects_corruption() {
        let mut bytes = vec![0_u8; 32];
        fill_pattern(&mut bytes, 100);
        bytes[7] ^= 1;
        assert!(verify_pattern(&bytes, 100).is_err());
    }
}
