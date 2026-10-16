//! Explicit, foreground, one-shot Noise-authenticated TCP object synchronization.
//! Object IDs are exchanged only inside the encrypted Noise transport. The caller supplies
//! pinned transport keys; collection policy validation remains an application responsibility.
use crate::{
    format::{Id, MAX_OBJECT},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use snow::{Builder, params::NoiseParams};
use std::collections::HashSet;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_IDS: usize = 16_384;
const MAX_TOTAL: u64 = 1 << 30;
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_FRAME: usize = MAX_OBJECT + 64;
const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent: usize,
    pub received: usize,
    pub skipped: usize,
}
fn params() -> Result<NoiseParams> {
    PARAMS.parse().context("Noise parameters")
}
fn setup(s: &mut TcpStream) -> Result<()> {
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    Ok(())
}
fn write_frame(s: &mut TcpStream, b: &[u8]) -> Result<()> {
    ensure!(b.len() <= MAX_FRAME, "frame exceeds limit");
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)?;
    Ok(())
}
fn read_frame(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    s.read_exact(&mut n)?;
    let n = u32::from_be_bytes(n) as usize;
    ensure!(n <= MAX_FRAME, "frame exceeds limit");
    let mut b = vec![0; n];
    s.read_exact(&mut b)?;
    Ok(b)
}
const MSG_CHUNK: usize = 60_000;
fn send_msg(s: &mut TcpStream, t: &mut snow::TransportState, b: &[u8]) -> Result<()> {
    ensure!(b.len() <= MAX_FRAME, "message exceeds limit");
    let total = (b.len() as u32).to_be_bytes();
    let mut first = Vec::with_capacity(MSG_CHUNK);
    first.extend_from_slice(&total);
    first.extend_from_slice(&b[..b.len().min(MSG_CHUNK - 4)]);
    let mut out = vec![0; first.len() + 64];
    let n = t.write_message(&first, &mut out)?;
    write_frame(s, &out[..n])?;
    let mut at = (MSG_CHUNK - 4).min(b.len());
    while at < b.len() {
        let end = (at + MSG_CHUNK).min(b.len());
        let mut out = vec![0; end - at + 64];
        let n = t.write_message(&b[at..end], &mut out)?;
        write_frame(s, &out[..n])?;
        at = end;
    }
    Ok(())
}
fn recv_msg(s: &mut TcpStream, t: &mut snow::TransportState) -> Result<Vec<u8>> {
    let frame = read_frame(s)?;
    let mut out = vec![0; frame.len()];
    let n = t.read_message(&frame, &mut out)?;
    ensure!(n >= 4, "truncated segmented message");
    let total = u32::from_be_bytes(out[..4].try_into()?) as usize;
    ensure!(total <= MAX_FRAME, "message exceeds limit");
    out.truncate(n);
    let mut result = out[4..].to_vec();
    while result.len() < total {
        let frame = read_frame(s)?;
        let mut part = vec![0; frame.len()];
        let n = t.read_message(&frame, &mut part)?;
        ensure!(
            n > 0 && result.len() + n <= total,
            "invalid message segment"
        );
        result.extend_from_slice(&part[..n]);
    }
    ensure!(result.len() == total, "invalid message length");
    Ok(result)
}
fn handshake_client(
    s: &mut TcpStream,
    secret: &[u8],
    pinned: &[u8],
) -> Result<snow::TransportState> {
    let mut h = Builder::new(params()?)
        .local_private_key(secret)?
        .build_initiator()?;
    let mut buf = vec![0; 1024];
    let n = h.write_message(&[], &mut buf)?;
    write_frame(s, &buf[..n])?;
    let b = read_frame(s)?;
    h.read_message(&b, &mut buf)?;
    let n = h.write_message(&[], &mut buf)?;
    write_frame(s, &buf[..n])?;
    ensure!(
        h.get_remote_static() == Some(pinned),
        "peer transport key mismatch"
    );
    Ok(h.into_transport_mode()?)
}
fn handshake_server(
    s: &mut TcpStream,
    secret: &[u8],
    pinned: &[u8],
) -> Result<snow::TransportState> {
    let mut h = Builder::new(params()?)
        .local_private_key(secret)?
        .build_responder()?;
    let mut buf = vec![0; 1024];
    let b = read_frame(s)?;
    h.read_message(&b, &mut buf)?;
    let n = h.write_message(&[], &mut buf)?;
    write_frame(s, &buf[..n])?;
    let b = read_frame(s)?;
    h.read_message(&b, &mut buf)?;
    ensure!(
        h.get_remote_static() == Some(pinned),
        "peer transport key mismatch"
    );
    Ok(h.into_transport_mode()?)
}
fn validate_ids(ids: &[Id]) -> Result<()> {
    ensure!(ids.len() <= MAX_IDS, "too many object ids");
    let unique: HashSet<&Id> = ids.iter().collect();
    ensure!(unique.len() == ids.len(), "duplicate object id");
    Ok(())
}
fn validate_requests(available: &[Id], requests: &[Id]) -> Result<()> {
    validate_ids(available)?;
    validate_ids(requests)?;
    let offered: HashSet<&Id> = available.iter().collect();
    ensure!(
        requests.iter().all(|id| offered.contains(id)),
        "peer requested unadvertised object"
    );
    Ok(())
}
fn ids_message(ids: &[Id]) -> Result<Vec<u8>> {
    validate_ids(ids)?;
    let mut b = Vec::with_capacity(4 + ids.len() * 32);
    b.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        b.extend_from_slice(id);
    }
    Ok(b)
}
fn parse_ids(b: &[u8]) -> Result<Vec<Id>> {
    ensure!(b.len() >= 4, "truncated inventory");
    let n = u32::from_be_bytes(b[..4].try_into()?) as usize;
    ensure!(n <= MAX_IDS && b.len() == 4 + n * 32, "invalid inventory");
    let (chunks, remainder) = b[4..].as_chunks::<32>();
    ensure!(remainder.is_empty(), "invalid inventory length");
    let ids: Vec<Id> = chunks.to_vec();
    validate_ids(&ids)?;
    Ok(ids)
}
fn send_objects(
    s: &mut TcpStream,
    t: &mut snow::TransportState,
    store: &Store,
    ids: &[Id],
    report: &mut SyncReport,
) -> Result<()> {
    let mut total = 0u64;
    for id in ids {
        let b = store.get(id)?;
        total += b.len() as u64;
        ensure!(total <= MAX_TOTAL, "send quota exceeded");
        let mut record = Vec::with_capacity(32 + b.len());
        record.extend_from_slice(id);
        record.extend_from_slice(&b);
        send_msg(s, t, &record)?;
        report.sent += 1;
    }
    Ok(())
}
fn receive_objects(
    s: &mut TcpStream,
    t: &mut snow::TransportState,
    store: &Store,
    ids: &[Id],
    report: &mut SyncReport,
) -> Result<()> {
    let mut total = 0u64;
    for id in ids {
        let record = recv_msg(s, t)?;
        ensure!(
            record.len() >= 32 && record[..32] == id[..],
            "unexpected object response"
        );
        let b = &record[32..];
        ensure!(
            b.len() <= MAX_OBJECT && crate::format::id(b) == *id,
            "invalid received object"
        );
        total += b.len() as u64;
        ensure!(total <= MAX_TOTAL, "receive quota exceeded");
        store.put(b)?;
        report.received += 1;
    }
    Ok(())
}
fn exchange(
    s: &mut TcpStream,
    t: &mut snow::TransportState,
    store: &Store,
    ids: &[Id],
    initiator: bool,
) -> Result<SyncReport> {
    let local_inventory = ids_message(ids)?;
    let remote = if initiator {
        send_msg(s, t, &local_inventory)?;
        parse_ids(&recv_msg(s, t)?)?
    } else {
        let remote = parse_ids(&recv_msg(s, t)?)?;
        send_msg(s, t, &local_inventory)?;
        remote
    };
    let mut need = Vec::new();
    for id in &remote {
        if !store.contains(id)? {
            need.push(*id);
        }
    }
    let local_requests = ids_message(&need)?;
    let requests = if initiator {
        send_msg(s, t, &local_requests)?;
        parse_ids(&recv_msg(s, t)?)?
    } else {
        let requests = parse_ids(&recv_msg(s, t)?)?;
        send_msg(s, t, &local_requests)?;
        requests
    };
    validate_requests(ids, &requests)?;
    let mut report = SyncReport::default();
    if initiator {
        send_objects(s, t, store, &requests, &mut report)?;
        receive_objects(s, t, store, &need, &mut report)?;
    } else {
        receive_objects(s, t, store, &need, &mut report)?;
        send_objects(s, t, store, &requests, &mut report)?;
    }
    Ok(report)
}
/// Connect to an explicitly selected peer; no background task or listener is created.
pub fn sync_client(
    addr: SocketAddr,
    store: &Store,
    secret: &[u8],
    pinned_peer: &[u8],
    ids: &[Id],
) -> Result<SyncReport> {
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    setup(&mut s)?;
    let mut t = handshake_client(&mut s, secret, pinned_peer)?;
    exchange(&mut s, &mut t, store, ids, true)
}
/// Serve exactly one connection on an explicitly bound listener, then return.
pub fn serve_once(
    listener: &TcpListener,
    store: &Store,
    secret: &[u8],
    pinned_peer: &[u8],
    ids: &[Id],
) -> Result<SyncReport> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + TIMEOUT;
    let accepted: std::io::Result<(TcpStream, SocketAddr)> = loop {
        match listener.accept() {
            Ok(pair) => break Ok(pair),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) => break Err(e),
        }
    };
    listener.set_nonblocking(false)?;
    let (mut s, _) = accepted?;
    setup(&mut s)?;
    let mut t = handshake_server(&mut s, secret, pinned_peer)?;
    exchange(&mut s, &mut t, store, ids, false)
}
const IDENTITY_MAGIC: &[u8; 8] = b"ARCNOISE";
const IDENTITY_AAD: &[u8] = b"arc-exp-1/noise-identity\0";
/// Create a password-encrypted Noise static private key at a no-clobber mode-0600 path.
pub fn identity_create(path: &Path, password: &str) -> Result<[u8; 32]> {
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "invalid identity password"
    );
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *secret);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let params = Params::new(65_536, 3, 1, None)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
        password.as_bytes(),
        &salt,
        &mut *key,
    )?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &*secret,
                aad: IDENTITY_AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("identity encryption failed"))?;
    let mut bytes = Vec::with_capacity(8 + 16 + 24 + ciphertext.len());
    bytes.extend_from_slice(IDENTITY_MAGIC);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    public(&*secret)
}
/// Load and authenticate a password-encrypted Noise static private key.
pub fn identity_load(path: &Path, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "invalid identity password"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == 96,
        "invalid Noise identity file"
    );
    let mut bytes = [0u8; 96];
    file.read_exact(&mut bytes)?;
    ensure!(&bytes[..8] == IDENTITY_MAGIC, "invalid Noise identity file");
    let params = Params::new(65_536, 3, 1, None)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
        password.as_bytes(),
        &bytes[8..24],
        &mut *key,
    )?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&bytes[24..48]),
                Payload {
                    msg: &bytes[48..],
                    aad: IDENTITY_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("identity authentication failed"))?,
    );
    Ok(Zeroizing::new(plain.as_slice().try_into()?))
}
/// Derive the public Noise static key corresponding to a private key.
pub fn public(secret: &[u8]) -> Result<[u8; 32]> {
    use x25519_dalek::StaticSecret;
    let private: [u8; 32] = secret.try_into()?;
    let public = x25519_dalek::PublicKey::from(&StaticSecret::from(private));
    Ok(*public.as_bytes())
}
#[cfg(test)]
mod tests {
    use super::{validate_ids, validate_requests};
    #[test]
    fn requests_must_be_unique_and_advertised() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(validate_requests(&[a, b], &[b]).is_ok());
        assert!(validate_requests(&[a], &[b]).is_err());
        assert!(validate_ids(&[a, a]).is_err());
        assert!(validate_requests(&[a, b], &[a, a]).is_err());
    }
}
