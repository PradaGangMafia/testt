//! P2P acceptance: n01–n12.

use ed25519_dalek::SigningKey;
use msgfmt::{decode_peer_record, encode_peer_record, Error as MsgError, PeerRecord};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Mutex,
};
use transport::{
    parse_relay_spec, punch, Channel, HealthState, P2pChannel, PunchConfig, RecoveryState,
    ReplicationBudget, ReplicationClass,
};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

fn peer(epoch: u64, supernode: bool) -> PeerRecord {
    let signing = key();
    PeerRecord {
        epoch,
        agent_pub: *signing.verifying_key().as_bytes(),
        listen: Some("127.0.0.1:9000".into()),
        observed: None,
        relays: vec!["0:0:relay:https://relay.invalid".into()],
        supernode,
        uptime_s: 12,
        load: 1,
        version: "0.1.0".into(),
    }
}

#[test]
fn n01_signed_peer_record_round_trips() {
    let signing = key();
    let record = peer(1, true);
    let frame = encode_peer_record(&record, &[5; 32], &signing).unwrap();
    let mut last = 0;
    let decoded = decode_peer_record(&frame, &signing.verifying_key(), &[5; 32], &mut last)
        .expect("signed record");
    assert_eq!(decoded.peer, record);
}

#[test]
fn n02_unenrolled_key_is_rejected() {
    let signing = key();
    let other = SigningKey::from_bytes(&[12; 32]);
    let frame = encode_peer_record(&peer(1, false), &[5; 32], &signing).unwrap();
    let mut last = 0;
    assert_eq!(
        decode_peer_record(&frame, &other.verifying_key(), &[5; 32], &mut last),
        Err(MsgError::BadSignature)
    );
}

#[test]
fn n03_replayed_peer_record_is_stale() {
    let signing = key();
    let frame = encode_peer_record(&peer(4, false), &[5; 32], &signing).unwrap();
    let mut last = 0;
    decode_peer_record(&frame, &signing.verifying_key(), &[5; 32], &mut last).unwrap();
    assert_eq!(
        decode_peer_record(&frame, &signing.verifying_key(), &[5; 32], &mut last),
        Err(MsgError::StaleEpoch)
    );
}

#[test]
fn n04_supernode_records_carry_the_flag() {
    let signing = key();
    let frame = encode_peer_record(&peer(2, true), &[5; 32], &signing).unwrap();
    let mut last = 0;
    assert!(
        decode_peer_record(&frame, &signing.verifying_key(), &[5; 32], &mut last)
            .unwrap()
            .peer
            .supernode
    );
}

#[tokio::test]
async fn n05_cursor_is_stable_across_channel_instances() {
    let (base, frames) = relay_server().await;
    let channel = P2pChannel::new(base.clone(), [9; 32]).unwrap();
    channel.put(b"frame-one").await.unwrap();
    channel.put(b"frame-two").await.unwrap();
    assert_eq!(channel.list_since(0).await.unwrap().len(), 2);
    assert_eq!(channel.list_since(1).await.unwrap().len(), 1);
    assert_eq!(channel.list_since(2).await.unwrap().len(), 0);
    let second = P2pChannel::new(base, [9; 32]).unwrap();
    assert_eq!(channel.id(), second.id());
    assert_eq!(frames.lock().await.len(), 2);
    assert_eq!(channel.tier(), 2);
}

#[test]
fn n06_three_control_replicas_fit_the_budget() {
    let mut budget = ReplicationBudget::default();
    for _ in 0..3 {
        assert!(budget.admit(4000, ReplicationClass::Control, true));
    }
}

#[test]
fn n07_control_traffic_replicates_even_when_tier_zero_is_healthy() {
    let mut budget = ReplicationBudget::default();
    assert!(!budget.admit(4000, ReplicationClass::Ordinary, true));
    assert!(budget.admit(4000, ReplicationClass::Control, true));
    assert!(budget.admit(4000, ReplicationClass::Result, true));
}

#[test]
fn n08_recovery_window_expires() {
    let mut recovery = RecoveryState::default();
    assert!(!recovery.record_all_down(31 * 60));
    assert!(recovery.expired());
}

#[test]
fn n09_bootstrap_relay_is_tier_zero() {
    let spec = parse_relay_spec("0:0:bootstrap:https://bootstrap.invalid").unwrap();
    assert_eq!(spec.tier, 0);
    assert_eq!(spec.kind, "bootstrap");
    assert_eq!(spec.priority, 0);
}

#[tokio::test]
async fn n10_udp_punch_selects_the_replying_peer() {
    let responder = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer_addr = responder.local_addr().unwrap();
    let responder_task = {
        let responder = Arc::clone(&responder);
        tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (len, from) = responder.recv_from(&mut buf).await.unwrap();
            assert!(len >= 20);
            let mut reply = [0_u8; 20];
            reply[0..2].copy_from_slice(&0x0101_u16.to_be_bytes());
            reply[2..4].copy_from_slice(&0u16.to_be_bytes());
            reply[4..8].copy_from_slice(&0x2112_A442_u32.to_be_bytes());
            reply[8..20].copy_from_slice(&buf[8..20]);
            responder.send_to(&reply, from).await.unwrap();
        })
    };
    let result = punch(PunchConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        candidates: vec![peer_addr],
    })
    .await
    .expect("punch succeeds");
    assert_eq!(result.peer, peer_addr);
    responder_task.await.unwrap();
}

#[test]
fn n11_sticky_failure_skips_until_the_backoff_expires() {
    let mut health = HealthState::default();
    health.failure(1_000);
    health.failure(1_000);
    assert!(health.eligible(1_000));
    health.failure(1_000);
    assert!(!health.eligible(1_599));
    assert!(health.eligible(1_600));
    health.success();
    assert!(health.eligible(0));
    assert_eq!(health.strikes, 0);
}

#[test]
fn n12_amplification_cap_limits_a_cycle() {
    let mut budget = ReplicationBudget::default();
    budget.new_cycle();
    assert!(budget.admit(2 * 1024 * 1024, ReplicationClass::Result, true));
    assert!(!budget.admit(1, ReplicationClass::Result, true));
    budget.new_cycle();
    assert!(budget.admit(1024, ReplicationClass::Result, true));
}

/// Minimal in-process relay speaking the `/put` and `/list` protocol.
async fn relay_server() -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let stored = Arc::clone(&frames);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let stored = Arc::clone(&stored);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];
                let header_end = loop {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    if let Some(index) = find_header_end(&buffer) {
                        break index;
                    }
                };
                let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buffer.len() < header_end + 4 + length {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                let body = buffer[header_end + 4..].to_vec();
                let first = headers.lines().next().unwrap_or_default();
                if first.starts_with("POST /put ") {
                    stored.lock().await.push(body);
                    respond(&mut stream, "200 OK", b"{}").await;
                } else if let Some(query) = first.strip_prefix("GET /list?since=") {
                    let since: usize = query
                        .split_whitespace()
                        .next()
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0);
                    let frames = stored.lock().await;
                    let body = format!(
                        "[{}]",
                        frames
                            .iter()
                            .enumerate()
                            .filter(|(index, _)| index + 1 > since)
                            .map(|(index, frame)| format!(
                                "[{},\"{}\"]",
                                index + 1,
                                frame
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<String>()
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    respond(&mut stream, "200 OK", body.as_bytes()).await;
                } else {
                    respond(&mut stream, "404 Not Found", b"{}").await;
                }
            });
        }
    });
    (format!("http://{address}"), frames)
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn respond(stream: &mut tokio::net::TcpStream, status: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(body).await;
}
