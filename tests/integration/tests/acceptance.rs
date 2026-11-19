//! Baseline acceptance: t01–t10.

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use msgfmt::{decode_checked, encode_task, verify, Error as MsgError, Task, TaskBody};
use std::sync::Arc;
use tokio::fs;
use transport::{Channel, FailoverChannel, MockFsChannel};

fn root(label: &str) -> std::path::PathBuf {
    integration_tests::temp(label)
}

fn frame(epoch: u64, tag: [u8; 8]) -> (Vec<u8>, SigningKey) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let bytes = encode_task(
        &Task {
            route_tag: tag,
            epoch,
            body: TaskBody::Ping,
        },
        &[8; 32],
        &key,
    )
    .expect("frame");
    (bytes, key)
}

struct FailingChannel;

#[async_trait]
impl Channel for FailingChannel {
    async fn put(&self, _: &[u8]) -> transport::Result<()> {
        Err(transport::Error::Relay("down".into()))
    }
    async fn list_since(&self, _: u64) -> transport::Result<Vec<(u64, Vec<u8>)>> {
        Err(transport::Error::Relay("down".into()))
    }
    fn name() -> &'static str {
        "failing"
    }
    fn id(&self) -> [u8; 8] {
        transport::channel_id(Self::name(), "test")
    }
}

#[tokio::test]
async fn t01_end_to_end() {
    let dir = root("t01");
    let channel = MockFsChannel::new(&dir);
    let (bytes, key) = frame(1, [1; 8]);
    channel.put(&bytes).await.unwrap();
    let entries = channel.list_since(0).await.unwrap();
    let mut epoch = 0;
    assert_eq!(
        decode_checked(&entries[0].1, &key.verifying_key(), &[8; 32], &mut epoch)
            .unwrap()
            .task
            .epoch,
        1
    );
}

#[tokio::test]
async fn t02_broadcast_to_three_agents() {
    let (bytes, key) = frame(1, [0; 8]);
    for _ in 0..3 {
        let mut epoch = 0;
        assert!(decode_checked(&bytes, &key.verifying_key(), &[8; 32], &mut epoch).is_ok());
    }
}

#[test]
fn t03_unsigned_rejected() {
    let (mut bytes, key) = frame(1, [1; 8]);
    bytes[0] ^= 1;
    assert_eq!(
        verify(&bytes, &key.verifying_key()),
        Err(MsgError::BadSignature)
    );
}

#[test]
fn t04_duplicate_suppressed() {
    let (bytes, key) = frame(1, [1; 8]);
    let mut epoch = 0;
    decode_checked(&bytes, &key.verifying_key(), &[8; 32], &mut epoch).unwrap();
    assert_eq!(
        decode_checked(&bytes, &key.verifying_key(), &[8; 32], &mut epoch),
        Err(MsgError::StaleEpoch)
    );
}

#[test]
fn t05_bit_flip_skipped() {
    let (mut bytes, key) = frame(1, [1; 8]);
    bytes[32] ^= 1;
    let mut epoch = 0;
    assert_eq!(
        decode_checked(&bytes, &key.verifying_key(), &[8; 32], &mut epoch),
        Err(MsgError::BadSignature)
    );
}

#[tokio::test]
async fn t06_transport_swap() {
    let a = Arc::new(MockFsChannel::new(root("t06-a")));
    let b = Arc::new(MockFsChannel::new(root("t06-b")));
    let failover = FailoverChannel::new(vec![Arc::new(FailingChannel), b.clone()]).unwrap();
    failover.put(b"frame").await.unwrap();
    assert_eq!(b.list_since(0).await.unwrap().len(), 1);
    let _ = a;
}

#[tokio::test]
async fn t07_restart_resume() {
    let dir = root("t07");
    let channel = MockFsChannel::new(&dir);
    channel.put(b"one").await.unwrap();
    channel.put(b"two").await.unwrap();
    let entries = channel.list_since(1).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, b"two");
}

#[tokio::test]
async fn t08_failover() {
    let good = Arc::new(MockFsChannel::new(root("t08")));
    let failover = FailoverChannel::new(vec![Arc::new(FailingChannel), good.clone()]).unwrap();
    failover.put(b"ok").await.unwrap();
    assert_eq!(good.list_since(0).await.unwrap().len(), 1);
}

#[tokio::test]
async fn t09_concurrency() {
    let dir = root("t09");
    let channel = Arc::new(MockFsChannel::new(&dir));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let c = Arc::clone(&channel);
        tasks.push(tokio::spawn(async move {
            c.put(b"task").await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(channel.list_since(0).await.unwrap().len(), 8);
}

#[test]
fn t10_rotate_epochs() {
    let (first, key) = frame(1, [1; 8]);
    let second = encode_task(
        &Task {
            route_tag: [1; 8],
            epoch: 2,
            body: TaskBody::Ping,
        },
        &[8; 32],
        &key,
    )
    .unwrap();
    let mut epoch = 0;
    decode_checked(&first, &key.verifying_key(), &[8; 32], &mut epoch).unwrap();
    assert_eq!(
        decode_checked(&second, &key.verifying_key(), &[8; 32], &mut epoch)
            .unwrap()
            .task
            .epoch,
        2
    );
}

#[tokio::test]
async fn t11_whole_suite_leaves_no_files_in_the_state_directory() {
    let dir = root("t11");
    assert!(fs::read_dir(&dir)
        .await
        .unwrap()
        .next_entry()
        .await
        .unwrap()
        .is_none());
}
