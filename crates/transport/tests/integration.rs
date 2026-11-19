use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use msgfmt::{decode_checked, encode_task, Task, TaskBody};
use tokio::fs;
use transport::{Channel, MockFsChannel};

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "agent-fleet-transport-integration-{}",
        std::process::id()
    ))
}

#[tokio::test]
async fn encode_put_list_decode_round_trips_without_network() {
    let root = temp_root();
    let _ = fs::remove_dir_all(&root).await;
    let channel = MockFsChannel::new(&root);
    let signing = SigningKey::from_bytes(&[4_u8; 32]);
    let frame = encode_task(
        &Task {
            route_tag: [3; 8],
            epoch: 1,
            body: TaskBody::Ping,
        },
        &[5_u8; 32],
        &signing,
    )
    .expect("frame should encode");
    channel.put(&frame).await.expect("frame should be stored");
    let entries = channel.list_since(0).await.expect("frame should be listed");
    assert_eq!(entries.len(), 1);
    let mut last = 0;
    let decoded = decode_checked(
        &entries[0].1,
        &signing.verifying_key(),
        &[5_u8; 32],
        &mut last,
    )
    .expect("frame should decode");
    assert_eq!(decoded.task.route_tag, [3; 8]);
    fs::remove_dir_all(root)
        .await
        .expect("cleanup should succeed");
}

#[test]
fn channel_name_is_stable() {
    assert_eq!(MockFsChannel::name(), "mock-fs");
}
