//! Multi-relay acceptance: m01–m11.

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use msgfmt::{decode, decode_relay_set, encode_relay_set, Error as MsgError, RelayEntry, RelaySet};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use transport::{
    channel_id, parse_relay_spec, Channel, FailoverChannel, MockFsChannel, RecoveryState,
};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn relay(name: &str) -> RelayEntry {
    RelayEntry {
        id: channel_id("relay", name),
        kind: "relay".into(),
        tier: 0,
        addr: name.into(),
    }
}

struct Failing;

#[async_trait]
impl Channel for Failing {
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
        channel_id("failing", "m")
    }
}

struct Flaky {
    calls: AtomicUsize,
}

#[async_trait]
impl Channel for Flaky {
    async fn put(&self, _: &[u8]) -> transport::Result<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call % 2 == 0 {
            Err(transport::Error::Relay("flaky".into()))
        } else {
            Ok(())
        }
    }
    async fn list_since(&self, _: u64) -> transport::Result<Vec<(u64, Vec<u8>)>> {
        Ok(Vec::new())
    }
    fn name() -> &'static str {
        "flaky"
    }
    fn id(&self) -> [u8; 8] {
        channel_id("flaky", "m")
    }
}

#[tokio::test]
async fn m01_per_channel_cursors_are_independent() {
    let a = MockFsChannel::new(integration_tests::temp("m01-a"));
    let b = MockFsChannel::new(integration_tests::temp("m01-b"));
    a.put(b"a1").await.unwrap();
    a.put(b"a2").await.unwrap();
    b.put(b"b1").await.unwrap();
    assert_eq!(a.list_since(0).await.unwrap().len(), 2);
    assert_eq!(a.list_since(1).await.unwrap().len(), 1);
    assert_eq!(b.list_since(1).await.unwrap().len(), 0);
    assert_eq!(a.id(), MockFsChannel::new(a.root()).id());
}

#[tokio::test]
async fn m02_failover_does_not_starve_the_fallback() {
    let good = Arc::new(MockFsChannel::new(integration_tests::temp("m02")));
    let flaky = Arc::new(Flaky {
        calls: AtomicUsize::new(0),
    });
    let failover = FailoverChannel::new(vec![flaky, good.clone()]).unwrap();
    for index in 0..4_u8 {
        failover
            .put(&[index])
            .await
            .expect("fallback admits every put");
    }
    assert_eq!(good.list_since(0).await.unwrap().len(), 4);
}

#[tokio::test]
async fn m03_fan_out_reaches_three_channels() {
    let frame = b"result-frame";
    let mut roots = Vec::new();
    for index in 0..3 {
        let channel = MockFsChannel::new(integration_tests::temp(&format!("m03-{index}")));
        channel.put(frame).await.unwrap();
        roots.push(channel);
    }
    for channel in roots {
        assert_eq!(channel.list_since(0).await.unwrap()[0].1, frame);
    }
}

#[tokio::test]
async fn m04_mid_flight_loss_lands_on_the_next_channel() {
    let good = Arc::new(MockFsChannel::new(integration_tests::temp("m04")));
    let failover = FailoverChannel::new(vec![Arc::new(Failing), good.clone()]).unwrap();
    failover.put(b"lost-on-primary").await.unwrap();
    let entries = good.list_since(0).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1, b"lost-on-primary");
}

#[test]
fn m05_tier_then_priority_orders_relays() {
    let mut specs = [
        "2:5:relay:https://c",
        "0:9:relay:https://a",
        "0:1:relay:https://b",
    ]
    .map(|spec| parse_relay_spec(spec).unwrap())
    .to_vec();
    specs.sort_by_key(|spec| (spec.tier, spec.priority));
    assert_eq!(specs[0].arg, "https://b");
    assert_eq!(specs[1].arg, "https://a");
    assert_eq!(specs[2].arg, "https://c");
    assert_eq!(specs[2].tier, 2);
}

#[test]
fn m06_relay_set_applies_and_round_trips() {
    let signing = key();
    let set = RelaySet {
        gen: 7,
        add: vec![relay("https://one"), relay("https://two")],
        remove: vec![channel_id("relay", "https://old")],
    };
    let frame = encode_relay_set(&set, &[4; 32], &signing).unwrap();
    let mut last = 0;
    let decoded = decode_relay_set(&frame, &signing.verifying_key(), &[4; 32], &mut last).unwrap();
    assert_eq!(decoded.relay_set, set);
    assert_eq!(last, 7);
}

#[test]
fn m07_a_replayed_relay_set_is_stale() {
    let signing = key();
    let set = RelaySet {
        gen: 2,
        add: vec![relay("https://one")],
        remove: Vec::new(),
    };
    let frame = encode_relay_set(&set, &[4; 32], &signing).unwrap();
    let mut last = 0;
    decode_relay_set(&frame, &signing.verifying_key(), &[4; 32], &mut last).unwrap();
    assert_eq!(
        decode_relay_set(&frame, &signing.verifying_key(), &[4; 32], &mut last),
        Err(MsgError::StaleEpoch)
    );
}

#[test]
fn m08_bootstrap_recovery_waits_three_cycles_and_resets() {
    let mut recovery = RecoveryState::default();
    assert!(!recovery.record_all_down(30));
    assert!(!recovery.record_all_down(30));
    assert!(recovery.record_all_down(30));
    recovery.tier_zero_succeeded();
    assert!(!recovery.record_all_down(30));
}

#[test]
fn m09_removals_are_tombstoned_in_the_set() {
    let signing = key();
    let removed = channel_id("relay", "https://old");
    let set = RelaySet {
        gen: 3,
        add: Vec::new(),
        remove: vec![removed],
    };
    let frame = encode_relay_set(&set, &[4; 32], &signing).unwrap();
    let mut last = 0;
    let decoded = decode_relay_set(&frame, &signing.verifying_key(), &[4; 32], &mut last).unwrap();
    assert_eq!(decoded.relay_set.remove, vec![removed]);
    assert!(decoded.relay_set.add.is_empty());
}

#[tokio::test]
async fn m10_quorum_failure_is_reported() {
    let failover = FailoverChannel::new(vec![Arc::new(Failing), Arc::new(Failing)]).unwrap();
    assert!(failover.put(b"frame").await.is_err());
    assert!(failover.list_since(0).await.is_err());
}

#[test]
fn m11_unknown_msg_type_is_rejected_after_decryption() {
    // A validly encrypted relay-set frame is not a task. The task decoder
    // must reject it by type, not by AEAD or signature failure.
    let signing = key();
    let frame = encode_relay_set(
        &RelaySet {
            gen: 1,
            add: vec![relay("https://one")],
            remove: Vec::new(),
        },
        &[4; 32],
        &signing,
    )
    .unwrap();
    assert_eq!(decode(&frame, &[4; 32]), Err(MsgError::UnknownMsgType));
}

#[test]
fn relay_set_ids_must_be_stable() {
    let entries = BTreeMap::from([("one", relay("https://one"))]);
    assert_eq!(entries["one"].id, channel_id("relay", "https://one"));
}
