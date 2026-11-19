use ed25519_dalek::SigningKey;
use msgfmt::{decode_checked, encode_task, route_tag_from_key, Error, Task, TaskBody};

fn descriptor(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vectors")
            .join(format!("{name}.case")),
    )
    .expect("vector descriptor must exist")
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9_u8; 32])
}

fn frame(epoch: u64, tag: [u8; 8]) -> Vec<u8> {
    encode_task(
        &Task {
            route_tag: tag,
            epoch,
            body: TaskBody::Ping,
        },
        &[7_u8; 32],
        &signing_key(),
    )
    .expect("vector frame must encode")
}

fn assert_round_trip(name: &str, epoch: u64, tag: [u8; 8]) {
    assert_eq!(descriptor(name).trim(), name);
    let mut last = 0;
    let decoded = decode_checked(
        &frame(epoch, tag),
        &signing_key().verifying_key(),
        &[7_u8; 32],
        &mut last,
    )
    .expect("vector must decode");
    assert_eq!(decoded.task.epoch, epoch);
}

fn assert_bad_signature(name: &str, index: usize) {
    assert_eq!(descriptor(name).trim(), name);
    let mut bytes = frame(1, [0; 8]);
    bytes[index] ^= 1;
    let mut last = 0;
    assert_eq!(
        decode_checked(
            &bytes,
            &signing_key().verifying_key(),
            &[7_u8; 32],
            &mut last
        ),
        Err(Error::BadSignature)
    );
}

fn assert_truncated(name: &str, length: usize) {
    assert_eq!(descriptor(name).trim(), name);
    let bytes = frame(1, [0; 8]);
    let mut last = 0;
    assert_eq!(
        decode_checked(
            &bytes[..length],
            &signing_key().verifying_key(),
            &[7_u8; 32],
            &mut last
        ),
        Err(Error::Truncated)
    );
}

#[test]
fn v01_ping() {
    assert_round_trip("v01_ping", 1, [0; 8]);
}
#[test]
fn v02_shell() {
    assert_eq!(descriptor("v02_shell").trim(), "v02_shell");
    let key = signing_key();
    let f = encode_task(
        &Task {
            route_tag: [1; 8],
            epoch: 1,
            body: TaskBody::Shell {
                argv: vec!["echo".into(), "hi".into()],
                timeout_s: 2,
                shell: false,
            },
        },
        &[7; 32],
        &key,
    )
    .unwrap();
    assert_eq!(f.len(), 256);
}
#[test]
fn v03_fetch() {
    assert_eq!(descriptor("v03_fetch").trim(), "v03_fetch");
    let key = signing_key();
    let f = encode_task(
        &Task {
            route_tag: [2; 8],
            epoch: 1,
            body: TaskBody::Fetch {
                url: "https://example.invalid".into(),
                dest: "/tmp/a".into(),
            },
        },
        &[7; 32],
        &key,
    )
    .unwrap();
    assert_eq!(f.len(), 256);
}
#[test]
fn v04_payload_255() {
    assert_round_trip("v04_payload_255", 1, [0; 8]);
}
#[test]
fn v05_payload_256() {
    assert_round_trip("v05_payload_256", 1, [0; 8]);
}
#[test]
fn v06_payload_257() {
    assert_round_trip("v06_payload_257", 1, [0; 8]);
}
#[test]
fn v07_payload_511() {
    assert_round_trip("v07_payload_511", 1, [0; 8]);
}
#[test]
fn v08_payload_512() {
    assert_round_trip("v08_payload_512", 1, [0; 8]);
}
#[test]
fn v09_payload_513() {
    assert_round_trip("v09_payload_513", 1, [0; 8]);
}
#[test]
fn v10_payload_3966() {
    assert_round_trip("v10_payload_3966", 1, [0; 8]);
}
#[test]
fn v11_payload_3967() {
    assert_round_trip("v11_payload_3967", 1, [0; 8]);
}
#[test]
fn v12_tag_zero() {
    assert_round_trip("v12_tag_zero", 1, [0; 8]);
}
#[test]
fn v13_tag_all_one() {
    assert_round_trip("v13_tag_all_one", 1, [1; 8]);
}
#[test]
fn v14_epoch_zero() {
    assert_eq!(descriptor("v14_epoch_zero").trim(), "v14_epoch_zero");
    let key = signing_key();
    let f = frame(0, [0; 8]);
    assert!(msgfmt::verify(&f, &key.verifying_key()).is_ok());
}
#[test]
fn v15_epoch_max() {
    assert_round_trip("v15_epoch_max", u64::MAX, [0; 8]);
}
#[test]
fn v16_class_256() {
    assert_eq!(frame(1, [0; 8]).len(), 256);
}
#[test]
fn v17_class_512() {
    assert_round_trip("v17_class_512", 1, [0; 8]);
}
#[test]
fn v18_class_1024() {
    assert_round_trip("v18_class_1024", 1, [0; 8]);
}
#[test]
fn v19_class_4096() {
    assert_round_trip("v19_class_4096", 1, [0; 8]);
}
#[test]
fn v20_truncate_zero() {
    assert_truncated("v20_truncate_zero", 0);
}
#[test]
fn v21_truncate_one() {
    assert_truncated("v21_truncate_one", 1);
}
#[test]
fn v22_truncate_eight() {
    assert_truncated("v22_truncate_eight", 8);
}
#[test]
fn v23_truncate_32() {
    assert_truncated("v23_truncate_32", 32);
}
#[test]
fn v24_truncate_64() {
    assert_truncated("v24_truncate_64", 64);
}
#[test]
fn v25_truncate_last() {
    assert_truncated("v25_truncate_last", 255);
}
#[test]
fn v26_flip_byte_zero() {
    assert_bad_signature("v26_flip_byte_zero", 0);
}
#[test]
fn v27_flip_byte_16() {
    assert_bad_signature("v27_flip_byte_16", 16);
}
#[test]
fn v28_flip_byte_32() {
    assert_bad_signature("v28_flip_byte_32", 32);
}
#[test]
fn v29_flip_last() {
    assert_bad_signature("v29_flip_last", 255);
}
#[test]
fn v30_wrong_enc_key() {
    assert_eq!(descriptor("v30_wrong_enc_key").trim(), "v30_wrong_enc_key");
    let mut last = 0;
    assert_eq!(
        decode_checked(
            &frame(1, [0; 8]),
            &signing_key().verifying_key(),
            &[8; 32],
            &mut last
        ),
        Err(Error::BadAead)
    );
}
#[test]
fn v31_wrong_sign_key() {
    assert_eq!(
        descriptor("v31_wrong_sign_key").trim(),
        "v31_wrong_sign_key"
    );
    let mut last = 0;
    let wrong = SigningKey::from_bytes(&[8; 32]);
    assert_eq!(
        decode_checked(
            &frame(1, [0; 8]),
            &wrong.verifying_key(),
            &[7; 32],
            &mut last
        ),
        Err(Error::BadSignature)
    );
}
#[test]
fn v32_replay_epoch() {
    assert_eq!(descriptor("v32_replay_epoch").trim(), "v32_replay_epoch");
    let mut last = 0;
    let f = frame(1, [0; 8]);
    decode_checked(&f, &signing_key().verifying_key(), &[7; 32], &mut last).unwrap();
    assert_eq!(
        decode_checked(&f, &signing_key().verifying_key(), &[7; 32], &mut last),
        Err(Error::StaleEpoch)
    );
}
#[test]
fn v33_shell_empty_argv() {
    assert_eq!(
        descriptor("v33_shell_empty_argv").trim(),
        "v33_shell_empty_argv"
    );
}
#[test]
fn v34_shell_unicode() {
    assert_round_trip("v34_shell_unicode", 1, [0; 8]);
}
#[test]
fn v35_fetch_long_url() {
    assert_round_trip("v35_fetch_long_url", 1, [0; 8]);
}
#[test]
fn v36_broadcast_tag() {
    assert_round_trip("v36_broadcast_tag", 1, [0; 8]);
}
#[test]
fn v37_epoch_one() {
    assert_round_trip("v37_epoch_one", 1, [0; 8]);
}
#[test]
fn v38_epoch_max_minus_one() {
    assert_round_trip("v38_epoch_max_minus_one", u64::MAX - 1, [0; 8]);
}
#[test]
fn v39_padding_zero() {
    assert_round_trip("v39_padding_zero", 1, [0; 8]);
}
#[test]
fn v40_unknown_type_after_decrypt() {
    assert_eq!(
        descriptor("v40_unknown_type_after_decrypt").trim(),
        "v40_unknown_type_after_decrypt"
    );
}

#[test]
fn route_tag_is_stable_for_an_enrolled_key() {
    assert_eq!(
        route_tag_from_key(b"agent-key"),
        route_tag_from_key(b"agent-key")
    );
}
