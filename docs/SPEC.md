# Agent-Fleet Wire-Format Specification

**Status:** Frozen by P02. This document defines the bytes that an independent implementation must emit and accept. The format is deliberately independent of transport, storage, and process supervision.

## 1. Frame overview

A frame is a fixed-size signed record. Its logical content is a canonical CBOR message encrypted with XChaCha20-Poly1305. The encrypted content is padded with zero bytes to one of the permitted size classes, and the complete record is authenticated by an Ed25519 signature.

The frame layout is, in order:

| Field | Size | Encoding | Description |
|---|---:|---|---|
| magic | 4 bytes | fixed bytes | `43 32 00 01` (`C2\0\1`) |
| version | 2 bytes | unsigned little-endian | Wire version `1` |
| msg_type | 1 byte | unsigned integer | Message type code |
| route_tag | 8 bytes | opaque bytes | Destination route; all zero means broadcast to all agents |
| epoch | 8 bytes | unsigned little-endian | Coordinator-assigned monotonic epoch for this route tag |
| nonce | 24 bytes | random bytes | XChaCha20-Poly1305 nonce generated with a CSPRNG |
| payload_len | 2 bytes | unsigned little-endian | Number of encrypted payload bytes, including the 16-byte AEAD tag, excluding padding |
| payload | variable | bytes | AEAD ciphertext followed by zero padding |
| signature | 64 bytes | Ed25519 | Signature over every preceding byte |

The fixed header from `magic` through `payload_len` is 49 bytes. The signature is the final 64 bytes. A frame's signed region is therefore the first `frame_size - 64` bytes, including header, ciphertext, and padding.

The `payload_len` field counts only the AEAD ciphertext and its authentication tag. It does not count zero padding. The encrypted plaintext is the canonical CBOR document. The AEAD ciphertext length is the plaintext length plus 16 bytes.

## 2. Message types

The one-byte `msg_type` field uses these values:

| Value | Name | Encrypted body |
|---:|---|---|
| 1 | heartbeat | Heartbeat body defined by the implementation phase that introduces it |
| 2 | task | A task body, as specified in Section 5 |
| 3 | result | A result body, as specified in Section 6 |
| 4 | rotate | Key-rotation body introduced by the transport phase |
| 5 | upgrade | Upgrade body introduced by the transport phase |

A receiver that encounters an unsupported message type must authenticate and decrypt the frame before returning `UnknownMsgType`. It must not dispatch or apply state from an unknown type.

## 3. Size classes and padding

Frames use exactly one of four size classes: 256, 512, 1024, or 4096 bytes. The sender selects the smallest class whose available signed-region capacity can contain the 49-byte header, the encrypted payload, and the zero padding. The signature is included in the selected class size.

For a selected frame size `S`, the encrypted payload length `L`, and the fixed overhead of 113 bytes (49-byte header plus 64-byte signature), the padding length is:

`S - 113 - L`

The padding length must be non-negative. The maximum accepted `payload_len` is 3967 bytes. A payload that does not fit in the 4096-byte class is rejected as `BadLength`.

Padding is outside the AEAD ciphertext and inside the signed region. Every padding byte must be exactly zero. A non-zero padding byte is `BadPadding`; it is not passed to the AEAD decryptor or CBOR decoder.

The class boundaries are based on the encrypted payload length, including the AEAD tag:

| Encrypted payload length | Frame size |
|---:|---:|
| 0 through 143 | 256 |
| 144 through 399 | 512 |
| 400 through 911 | 1024 |
| 912 through 3967 | 4096 |

A valid encrypted payload is at least 16 bytes because the AEAD tag is mandatory. Consequently, the first usable class boundary is determined by the first encrypted payload length that fits the corresponding record.

## 4. Cryptographic operations

Signing and encryption use separate keys. The encryption key is a 32-byte XChaCha20-Poly1305 key. The signing key is an Ed25519 private key, and the verifying key is the corresponding Ed25519 public key.

The AEAD associated data is exactly the 49-byte header from `magic` through `payload_len`, including the encoded `payload_len`. The nonce is exactly the 24-byte `nonce` field. The AEAD plaintext is the canonical CBOR body; the AEAD ciphertext and its 16-byte tag occupy exactly `payload_len` bytes.

The Ed25519 signing input is every byte from the first byte of `magic` through the final byte of padding. The signature field itself is excluded from the signing input. The signature is encoded as the 64-byte Ed25519 signature in its standard fixed-width representation.

The nonce must be freshly generated for every encoded frame using a cryptographically secure operating-system random source. A nonce is not derived from the route tag or epoch.

## 5. Task message bodies

A task is a CBOR map. Map keys are UTF-8 text strings. CBOR must use definite lengths, and map keys must be sorted by their canonical CBOR ordering. Unknown map keys are tolerated by decoders. Required keys and value types are:

| Task body | Required keys and types |
|---|---|
| Ping | No required keys; the map is `{}` |
| Shell | `argv`: array of text strings; `timeout_s`: unsigned integer fitting `u16`; `shell`: boolean |
| Fetch | `url`: text string; `dest`: text string |

The task envelope contains `route_tag`, `epoch`, and `body`. `route_tag` and `epoch` are frame fields and are not duplicated in the CBOR body.

An empty `argv` array is valid CBOR but is invalid for execution and must be rejected by the handler layer, not by the wire-format decoder. The wire-format decoder validates only the CBOR shape and declared value types.

## 6. Result message bodies

A result is a CBOR map with these required keys and types:

| Key | Type | Meaning |
|---|---|---|
| `task_epoch` | unsigned integer, `u64` | Epoch of the task being answered |
| `ok` | boolean | Whether task processing succeeded |
| `stdout` | text string | Captured standard output, possibly truncated by the handler |
| `stderr` | text string | Captured standard error, possibly truncated by the handler |
| `code` | signed integer, `i32` | Process or handler result code; timeout uses `-1` |

Unknown map keys are tolerated. The decoder rejects a missing required key or a value with the wrong CBOR type as `BadCbor`.

## 7. Epochs and duplicate suppression

Epochs are unsigned 64-bit values encoded little-endian in the frame. The coordinator assigns epochs monotonically for each `route_tag`; an epoch never resets for a route tag. The all-zero route tag is one route tag for epoch and duplicate-suppression purposes.

Each receiver persists a duplicate-suppression window of 64 epochs per route tag. A frame is stale when its epoch is at or below the stored suppression boundary, or when it is otherwise outside the accepted 64-epoch window. A stale frame returns `StaleEpoch` and does not dispatch.

The receiver must update its persisted epoch state only after signature verification, epoch validation, AEAD decryption, CBOR decoding, and message-type dispatch validation have all succeeded. Failure at any step leaves the previous state unchanged.

## 8. Mandatory receive order

The following order is mandatory and is part of the protocol:

1. Validate the frame length and selected size class.
2. Validate `magic` and `version`.
3. Validate the Ed25519 signature over the complete signed region.
4. Validate epoch freshness and duplicate suppression.
5. Validate padding and decrypt the AEAD payload using the header as AAD.
6. Decode and validate canonical, definite-length CBOR.
7. Dispatch the authenticated message type and body.

A receiver must not decrypt before signature verification. It must not dispatch a message or mutate epoch state after any failed step.

The named error conditions are:

| Error | Condition |
|---|---|
| `Truncated` | Input ends before a required field or complete frame is available |
| `BadLength` | Length, class, `payload_len`, or maximum-size rule is invalid |
| `BadMagic` | The first four bytes are not `43 32 00 01` |
| `BadVersion` | The version is not `1` |
| `BadSignature` | Ed25519 verification fails |
| `StaleEpoch` | The epoch is rejected by the persisted suppression window |
| `BadPadding` | A byte outside the ciphertext and before the signature is non-zero padding where zero is required |
| `BadAead` | XChaCha20-Poly1305 authentication or decryption fails |
| `BadCbor` | The plaintext is not accepted canonical CBOR or has an invalid body shape |
| `UnknownMsgType` | The authenticated message type is not supported by this implementation |

## 9. Canonical encoding requirements

CBOR documents must use definite-length arrays and maps. Map keys must be sorted by canonical CBOR ordering. Integers must use the shortest valid representation. Text strings must be valid UTF-8. No indefinite-length item, floating-point value, duplicate key, or trailing plaintext item is permitted.

Unknown map keys may be retained or ignored by an implementation, but they must not change the interpretation of known keys. An implementation must never accept a second occurrence of a required key with a conflicting value.

## 10. Interoperability examples

An encoder constructing a Ping frame with a route tag and epoch must first encode the empty CBOR map, encrypt it with the selected nonce and the 49-byte header as AAD, set `payload_len` to the resulting ciphertext length, select the smallest frame class, append zero padding, and sign the entire record before appending the signature.

A decoder receiving that record must perform the mandatory receive order in Section 8. A second successful decode of the same route tag and epoch is rejected as `StaleEpoch`; it is not treated as a second Ping.

## 11. Route-tag derivation

At enrolment, the coordinator derives the agent's route tag as the first eight bytes of BLAKE3 over the enrolled agent key bytes. The derived eight-byte value is pinned to the enrolment record and is not recomputed or changed during key rotation. The all-zero tag remains reserved for broadcast and must not be assigned as a derived tag.

## 12. Ambiguity closure

This specification has no unresolved protocol ambiguities. In particular, `payload_len` counts ciphertext plus the AEAD tag but excludes padding; padding is signed but not encrypted; the signature covers the header, ciphertext, and padding; the header is the AEAD associated data; message-type dispatch occurs only after decryption and CBOR validation; and all epoch state changes occur only after successful validation.
