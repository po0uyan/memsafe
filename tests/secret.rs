//! Tests for the `Secret<N>` newtype — the only public secret-handling API.
//!
//! `Secret::new_with` is the in-place initialization primitive: the protected
//! page is allocated, locked, and OS-zeroed before the closure runs, and the
//! closure writes secret bytes directly through `&mut [u8; N]` into protected
//! memory. These tests confirm that what the closure writes is what we get
//! back, that the trailing region is OS-zeroed, and that the source-returning
//! error contract holds.

use memsafe::Secret;

#[test]
fn new_with_writes_full_buffer() {
    let mut secret = Secret::<32>::new_with(|buf| {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
    })
    .unwrap();
    let view = secret.read().unwrap();
    for i in 0..32 {
        assert_eq!(view[i], i as u8);
    }
}

#[test]
fn new_with_partial_write_leaves_trailing_bytes_zero() {
    let mut secret = Secret::<64>::new_with(|buf| {
        buf[..5].copy_from_slice(b"hello");
    })
    .unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..5], b"hello");
    for &byte in &view[5..] {
        assert_eq!(byte, 0);
    }
}

#[test]
fn new_with_no_writes_yields_zero_buffer() {
    let mut secret = Secret::<16>::new_with(|_| {}).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..], &[0u8; 16]);
}

#[test]
fn from_bytes_stores_payload() {
    let raw = b"my-api-key".to_vec();
    let mut secret = Secret::<32>::from_bytes(raw).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..10], b"my-api-key");
}

#[test]
fn from_bytes_zero_fills_remaining_buffer() {
    let raw = b"my-api-key".to_vec();
    let mut secret = Secret::<32>::from_bytes(raw).unwrap();
    let view = secret.read().unwrap();
    for &byte in &view[10..] {
        assert_eq!(byte, 0);
    }
}

#[test]
fn from_bytes_exact_fit() {
    let raw = b"my-api-key-1234".to_vec();
    let mut secret = Secret::<15>::from_bytes(raw).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..], b"my-api-key-1234");
}

#[test]
fn from_bytes_empty_input() {
    let mut secret = Secret::<16>::from_bytes(Vec::<u8>::new()).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..], &[0u8; 16]);
}

#[test]
fn from_bytes_too_long_returns_source_untouched() {
    let raw = b"way-too-long-secret".to_vec();
    let result = Secret::<4>::from_bytes(raw);
    let (returned, _err) = match result {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(returned, b"way-too-long-secret");
}

#[test]
fn from_bytes_works_with_box_slice() {
    let boxed: Box<[u8]> = b"my-api-key".to_vec().into_boxed_slice();
    let mut secret = Secret::<32>::from_bytes(boxed).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..10], b"my-api-key");
}

#[test]
fn from_bytes_works_with_array() {
    let arr: [u8; 10] = *b"my-api-key";
    let mut secret = Secret::<32>::from_bytes(arr).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..10], b"my-api-key");
}

#[test]
fn try_from_str_works() {
    let mut secret: Secret<32> = "my-api-key".try_into().unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..10], b"my-api-key");
}

#[test]
fn try_from_str_too_long_errors() {
    let result: Result<Secret<4>, _> = "my-api-key".try_into();
    assert!(result.is_err());
}

#[test]
fn try_from_string_works() {
    let s = String::from("my-api-key");
    let mut secret: Secret<32> = s.try_into().unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..10], b"my-api-key");
}

#[test]
fn try_from_string_too_long_returns_string_untouched() {
    let s = String::from("way-too-long-secret");
    let result: Result<Secret<4>, _> = s.try_into();
    let (returned, _err) = match result {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(returned, "way-too-long-secret");
}

#[test]
fn write_then_read_round_trip() {
    let mut secret = Secret::<16>::new_with(|buf| {
        buf[..7].copy_from_slice(b"initial");
    })
    .unwrap();
    {
        let mut writer = secret.write().unwrap();
        writer[..7].copy_from_slice(b"updated");
    }
    let view = secret.read().unwrap();
    assert_eq!(&view[..7], b"updated");
}

#[test]
fn from_bytes_supports_unicode() {
    let unicode_secret = "héllo-🔒-secret";
    let raw = unicode_secret.as_bytes().to_vec();
    let mut secret = Secret::<64>::from_bytes(raw).unwrap();
    let view = secret.read().unwrap();
    assert_eq!(&view[..unicode_secret.len()], unicode_secret.as_bytes());
}

#[test]
fn new_with_pattern_simulating_stream_read() {
    // Beginner pattern: read straight from a Read source into protected memory.
    // No String, no Vec, no stack temporary ever holds the secret.
    use std::io::Read;
    let source: &[u8] = b"streamed-secret";
    let mut cursor = std::io::Cursor::new(source);

    let mut secret = Secret::<64>::new_with(|buf| {
        let _ = cursor.read(&mut buf[..]).unwrap();
    })
    .unwrap();

    let view = secret.read().unwrap();
    assert_eq!(&view[..source.len()], source);
}
