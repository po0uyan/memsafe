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

#[test]
fn new_with_panic_in_init_unwinds_cleanly() {
    // If `init` panics partway through writing the secret, unwinding
    // runs the construction guard's `Drop`: the page is volatile-zeroed,
    // unlocked, and unmapped before the panic propagates. Externally,
    // the panic surfaces unchanged and no partially-built `Secret`
    // reaches the caller.
    let result = std::panic::catch_unwind(|| {
        Secret::<32>::new_with(|buf| {
            buf[..3].copy_from_slice(b"abc");
            panic!("simulated init failure");
        })
    });
    assert!(result.is_err(), "panic should propagate to the caller");
}

#[test]
fn read_guard_can_be_taken_repeatedly() {
    // Each read elevates the page and reseals it on guard drop; the cycle
    // must be repeatable indefinitely with stable contents.
    let mut secret = Secret::<16>::new_with(|buf| {
        buf[..6].copy_from_slice(b"stable");
    })
    .unwrap();
    for _ in 0..100 {
        let view = secret.read().unwrap();
        assert_eq!(&view[..6], b"stable");
    }
}

#[test]
fn interleaved_write_and_read_cycles_persist() {
    // Alternating write/read guards must observe every previous mutation:
    // the reseal-elevate cycle may not lose or corrupt page contents.
    let mut secret = Secret::<8>::new_with(|_| {}).unwrap();
    for round in 0u8..50 {
        {
            let mut w = secret.write().unwrap();
            w[0] = round;
            // Reading back through the *write* guard must also work.
            assert_eq!(w[0], round);
        }
        let r = secret.read().unwrap();
        assert_eq!(r[0], round);
    }
}

#[test]
fn secrets_are_independent() {
    // Two secrets must live on distinct pages: mutating one may not affect
    // the other.
    let mut a = Secret::<16>::new_with(|b| b.fill(0xAA)).unwrap();
    let mut b = Secret::<16>::new_with(|b| b.fill(0xBB)).unwrap();
    {
        let mut w = a.write().unwrap();
        w.fill(0x11);
    }
    assert_eq!(b.read().unwrap()[0], 0xBB);
    assert_eq!(a.read().unwrap()[0], 0x11);
}

#[test]
fn secret_is_send_across_threads() {
    // A secret created on one thread must be movable to another and remain
    // readable there (the page belongs to the process, not the thread).
    let mut secret = Secret::<16>::new_with(|buf| {
        buf[..5].copy_from_slice(b"moved");
    })
    .unwrap();

    let handle = std::thread::spawn(move || {
        {
            let view = secret.read().unwrap();
            assert_eq!(&view[..5], b"moved");
        }
        secret
    });
    let mut secret = handle.join().unwrap();
    assert_eq!(&secret.read().unwrap()[..5], b"moved");
}

#[test]
fn drop_after_use_does_not_panic() {
    // Drop re-elevates, wipes, unlocks, and unmaps; it must succeed from
    // every reachable guard state.
    let mut secret = Secret::<32>::new_with(|b| b.fill(0x5A)).unwrap();
    let _ = secret.read().unwrap();
    let _ = secret.write().unwrap();
    drop(secret);

    // And from the never-accessed state.
    let untouched = Secret::<32>::new_with(|_| {}).unwrap();
    drop(untouched);
}

#[test]
fn try_from_str_leaves_borrowed_source_intact() {
    // Documented contract: a borrowed &str cannot be zeroized by the crate;
    // the caller keeps full ownership of the source.
    let source = String::from("my-api-key");
    let _secret: Secret<32> = source.as_str().try_into().unwrap();
    assert_eq!(source, "my-api-key");
}

#[test]
fn try_from_str_exact_fit_and_empty() {
    let mut exact: Secret<10> = "my-api-key".try_into().unwrap();
    assert_eq!(&exact.read().unwrap()[..], b"my-api-key");

    let mut empty: Secret<8> = "".try_into().unwrap();
    assert_eq!(&empty.read().unwrap()[..], &[0u8; 8]);
}

#[test]
fn try_from_string_error_preserves_unicode_exactly() {
    // The returned String must be byte-for-byte the original, including
    // multi-byte UTF-8 content.
    let s = String::from("héllo-🔒-way-too-long-for-four-bytes");
    let result: Result<Secret<4>, _> = s.clone().try_into();
    let (returned, _err) = match result {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(returned, s);
}

#[test]
fn error_kind_is_invalid_input_on_length_mismatch() {
    let result: Result<Secret<4>, _> = "too-long-for-buffer".try_into();
    let err = result.err().expect("expected length-mismatch error");
    assert_eq!(err.inner().kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn memory_error_source_chain_exposes_inner_io_error() {
    use std::error::Error;

    // Force a length-mismatch error so we can walk the chain.
    let result: Result<Secret<4>, _> = Secret::<4>::from_bytes(b"too-long".to_vec());
    let (_returned, err) = match result {
        Ok(_) => panic!("expected length-mismatch error"),
        Err(e) => e,
    };

    // `Error::source()` must expose the inner `io::Error` so structured
    // error reporters (anyhow, eyre, ...) can drill into the root cause
    // without parsing the `Display` text.
    let source = err.source().expect("MemoryError must expose a source");
    let io_err = source
        .downcast_ref::<std::io::Error>()
        .expect("source should downcast to io::Error");
    assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
}
