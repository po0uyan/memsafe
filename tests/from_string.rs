//! Tests for the `FromStr` / `from_string` constructors and `TryFrom<&str>` /
//! `TryFrom<String>` implementations on the default `MemSafe<[u8; N]>` API.
//!
//! These tests cover observable behavior. Internal heap zeroization of the
//! source `String` consumed by `from_string` is a security invariant verified
//! by code review — observing freed memory through a raw pointer after
//! `String::drop` is undefined behavior and not a reliable test.

#[cfg(test)]
mod tests {
    use memsafe::MemSafe;
    use std::str::FromStr;

    const SECRET: &str = "my-api-key-1234";

    #[test]
    fn from_str_stores_bytes_in_protected_memory() {
        let mut secret = MemSafe::<[u8; 64]>::from_str(SECRET).unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn from_str_zero_fills_remaining_bytes() {
        let mut secret = MemSafe::<[u8; 32]>::from_str(SECRET).unwrap();
        let reader = secret.read().unwrap();
        for &byte in &reader[SECRET.len()..] {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn from_str_exact_fit() {
        let mut secret = MemSafe::<[u8; 15]>::from_str(SECRET).unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..], SECRET.as_bytes());
    }

    #[test]
    fn from_str_empty_input() {
        let mut secret = MemSafe::<[u8; 16]>::from_str("").unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..], &[0u8; 16]);
    }

    #[test]
    fn from_str_too_long_returns_error() {
        let result = MemSafe::<[u8; 4]>::from_str(SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn from_str_supports_unicode() {
        let unicode_secret = "héllo-🔒-secret";
        let mut secret = MemSafe::<[u8; 64]>::from_str(unicode_secret).unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..unicode_secret.len()], unicode_secret.as_bytes());
    }

    #[test]
    fn parse_works_via_fromstr() {
        let mut secret: MemSafe<[u8; 32]> = SECRET.parse().unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn from_string_stores_bytes_in_protected_memory() {
        let owned = String::from(SECRET);
        let mut secret = MemSafe::<[u8; 64]>::from_string(owned).unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn from_string_too_long_returns_error() {
        let owned = String::from(SECRET);
        let result = MemSafe::<[u8; 4]>::from_string(owned);
        assert!(result.is_err());
    }

    #[test]
    fn from_string_empty_input() {
        let mut secret = MemSafe::<[u8; 16]>::from_string(String::new()).unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..], &[0u8; 16]);
    }

    #[test]
    fn try_from_str_works() {
        let mut secret: MemSafe<[u8; 32]> = SECRET.try_into().unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn try_from_string_works() {
        let owned = String::from(SECRET);
        let mut secret: MemSafe<[u8; 32]> = owned.try_into().unwrap();
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn try_from_str_too_long_errors() {
        let result: Result<MemSafe<[u8; 4]>, _> = SECRET.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn write_after_from_str_overwrites_buffer() {
        let mut secret = MemSafe::<[u8; 16]>::from_str("initial").unwrap();
        {
            let mut writer = secret.write().unwrap();
            writer[..7].copy_from_slice(b"updated");
        }
        let reader = secret.read().unwrap();
        assert_eq!(&reader[..7], b"updated");
    }
}