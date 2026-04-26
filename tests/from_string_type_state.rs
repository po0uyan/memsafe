//! Tests for the `FromStr` / `from_string` constructors and `TryFrom<&str>` /
//! `TryFrom<String>` implementations on the type-state
//! `MemSafe<[u8; N], _>` API.

#![cfg(feature = "type-state")]

#[cfg(test)]
mod tests {
    use memsafe::type_state::MemSafe;
    use std::str::FromStr;

    const SECRET: &str = "my-api-key-1234";

    #[test]
    fn from_str_then_read_only() {
        let secret = MemSafe::<[u8; 64]>::from_str(SECRET)
            .unwrap()
            .read_only()
            .unwrap();
        assert_eq!(&secret[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn from_str_zero_fills_remaining_bytes() {
        let secret = MemSafe::<[u8; 32]>::from_str(SECRET)
            .unwrap()
            .read_only()
            .unwrap();
        for &byte in &secret[SECRET.len()..] {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn from_str_exact_fit() {
        let secret = MemSafe::<[u8; 15]>::from_str(SECRET)
            .unwrap()
            .read_only()
            .unwrap();
        assert_eq!(&secret[..], SECRET.as_bytes());
    }

    #[test]
    fn from_str_empty_input() {
        let secret = MemSafe::<[u8; 16]>::from_str("")
            .unwrap()
            .read_only()
            .unwrap();
        assert_eq!(&secret[..], &[0u8; 16]);
    }

    #[test]
    fn from_str_too_long_returns_error() {
        let result = MemSafe::<[u8; 4]>::from_str(SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn parse_works_via_fromstr() {
        let secret: MemSafe<[u8; 32]> = SECRET.parse().unwrap();
        let secret = secret.read_only().unwrap();
        assert_eq!(&secret[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn from_string_stores_bytes_in_protected_memory() {
        let owned = String::from(SECRET);
        let secret = MemSafe::<[u8; 64]>::from_string(owned)
            .unwrap()
            .read_only()
            .unwrap();
        assert_eq!(&secret[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn from_string_too_long_returns_error() {
        let owned = String::from(SECRET);
        let result = MemSafe::<[u8; 4]>::from_string(owned);
        assert!(result.is_err());
    }

    #[test]
    fn try_from_str_works() {
        let secret: MemSafe<[u8; 32]> = SECRET.try_into().unwrap();
        let secret = secret.read_only().unwrap();
        assert_eq!(&secret[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn try_from_string_works() {
        let owned = String::from(SECRET);
        let secret: MemSafe<[u8; 32]> = owned.try_into().unwrap();
        let secret = secret.read_only().unwrap();
        assert_eq!(&secret[..SECRET.len()], SECRET.as_bytes());
    }

    #[test]
    fn write_after_from_str_overwrites_buffer() {
        let mut secret = MemSafe::<[u8; 16]>::from_str("initial")
            .unwrap()
            .read_write()
            .unwrap();
        secret[..7].copy_from_slice(b"updated");
        let secret = secret.read_only().unwrap();
        assert_eq!(&secret[..7], b"updated");
    }
}