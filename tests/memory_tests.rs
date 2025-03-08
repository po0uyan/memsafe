use memsafe::MemSafe;

/// Test suite for MemSafe functionality
/// These tests verify the core functionality of the MemSafe wrapper
#[cfg(test)]
mod memory_safety_tests {
    use std::{
        io::{Cursor, Read, Write},
        sync::Arc,
    };

    use super::*;

    #[allow(unused_variables)]
    #[test]
    fn test_str_new_drop() {
        let safe_str = MemSafe::new(0).unwrap();
    }

    #[allow(unused_variables)]
    #[test]
    fn test_str_new_readonly_drop() {
        let safe_str = MemSafe::new(0).unwrap().read_only().unwrap();
    }

    #[allow(unused_variables)]
    #[test]
    fn test_str_new_readwrite_drop() {
        let safe_str = MemSafe::new(0).unwrap().read_write().unwrap();
    }

    #[allow(unused_variables)]
    #[test]
    fn test_str_new_readonly_readwrite_drop() {
        let safe_str = MemSafe::new(0)
            .unwrap()
            .read_only()
            .unwrap()
            .read_write()
            .unwrap();
    }

    #[test]
    fn test_empty_u8_array_read() {
        let empty_safe = MemSafe::new([0_u8, 1_u8, 2_u8, 3_u8])
            .unwrap()
            .read_only()
            .unwrap();
        assert_eq!(empty_safe[0], 0);
        assert_eq!(empty_safe[1], 1);
        assert_eq!(empty_safe[2], 2);
        assert_eq!(empty_safe[3], 3);
        assert_eq!(empty_safe.len(), 4);
    }

    #[test]
    fn test_empty_u8_array_read_and_write() {
        let mut empty_safe = MemSafe::new([0_u8, 1_u8, 2_u8, 3_u8])
            .unwrap()
            .read_write()
            .unwrap();
        assert_eq!(empty_safe[0], 0);
        assert_eq!(empty_safe[1], 1);
        assert_eq!(empty_safe[2], 2);
        assert_eq!(empty_safe[3], 3);
        empty_safe[0] = 1;
        empty_safe[1] = 2;
        empty_safe[2] = 3;
        empty_safe[3] = 4;
        assert_eq!(empty_safe[0], 1);
        assert_eq!(empty_safe[1], 2);
        assert_eq!(empty_safe[2], 3);
        assert_eq!(empty_safe[3], 4);
        assert_eq!(empty_safe.len(), 4);
    }

    #[test]
    fn test_empty_string_handling() {
        let empty_safe = MemSafe::new(String::new()).unwrap().read_only().unwrap();
        assert_eq!(empty_safe.as_str(), "");
        assert_eq!(empty_safe.len(), 0);
        assert!(empty_safe.is_empty());
    }

    #[test]
    fn test_memory_clearing() {
        let sensitive_data = String::from("sensitive_password_123");
        let length = sensitive_data.len();
        {
            let _safe_data = MemSafe::new(sensitive_data.clone()).unwrap();
            // Data is still accessible here
        }
        // After drop, original string should remain untouched
        assert_eq!(sensitive_data.len(), length);
    }

    #[test]
    fn test_string_operations() {
        let mut safe_string = MemSafe::new(String::from("Hello"))
            .unwrap()
            .read_write()
            .unwrap();
        safe_string.push_str(", ");
        safe_string.push_str("World!");
        assert_eq!(safe_string.as_str(), "Hello, World!");

        // Test truncate
        safe_string.truncate(5);
        assert_eq!(safe_string.as_str(), "Hello");

        // Test clear
        safe_string.clear();
        assert!(safe_string.is_empty());
    }

    #[test]
    fn test_clone_behavior() {
        let original = MemSafe::new(String::from("original_data"))
            .unwrap()
            .read_only()
            .unwrap();
        let cloned = original.clone();

        assert_eq!(original.as_str(), cloned.as_str());
        assert_eq!(original.len(), cloned.len());

        // Ensure they are separate instances
        drop(original);
        assert_eq!(cloned.as_str(), "original_data");
    }

    #[test]
    fn test_mem_safe_string() {
        let mut secret = MemSafe::new(String::from("secret"))
            .unwrap()
            .read_write()
            .unwrap();
        assert_eq!(secret.as_str(), "secret");
        secret.push_str(" data");
        assert_eq!(secret.as_str(), "secret data");
    }

    #[test]
    fn test_read_compatibility() {
        const STR: &str = "this is a secret";
        let mut cur = Cursor::new(Vec::new());
        assert_eq!(STR.len(), cur.write(STR.as_bytes()).unwrap());
        cur.set_position(0);
        let mut mem_safe = MemSafe::new([0_u8; 32]).unwrap().read_write().unwrap();
        assert_eq!(STR.len(), cur.read(&mut *mem_safe).unwrap());
        STR.as_bytes()
            .iter()
            .enumerate()
            .for_each(|(idx, b1)| assert_eq!(b1, &mem_safe[idx]));
    }

    #[test]
    fn test_string_append_and_print() {
        let mut secret = MemSafe::new(String::from("secret"))
            .unwrap()
            .read_write()
            .unwrap();

        secret.push_str(" data");

        assert_eq!(*secret, "secret data");

        let output = format!("Secure data: {}", *secret);
        assert_eq!(output, "Secure data: secret data");

        let length = secret.len();
        assert_eq!(length, 11);
        assert_eq!(*secret, "secret data");
    }

    #[test]
    fn test_sync() {
        const LEN: usize = 1024;
        let mem_safe = MemSafe::new([0; LEN]).unwrap();
        evalute_sync(&mem_safe);
        let mut ms = mem_safe.read_write().unwrap();
        for i in 0..LEN {
            ms[i] = i;
        }
        // Sharing mem_safe between 1024 threads...
        let mem_safe = Arc::new(ms.read_only().unwrap());
        let _ = (0..1024)
            .map(|_| {
                let ms = mem_safe.clone();
                std::thread::spawn(move || {
                    for i in 0..LEN {
                        assert_eq!(ms[i], i);
                    }
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|hndl| hndl.join());
    }

    #[test]
    fn test_send() {
        const LEN: usize = 1024;
        let mut ms = MemSafe::new([0; LEN]).unwrap().read_write().unwrap();
        evalute_send(&ms);
        for i in 0..LEN {
            ms[i] = i;
        }
        let ms = ms.read_only().unwrap();

        // Sending mem_safe to another thread to duplicate all elements
        let hndl = std::thread::spawn(move || {
            let mut ms = ms.read_write().unwrap();
            for i in 0..LEN {
                ms[i] *= 2;
            }
            ms.read_only().unwrap()
        });
        let mem_safe = hndl.join().unwrap();
        for i in 0..LEN {
            assert_eq!(mem_safe[i], i * 2);
        }
    }

    fn evalute_sync<T: Sync>(_: &T) {}
    fn evalute_send<T: Send>(_: &T) {}
}
