#[cfg(test)]
mod tests {
    #[test]
    fn test_gaurd() {
        let mut mem_safe = memsafe::MemSafe::new([0_u8; 16]).unwrap();
        {
            let mut writer = mem_safe.write().unwrap();
            for i in 0..16 {
                writer[i] = i as u8;
            }
        }
        {
            let reader = mem_safe.read().unwrap();
            for i in 0..16 {
                assert_eq!(reader[i], i as u8);
            }
        }
    }

    #[test]
    fn test_thread_write_main_read() {
        let mut mem_safe = memsafe::MemSafe::new([0_u8; 1024]).unwrap();

        // Create a thread to read the data
        let handle = std::thread::spawn(move || {
            {
                let mut writer = mem_safe.write().unwrap();
                for i in 0..1024 {
                    writer[i] = i as u8;
                }
            }
            mem_safe // Return ownership back to the main thread
        });

        // Wait for the thread to complete and get back ownership
        let mut mem_safe = handle.join().unwrap();

        // Verify we can still use it in the main thread
        {
            let reader = mem_safe.read().unwrap();
            for i in 0..1024 {
                assert_eq!(reader[i], i as u8);
            }
        }
    }

    #[test]
    fn test_main_write_thread_read() {
        let mut mem_safe = memsafe::MemSafe::new([0_u8; 1024]).unwrap();

        // Write data in the main thread
        {
            let mut writer = mem_safe.write().unwrap();
            for i in 0..1024 {
                writer[i] = i as u8;
            }
        }

        // Create a thread to read the data
        let handle = std::thread::spawn(move || {
            {
                let reader = mem_safe.read().unwrap();
                for i in 0..1024 {
                    assert_eq!(reader[i], i as u8);
                }
            }
            mem_safe // Return ownership back to the main thread
        });

        // Wait for the thread to complete and get back ownership
        let _ = handle.join().unwrap();
    }
}

#[cfg(test)]
mod write_guard_tests {
    #[test]
    fn write_guard_supports_read_back_through_deref() {
        // MemSafeWrite implements Deref as well as DerefMut: values written
        // through the guard must be readable through the same guard.
        let mut mem_safe = memsafe::MemSafe::new([0_u8; 16]).unwrap();
        let mut writer = mem_safe.write().unwrap();
        writer[3] = 42;
        assert_eq!(writer[3], 42);
    }
}

#[cfg(test)]
mod drop_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// `MemSafe<T>` must run `T`'s destructor exactly once: never skipping
    /// it (the value's own resources leak) and never twice (use after free).
    #[test]
    fn drop_runs_the_value_destructor_exactly_once() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Counted(#[allow(dead_code)] u8);
        impl Drop for Counted {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mem_safe = memsafe::MemSafe::new(Counted(7)).unwrap();
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            0,
            "moving the value in must not drop it"
        );
        drop(mem_safe);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }
}
