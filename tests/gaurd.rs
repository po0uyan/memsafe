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
