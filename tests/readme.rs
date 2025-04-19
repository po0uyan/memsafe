#[cfg(test)]
mod tests {

    #[test]
    fn test_readme_example() {
        use memsafe::MemSafe;

        // allocate protected memory
        let mut secret = MemSafe::new([0_u8; 32]).unwrap();

        // write into protected memory
        {
            let mut write = secret.write().unwrap();
            write[..14].copy_from_slice("my-secret-info".as_bytes());
        }

        // read from protected memory
        {
            let read = secret.read().unwrap();
            println!("Secure data: {:02X?}", *read);
        }
    }
}
