#[cfg(test)]
mod tests {

    #[test]
    fn test_readme_example() {
        use memsafe::type_state::MemSafe;
        // initialize in an buffer in no access state
        let secret = MemSafe::new([0_u8; 32]).unwrap();

        // make array read-write and write into it
        let info = "my-scret-info";
        let mut secret = secret.read_write().unwrap();
        secret[..info.len()].copy_from_slice(info.as_bytes());

        // make array read only read from it
        let secret = secret.read_only().unwrap();
        println!("Secure data: {:02X?}", *secret);
    }
}
