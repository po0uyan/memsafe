#[cfg(test)]
mod tests {
    #[test]
    fn test_gaurd() {
        let mut mem_safe = memsafe::MemSafe::new([0_u8; 16]).unwrap();
        evalute_send(&mem_safe);
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

    fn evalute_send<T: Send>(_: &T) {}
}
