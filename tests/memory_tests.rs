use memsafe::MemSafe;

/// Test suite for MemSafe functionality
/// These tests verify the core functionality of the MemSafe wrapper
#[cfg(test)]
mod memory_safety_tests {
    use super::*;

    #[test]
    fn test_empty_string_handling() {
        let empty_safe = MemSafe::new(String::new()).unwrap();
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
        let mut safe_string = MemSafe::new(String::from("Hello")).unwrap();
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
        let original = MemSafe::new(String::from("original_data")).unwrap();
        let cloned = original.clone();
        
        assert_eq!(original.as_str(), cloned.as_str());
        assert_eq!(original.len(), cloned.len());
        
        // Ensure they are separate instances
        drop(original);
        assert_eq!(cloned.as_str(), "original_data");
    }

    #[test]
    fn test_mem_safe_string() {
        let mut secret = MemSafe::new(String::from("secret")).unwrap();
        assert_eq!(secret.as_str(), "secret");
        secret.push_str(" data");
        assert_eq!(secret.as_str(), "secret data");
    }
}