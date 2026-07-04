use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub struct MemoryError(std::io::Error);

impl From<std::io::Error> for MemoryError {
    fn from(err: std::io::Error) -> Self {
        MemoryError(err)
    }
}

impl MemoryError {
    pub fn inner(&self) -> &std::io::Error {
        &self.0
    }
}

impl Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Memory error: {}", self.0)
    }
}

impl Error for MemoryError {
    /// Expose the underlying `io::Error` to error-chain walkers (`anyhow`,
    /// `eyre`, `thiserror::Error::source`-aware reporters, etc.) so they
    /// can drill into the root cause without parsing the `Display` text.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_inner_error_message() {
        let err = MemoryError::from(std::io::Error::other("boom"));
        let rendered = format!("{err}");
        assert!(rendered.starts_with("Memory error:"));
        assert!(rendered.contains("boom"));
    }

    #[test]
    fn inner_exposes_io_error() {
        let err = MemoryError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bad input",
        ));
        assert_eq!(err.inner().kind(), std::io::ErrorKind::InvalidInput);
    }
}
