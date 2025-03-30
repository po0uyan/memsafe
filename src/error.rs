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

impl Error for MemoryError {}
