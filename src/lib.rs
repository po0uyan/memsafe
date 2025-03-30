use error::MemoryError;

mod cell;
pub mod error;
mod ffi;
mod gaurd;
mod ptr_ops;
pub mod type_state;

pub use gaurd::{MemSafe, MemSafeRead, MemSafeWrite};
