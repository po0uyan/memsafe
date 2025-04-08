use error::MemoryError;

mod cell;
pub mod error;
mod ffi;
mod mem_safe;
mod ptr_ops;
pub mod type_state;

pub use mem_safe::{MemSafe, MemSafeRead, MemSafeWrite};
