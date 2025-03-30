// src/lib.rs

use error::MemoryError;

mod cell;
pub mod error;
mod ffi;
pub mod gaurd;
mod ptr_ops;
pub mod type_state;

// use std::marker::PhantomData;
// use std::ops::{Deref, DerefMut};

// #[cfg(target_os = "linux")]
// use ffi::mem_no_dump;
// #[cfg(unix)]
// use ffi::mem_noaccess;
// use ffi::{mem_alloc, mem_dealloc, mem_lock, mem_readonly, mem_readwrite, mem_unlock};
// use ptr_ops::{ptr_deref, ptr_deref_mut, ptr_drop_in_place, ptr_fill_zero, ptr_write};
