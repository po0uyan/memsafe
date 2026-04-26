use std::{
    convert::Infallible,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use crate::{cell::Cell, ptr_ops::zeroize_string_heap, MemoryError};

/// Represents a memory state with no access permissions.
#[cfg(unix)]
pub struct NoAccess;

/// Represents a memory state with read-only permissions.
pub struct ReadOnly;

/// Represents a memory state with read-write permissions.
pub struct ReadWrite;

/// A memory-safe wrapper around raw pointers that ensures proper memory management.
///
/// The memory can have different states:
/// - `NoAccess`: Memory cannot be read or written (Unix only).
/// - `ReadOnly`: Memory is read-only.
/// - `ReadWrite`: Memory is readable and writable.
///
/// The transitions between states ensure security and prevent unintended modifications.
#[cfg(unix)]
pub struct MemSafe<T, State = NoAccess> {
    cell: Cell<T>,
    _state: PhantomData<State>,
}

/// A memory-safe wrapper around raw pointers that ensures proper memory management.
///
/// The memory can have different states:
/// - `NoAccess`: Memory cannot be read or written (Unix only).
/// - `ReadOnly`: Memory is read-only.
/// - `ReadWrite`: Memory is readable and writable.
///
/// The transitions between states ensure security and prevent unintended modifications.
#[cfg(windows)]
pub struct MemSafe<T, State = ReadOnly> {
    cell: Cell<T>,
    _state: PhantomData<State>,
}

#[cfg(unix)]
unsafe impl<T> Sync for MemSafe<T, NoAccess> where T: Sync {}
unsafe impl<T> Sync for MemSafe<T, ReadOnly> where T: Sync {}
#[cfg(unix)]
unsafe impl<T> Send for MemSafe<T, NoAccess> where T: Send {}
unsafe impl<T> Send for MemSafe<T, ReadOnly> where T: Send {}
unsafe impl<T> Send for MemSafe<T, ReadWrite> where T: Send {}

#[cfg(unix)]
impl<T> MemSafe<T, NoAccess> {
    /// Allocates a new instance of `T` in locked memory with no access permissions.
    pub fn new(value: T) -> Result<Self, MemoryError> {
        Ok(MemSafe {
            cell: Cell::new(value)?,
            _state: Default::default(),
        })
    }

    /// Does nothing and return the object itself.
    pub fn no_access(self) -> Result<Self, Infallible> {
        Ok(self)
    }

    // Changes the memory state from `NoAccess` to `ReadOnly`.
    pub fn read_only(mut self) -> Result<MemSafe<T, ReadOnly>, MemoryError> {
        self.cell.read_only()?;
        let new_self = MemSafe {
            cell: self.cell,
            _state: Default::default(),
        };
        Ok(new_self)
    }

    /// Changes the memory state from `NoAccess` to `ReadWrite`.
    pub fn read_write(mut self) -> Result<MemSafe<T, ReadWrite>, MemoryError> {
        self.cell.read_write()?;
        let new_self = MemSafe {
            cell: self.cell,
            _state: Default::default(),
        };
        Ok(new_self)
    }
}

impl<T> MemSafe<T, ReadOnly> {
    /// Allocates a new instance of `T` in locked memory with read-only permissions (only available in Windows).
    #[cfg(windows)]
    pub fn new(value: T) -> Result<Self, MemoryError> {
        Ok(MemSafe {
            cell: Cell::new(value)?,
            _state: Default::default(),
        })
    }
    /// Changes the memory state from `ReadOnly` to `NoAccess`.
    #[cfg(unix)]
    pub fn no_access(mut self) -> Result<MemSafe<T, NoAccess>, MemoryError> {
        self.cell.no_access()?;
        let new_self = MemSafe {
            cell: self.cell,
            _state: Default::default(),
        };
        Ok(new_self)
    }

    /// Does nothing and return the object itself.
    pub fn read_only(self) -> Result<Self, Infallible> {
        Ok(self)
    }

    /// Changes the memory state from `ReadOnly` to `ReadWrite`.
    pub fn read_write(mut self) -> Result<MemSafe<T, ReadWrite>, MemoryError> {
        self.cell.read_write()?;
        let new_self = MemSafe {
            cell: self.cell,
            _state: Default::default(),
        };
        Ok(new_self)
    }
}

impl<T> MemSafe<T, ReadWrite> {
    /// Changes the memory state from `ReadWrite` to `NoAccess`.
    #[cfg(unix)]
    pub fn no_access(mut self) -> Result<MemSafe<T, NoAccess>, MemoryError> {
        self.cell.no_access()?;
        let new_self = MemSafe {
            cell: self.cell,
            _state: Default::default(),
        };
        Ok(new_self)
    }

    /// Changes the memory state from `ReadWrite` to `ReadOnly`.
    pub fn read_only(mut self) -> Result<MemSafe<T, ReadOnly>, MemoryError> {
        self.cell.read_only()?;
        let new_self = MemSafe {
            cell: self.cell,
            _state: Default::default(),
        };
        Ok(new_self)
    }

    /// Does nothing and return the object itself.
    pub fn read_write(self) -> Result<Self, Infallible> {
        Ok(self)
    }
}

#[cfg(unix)]
impl<const N: usize> MemSafe<[u8; N], NoAccess> {
    /// Creates a `MemSafe` protected byte buffer from an owned `String`,
    /// securely zeroizing the source string's heap memory.
    ///
    /// The string's bytes are copied into a fixed-size buffer stored entirely
    /// within protected memory. The original `String`'s heap allocation is
    /// overwritten with zeros before being deallocated.
    ///
    /// # Errors
    ///
    /// Returns `MemoryError` if the string length exceeds the buffer size `N`.
    /// The source string's heap data is zeroized even on error.
    pub fn from_string(mut s: String) -> Result<Self, MemoryError> {
        let len = s.len();
        if len > N {
            zeroize_string_heap(&mut s);
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "string length exceeds buffer size",
            )));
        }
        let mut buf = [0u8; N];
        buf[..len].copy_from_slice(s.as_bytes());
        zeroize_string_heap(&mut s);
        Self::new(buf)
    }
}

#[cfg(windows)]
impl<const N: usize> MemSafe<[u8; N], ReadOnly> {
    /// Creates a `MemSafe` protected byte buffer from an owned `String`,
    /// securely zeroizing the source string's heap memory.
    ///
    /// # Errors
    ///
    /// Returns `MemoryError` if the string length exceeds the buffer size `N`.
    /// The source string's heap data is zeroized even on error.
    pub fn from_string(mut s: String) -> Result<Self, MemoryError> {
        let len = s.len();
        if len > N {
            zeroize_string_heap(&mut s);
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "string length exceeds buffer size",
            )));
        }
        let mut buf = [0u8; N];
        buf[..len].copy_from_slice(s.as_bytes());
        zeroize_string_heap(&mut s);
        Self::new(buf)
    }
}

#[cfg(unix)]
impl<const N: usize> FromStr for MemSafe<[u8; N], NoAccess> {
    type Err = MemoryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > N {
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "string length exceeds buffer size",
            )));
        }
        let mut buf = [0u8; N];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        Self::new(buf)
    }
}

#[cfg(windows)]
impl<const N: usize> FromStr for MemSafe<[u8; N], ReadOnly> {
    type Err = MemoryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > N {
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "string length exceeds buffer size",
            )));
        }
        let mut buf = [0u8; N];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        Self::new(buf)
    }
}

#[cfg(unix)]
impl<const N: usize> TryFrom<&str> for MemSafe<[u8; N], NoAccess> {
    type Error = MemoryError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as FromStr>::from_str(s)
    }
}

#[cfg(unix)]
impl<const N: usize> TryFrom<String> for MemSafe<[u8; N], NoAccess> {
    type Error = MemoryError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_string(s)
    }
}

#[cfg(windows)]
impl<const N: usize> TryFrom<&str> for MemSafe<[u8; N], ReadOnly> {
    type Error = MemoryError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as FromStr>::from_str(s)
    }
}

#[cfg(windows)]
impl<const N: usize> TryFrom<String> for MemSafe<[u8; N], ReadOnly> {
    type Error = MemoryError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_string(s)
    }
}

impl<T> Deref for MemSafe<T, ReadOnly> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.cell.deref()
    }
}

impl<T> AsRef<T> for MemSafe<T, ReadOnly> {
    fn as_ref(&self) -> &T {
        self.cell.deref()
    }
}

impl<T> Deref for MemSafe<T, ReadWrite> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.cell.deref()
    }
}

impl<T> AsRef<T> for MemSafe<T, ReadWrite> {
    fn as_ref(&self) -> &T {
        self.cell.deref()
    }
}

impl<T> DerefMut for MemSafe<T, ReadWrite> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.cell.deref_mut()
    }
}

impl<T> AsMut<T> for MemSafe<T, ReadWrite> {
    fn as_mut(&mut self) -> &mut T {
        self.cell.deref_mut()
    }
}
