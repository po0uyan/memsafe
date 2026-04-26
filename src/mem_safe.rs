use crate::cell::Cell;
use crate::ptr_ops::zeroize_string_heap;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use crate::MemoryError;

/// `MemSafe` allows for a protected memory space with controlled access to prevent
/// unauthorized access and ensure memory safety.
///
/// # Examples
///
/// ```
/// use memsafe::MemSafe;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut safe_data = MemSafe::new(42)?;
///
///     // Read access
///     {
///         let reader = safe_data.read()?;
///         assert_eq!(*reader, 42);
///     } // reader is dropped, privileges are released
///
///     // Write access
///     {
///         let mut writer = safe_data.write()?;
///         *writer = 100;
///     } // writer is dropped, privileges are released
///
///     // Verify the change
///     {
///         let reader = safe_data.read()?;
///         assert_eq!(*reader, 100);
///     }
///     # Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct MemSafe<T> {
    cell: Cell<T>,
}

unsafe impl<T> Send for MemSafe<T> where T: Send {}

impl<T> MemSafe<T> {
    /// Initialize a protected memory region containing the specified value,
    /// with lowest possible memory access controls applied.
    ///
    /// Lowest access level:
    /// | Platform          | Read | Write |
    /// |-------------------|------|-------|
    /// | Unix              |  ❌ |   ❌  |
    /// | Windows           |  ✅ |   ❌  |
    ///
    /// # Errors
    ///
    /// Returns a `MemoryError` if memory protection could not be initialized.
    ///
    /// # Examples
    ///
    /// ```
    /// use memsafe::MemSafe;
    ///
    /// let safe_data = MemSafe::new([0_u8; 32]).unwrap();
    /// ```
    pub fn new(value: T) -> Result<MemSafe<T>, MemoryError> {
        Ok(Self {
            cell: Cell::new(value)?,
        })
    }

    /// Obtains read-only access to the protected memory region. This method temporarily
    /// elevates the read privileges and returns a handle that implements `Deref` for
    /// accessing the inner value. When the returned `MemSafeRead` is dropped,
    /// privileges are automatically revoked on Unix-based OSes.
    ///
    /// # Errors
    ///
    /// Returns a `MemoryError` if privilege elevation fails.
    pub fn read(&mut self) -> Result<MemSafeRead<'_, T>, MemoryError> {
        self.cell.read_only()?;
        Ok(MemSafeRead { mem_safe: self })
    }

    /// Obtains mutable access to the protected memory region. This method temporarily
    /// elevates the read and write privileges and returns a handle that implements `Deref`
    /// and `DerefMut`for modifying the inner value. When the returned `MemSafeWrite` is
    /// dropped, privileges are automatically revoked on Unix-based OSes. On Windows read,
    /// privileges are maintained while write privileges are revoked.
    ///
    /// # Errors
    ///
    /// Returns a `MemoryError` if privilege elevation fails.
    pub fn write(&mut self) -> Result<MemSafeWrite<'_, T>, MemoryError> {
        self.cell.read_write()?;
        Ok(MemSafeWrite { mem_safe: self })
    }
}

impl<const N: usize> MemSafe<[u8; N]> {
    /// Creates a `MemSafe` protected byte buffer from an owned `String`,
    /// securely zeroizing the source string's heap memory.
    ///
    /// The string's bytes are copied into a fixed-size buffer stored entirely
    /// within protected memory. The original `String`'s heap allocation is
    /// overwritten with zeros before being deallocated, so no trace of the
    /// secret remains in unprotected memory.
    ///
    /// For borrowed input, see [`FromStr`] / [`TryFrom<&str>`]. Note that
    /// borrowed sources cannot be zeroized by this crate; the caller is
    /// responsible for the lifecycle of the source.
    ///
    /// # Errors
    ///
    /// Returns `MemoryError` if the string length exceeds the buffer size `N`,
    /// or if memory protection could not be initialized. The source string's
    /// heap data is zeroized even on error.
    ///
    /// # Examples
    ///
    /// ```
    /// use memsafe::MemSafe;
    ///
    /// let api_key = String::from("my-api-key");
    /// let secret = MemSafe::<[u8; 64]>::from_string(api_key).unwrap();
    /// ```
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

/// Parse a string slice into a `MemSafe` protected byte buffer.
///
/// The string's bytes are copied into a fixed-size buffer stored entirely
/// within protected memory. Remaining buffer bytes are zero-filled.
///
/// The source `&str` is borrowed and cannot be zeroized; use
/// [`MemSafe::from_string`] for owned input that should be zeroized.
///
/// # Examples
///
/// ```
/// use memsafe::MemSafe;
///
/// let secret: MemSafe<[u8; 64]> = "my-api-key".parse().unwrap();
/// ```
impl<const N: usize> FromStr for MemSafe<[u8; N]> {
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

impl<const N: usize> TryFrom<&str> for MemSafe<[u8; N]> {
    type Error = MemoryError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        <Self as FromStr>::from_str(s)
    }
}

impl<const N: usize> TryFrom<String> for MemSafe<[u8; N]> {
    type Error = MemoryError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_string(s)
    }
}

pub struct MemSafeRead<'a, T> {
    mem_safe: &'a mut MemSafe<T>,
}

impl<T> Deref for MemSafeRead<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.mem_safe.cell.deref()
    }
}

impl<T> Drop for MemSafeRead<'_, T> {
    fn drop(&mut self) {
        self.mem_safe.cell.low_priv().unwrap();
    }
}

pub struct MemSafeWrite<'a, T> {
    mem_safe: &'a mut MemSafe<T>,
}

impl<T> Deref for MemSafeWrite<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.mem_safe.cell.deref()
    }
}

impl<T> DerefMut for MemSafeWrite<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.mem_safe.cell.deref_mut()
    }
}

impl<T> Drop for MemSafeWrite<'_, T> {
    fn drop(&mut self) {
        self.mem_safe.cell.low_priv().unwrap();
    }
}
