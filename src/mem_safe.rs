use crate::cell::Cell;
use std::ops::{Deref, DerefMut};

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
