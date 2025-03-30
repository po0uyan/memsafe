use crate::cell::Cell;
use std::ops::{Deref, DerefMut};

use crate::MemoryError;

#[derive(Debug)]
pub struct MemSafe<T> {
    cell: Cell<T>,
}

unsafe impl<T> Send for MemSafe<T> where T: Send {}

impl<T> MemSafe<T> {
    pub fn new(value: T) -> Result<MemSafe<T>, MemoryError> {
        Ok(Self {
            cell: Cell::new(value)?,
        })
    }

    pub fn read(&mut self) -> Result<MemSafeRead<'_, T>, MemoryError> {
        self.cell.read_only()?;
        Ok(MemSafeRead { mem_safe: self })
    }

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
