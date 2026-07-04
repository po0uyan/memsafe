use crate::cell::Cell;
use crate::mem_safe::{MemSafe, MemSafeRead, MemSafeWrite};
use crate::MemoryError;

/// A fixed-size secret stored entirely *inline* within a protected memory page.
///
/// `Secret<N>` is a thin newtype around `MemSafe<[u8; N]>` whose API surface
/// only permits constructions that keep every byte of the secret inside the
/// locked, dump-excluded, default-deny region. By construction it is
/// **impossible** to reach the `MemSafe<String>` / `MemSafe<Vec<u8>>` pitfall
/// where only the 24-byte header is protected and the actual secret bytes
/// live on the unprotected `malloc` heap — the wrapped type is `[u8; N]`,
/// whose `size_of::<T>()` equals `N`.
///
/// This is the **recommended type for user-facing secrets** (API keys,
/// passwords, tokens). Use [`MemSafe`] directly for non-secret memory
/// protection (e.g. guard pages around an allocation).
///
/// # Examples
///
/// In-place initialization — the secret never visits the regular heap or a
/// stack temporary:
///
/// ```
/// use memsafe::Secret;
///
/// let mut secret = Secret::<64>::new_with(|buf| {
///     buf[..10].copy_from_slice(b"my-api-key");
/// }).unwrap();
///
/// let view = secret.read().unwrap();
/// assert_eq!(&view[..10], b"my-api-key");
/// ```
///
/// From an owned byte source — the source is volatile-zeroed after the copy:
///
/// ```
/// use memsafe::Secret;
///
/// let key = b"my-api-key".to_vec();
/// let mut secret = Secret::<64>::from_bytes(key).unwrap();
/// ```
///
/// # Formatting is a compile-time error
///
/// `Secret` deliberately implements neither `Debug` nor `Display`, so a stray
/// `{:?}` or `{}` in a log line can never leak it:
///
/// ```compile_fail
/// use memsafe::Secret;
/// let secret = Secret::<8>::new_with(|_| {}).unwrap();
/// println!("{:?}", secret); // does not compile: `Secret` is not `Debug`
/// ```
///
/// ```compile_fail
/// use memsafe::Secret;
/// let secret = Secret::<8>::new_with(|_| {}).unwrap();
/// println!("{}", secret); // does not compile: `Secret` is not `Display`
/// ```
pub struct Secret<const N: usize> {
    inner: MemSafe<[u8; N]>,
}

impl<const N: usize> Secret<N> {
    /// Allocate an `N`-byte secret in protected memory and fill it in place.
    ///
    /// The page is locked, dump-excluded (Linux), and OS-zeroed **before**
    /// `init` runs. `init` writes the secret through a `&mut [u8; N]` that
    /// points directly into the protected region — the secret never visits
    /// a stack temporary or the regular heap.
    ///
    /// This is the most secure constructor: there is no "before" state in
    /// which the bytes existed in unprotected memory.
    ///
    /// If `init` panics, the construction guard volatile-zeroes the page,
    /// unlocks it, and unmaps it before the panic propagates — a partially
    /// written secret can neither leak nor linger.
    pub fn new_with<F>(init: F) -> Result<Self, MemoryError>
    where
        F: FnOnce(&mut [u8; N]),
    {
        Cell::<[u8; N]>::new_with(init).map(|cell| Secret {
            inner: MemSafe { cell },
        })
    }

    /// Encapsulate an owned byte source into a new secret, volatile-zeroing
    /// the source after the copy.
    ///
    /// On error the source is returned alongside the failure reason:
    /// - On length mismatch (`source.len() > N`): source is returned untouched.
    /// - On memory-protection failure: source has already been zeroed.
    ///
    /// Only the bytes exposed by [`AsMut::as_mut`] are zeroized. For containers
    /// like `Vec` or `String`, capacity beyond `len` is not visited; call
    /// [`Vec::shrink_to_fit`] / [`String::shrink_to_fit`] beforehand if that
    /// matters for your threat model. Likewise, if the container ever *grew*
    /// while holding secret bytes, earlier reallocations left copies on the
    /// heap that this crate cannot reach — build the secret at its final size,
    /// or better, write it directly into protected memory with [`Secret::new_with`].
    pub fn from_bytes<T: AsMut<[u8]>>(bytes: T) -> Result<Self, (T, MemoryError)> {
        Cell::<[u8; N]>::from_bytes(bytes).map(|cell| Secret {
            inner: MemSafe { cell },
        })
    }

    /// Obtain temporary read access to the secret bytes. The returned guard
    /// derefs to `&[u8; N]` and restores lowest-privilege access on drop
    /// (Unix).
    ///
    /// **Timing note:** comparing secret bytes with `==` is not
    /// constant-time and can leak information through timing side channels.
    /// If you compare secrets (password checks, MAC verification), use a
    /// constant-time comparison such as the `subtle` crate's `ct_eq`.
    pub fn read(&mut self) -> Result<MemSafeRead<'_, [u8; N]>, MemoryError> {
        self.inner.read()
    }

    /// Obtain temporary read-write access to the secret bytes.
    pub fn write(&mut self) -> Result<MemSafeWrite<'_, [u8; N]>, MemoryError> {
        self.inner.write()
    }
}

impl<const N: usize> TryFrom<&str> for Secret<N> {
    type Error = MemoryError;

    /// Convert a borrowed string slice into a secret.
    ///
    /// **Note:** A borrowed `&str` cannot be zeroized by this crate. Prefer
    /// [`Secret::new_with`] (write straight into protected memory) or
    /// [`TryFrom<String>`] (zeroes the source) when the input was generated
    /// at runtime.
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.len() > N {
            return Err(MemoryError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "string length exceeds buffer size",
            )));
        }
        let bytes = s.as_bytes();
        let len = bytes.len();
        Self::new_with(|page| unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), page.as_mut_ptr(), len);
        })
    }
}

impl<const N: usize> TryFrom<String> for Secret<N> {
    type Error = (String, MemoryError);

    /// Convert an owned `String` into a secret, volatile-zeroing the source.
    /// On error the original `String` is returned alongside the reason.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_bytes(s.into_bytes()).map_err(|(v, e)| {
            // Both paths produce valid UTF-8: the size-error case never
            // mutated the bytes, and the memory-error case zeroed them
            // (NUL is valid UTF-8).
            (
                String::from_utf8(v).expect("zeroed or original UTF-8 bytes"),
                e,
            )
        })
    }
}
