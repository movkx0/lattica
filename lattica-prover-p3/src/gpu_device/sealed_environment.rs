//! Fixed-capacity environment capture for an already reserved research worker.
//! No allocation, process launch or admission authority. Each enclosing profile
//! owns its exact key list, value policy, reservation, and process exclusivity.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{ffi::CStr, marker::PhantomData, rc::Rc};

const MAX_KEYS: usize = 96;
const MAX_VALUE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Shape,
    DuplicateKey,
    ValueLimit { index: usize },
    Changed { index: usize },
    UntrackedKey,
    Utf8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Value<const BYTES: usize> {
    bytes: [u8; BYTES],
    used: usize,
    present: bool,
}
impl<const BYTES: usize> Value<BYTES> {
    const EMPTY: Self = Self {
        bytes: [0; BYTES],
        used: 0,
        present: false,
    };

    #[cfg(test)]
    fn copy_from(index: usize, source: Option<&[u8]>) -> Result<Self, Error> {
        let mut value = Self::EMPTY;
        if let Some(source) = source {
            if source.len() > BYTES {
                return Err(Error::ValueLimit { index });
            }
            value.bytes[..source.len()].copy_from_slice(source);
            value.used = source.len();
            value.present = true;
        }
        Ok(value)
    }

    fn get(&self) -> Option<&[u8]> {
        self.present.then_some(&self.bytes[..self.used])
    }
}

/// Owned values, including the distinction between missing and empty. The
/// private fields and absence of Clone prevent replacing a captured capability
/// with caller-declared booleans. This type is local to its serial worker.
pub(crate) struct Captured<const KEYS: usize, const BYTES: usize> {
    names: &'static [&'static CStr; KEYS],
    values: [Value<BYTES>; KEYS],
    _serial: PhantomData<Rc<()>>,
}

impl<const KEYS: usize, const BYTES: usize> Captured<KEYS, BYTES> {
    /// Include the owned inline payload and one sequential recheck temporary.
    /// Caller stack/allocator/runtime storage remains separately reserved.
    pub(crate) const fn inline_and_scratch_bytes() -> usize {
        std::mem::size_of::<Self>() + std::mem::size_of::<Value<BYTES>>()
    }

    fn check_names(names: &[&CStr; KEYS]) -> Result<(), Error> {
        if KEYS == 0 || KEYS > MAX_KEYS || BYTES == 0 || BYTES > MAX_VALUE_BYTES {
            return Err(Error::Shape);
        }
        for (index, name) in names.iter().enumerate() {
            if name.to_bytes().is_empty() || name.to_bytes().contains(&b'=') {
                return Err(Error::Shape);
            }
            if names[..index].contains(name) {
                return Err(Error::DuplicateKey);
            }
        }
        Ok(())
    }

    /// Capture after the enclosing real reservation and before any allocating
    /// std::env access. Every supplied key is queried, including absent keys.
    ///
    /// # Safety
    /// The guarded process must exclude all concurrent or subsequent environment
    /// mutation for this lifetime. libc getenv pointers remain borrowed only
    /// during this bounded copy. Recheck detects drift at boundaries; it is not
    /// an operating-system lock and cannot make concurrent setenv memory-safe.
    pub(crate) unsafe fn capture(names: &'static [&'static CStr; KEYS]) -> Result<Self, Error> {
        Self::check_names(names)?;
        let mut values = [Value::EMPTY; KEYS];
        for (index, name) in names.iter().enumerate() {
            // SAFETY: this method's immutable-environment contract applies to
            // every query; the name is a complete static NUL-terminated CStr.
            values[index] = unsafe { read_value(index, name)? };
        }
        Ok(Self {
            names,
            values,
            _serial: PhantomData,
        })
    }

    /// Refuse a changed presence bit or value before the next allocating or
    /// dispatch boundary. Holds no environment pointer after returning.
    ///
    /// # Safety
    /// The same immutable-process-environment contract as capture must hold.
    pub(crate) unsafe fn recheck(&self) -> Result<(), Error> {
        for (index, name) in self.names.iter().enumerate() {
            // SAFETY: the caller retains the exclusive immutable environment.
            let current = unsafe { read_value(index, name)? };
            if current != self.values[index] {
                return Err(Error::Changed { index });
            }
        }
        Ok(())
    }

    /// Untracked names are errors, never evidence that a worker override is
    /// absent. Missing and empty captured values remain different results.
    pub(crate) fn value(&self, name: &CStr) -> Result<Option<&[u8]>, Error> {
        let index = self
            .names
            .iter()
            .position(|entry| *entry == name)
            .ok_or(Error::UntrackedKey)?;
        Ok(self.values[index].get())
    }

    pub(crate) fn text(&self, name: &CStr) -> Result<Option<&str>, Error> {
        self.value(name)?
            .map(|bytes| std::str::from_utf8(bytes).map_err(|_| Error::Utf8))
            .transpose()
    }
}

unsafe fn read_value<const BYTES: usize>(index: usize, name: &CStr) -> Result<Value<BYTES>, Error> {
    // SAFETY: name is valid; caller excludes environment mutations throughout
    // lookup and copy. We deliberately do not call strlen or CStr::from_ptr.
    let pointer = unsafe { libc::getenv(name.as_ptr()) };
    // SAFETY: getenv returns null or a stable NUL-terminated value under this
    // method's immutable-environment contract.
    unsafe { copy_pointer(index, pointer) }
}

unsafe fn copy_pointer<const BYTES: usize>(
    index: usize,
    pointer: *const libc::c_char,
) -> Result<Value<BYTES>, Error> {
    if pointer.is_null() {
        return Ok(Value::EMPTY);
    }
    let mut result = Value::EMPTY;
    result.present = true;
    for offset in 0..=BYTES {
        // SAFETY: getenv returns a live NUL-terminated C string. We stop at its
        // first NUL and inspect at most BYTES+1 bytes, with no allocation.
        let byte = unsafe { *pointer.add(offset) as u8 };
        if byte == 0 {
            result.used = offset;
            return Ok(result);
        }
        if offset == BYTES {
            return Err(Error::ValueLimit { index });
        }
        result.bytes[offset] = byte;
    }
    unreachable!("bounded scan returns on its final iteration")
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::spill_alloc::allocation_requests::measure;

    const KEYS: [&CStr; 3] = [c"A", c"B", c"C"];

    #[test]
    fn pointer_scan_checks_the_eof_probe_before_exposing_an_owned_value() {
        for (source, expected) in [(c"", &b""[..]), (c"1234", &b"1234"[..])] {
            // SAFETY: the static CStr is stable and NUL terminated.
            let copied = unsafe { copy_pointer::<4>(0, source.as_ptr()) }.unwrap();
            assert_eq!(copied.get(), Some(expected));
        }
        // SAFETY: static valid CStr; the bounded scan must refuse byte five.
        assert_eq!(
            unsafe { copy_pointer::<4>(2, c"12345".as_ptr()) }.err(),
            Some(Error::ValueLimit { index: 2 })
        );
        // SAFETY: null models absent getenv output and is never dereferenced.
        assert_eq!(
            unsafe { copy_pointer::<4>(0, std::ptr::null()) }
                .unwrap()
                .get(),
            None
        );
    }

    #[test]
    fn exact_capacity_missing_empty_and_untracked_values_stay_distinct() {
        let empty = Value::<4>::copy_from(0, Some(b"")).unwrap();
        let absent = Value::<4>::copy_from(0, None).unwrap();
        assert!(empty != absent);
        assert_eq!(
            Value::<4>::copy_from(2, Some(b"12345")).err(),
            Some(Error::ValueLimit { index: 2 })
        );
        let captured = Captured {
            names: &KEYS,
            values: [
                absent,
                empty,
                Value::<4>::copy_from(2, Some(b"1234")).unwrap(),
            ],
            _serial: PhantomData,
        };
        assert_eq!(captured.value(c"A"), Ok(None));
        assert_eq!(captured.value(c"B"), Ok(Some(&b""[..])));
        assert_eq!(captured.value(c"C"), Ok(Some(&b"1234"[..])));
        assert_eq!(captured.value(c"OTHER"), Err(Error::UntrackedKey));
    }

    #[test]
    fn fixed_capture_validation_and_lookup_make_no_allocation_requests() {
        let (_, requests) = measure(|| {
            Captured::<3, 4>::check_names(&KEYS).unwrap();
            assert_eq!(
                Captured::<2, 4>::check_names(&[c"A", c"A"]),
                Err(Error::DuplicateKey)
            );
            assert_eq!(Captured::<1, 4>::check_names(&[c"A=B"]), Err(Error::Shape));
            assert_eq!(Captured::<0, 4>::check_names(&[]), Err(Error::Shape));
            let captured = Captured {
                names: &KEYS,
                values: [Value::<4>::copy_from(0, Some(b"1234")).unwrap(); 3],
                _serial: PhantomData,
            };
            assert_eq!(captured.text(c"A"), Ok(Some("1234")));
        });
        assert_eq!(
            (requests.calls, requests.bytes, requests.overflow),
            (0, 0, false)
        );
    }
}
