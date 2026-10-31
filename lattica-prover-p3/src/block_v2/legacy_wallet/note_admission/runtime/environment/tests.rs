use super::*;
use crate::spill_alloc::allocation_requests::measure;

fn valid(name: &CStr) -> Result<Option<&'static [u8]>, Error> {
    if name == INDEX {
        return Ok(Some(b"0"));
    }
    if name == UUID {
        return Ok(Some(b"GPU-01234567-89ab-cdef-0123-456789abcdef"));
    }
    Ok(FIXED
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value))
}

#[test]
fn fixed_note_policy_is_allocation_free_and_every_lookup_has_a_unique_key() {
    let (_, requests) = measure(|| {
        assert!(KEY_COUNT <= 96);
        for (index, key) in NAMES.iter().enumerate() {
            assert!(!key.to_bytes().is_empty());
            assert!(!NAMES[..index].contains(key));
        }
        assert!(
            SealedNoteEnvironment::requested_bytes().unwrap() > size_of::<SealedNoteEnvironment>()
        );
        assert_eq!(validate(valid).unwrap().index(), 0);
    });
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
}

#[test]
fn note_policy_rejects_every_override_missing_switch_and_changed_resource_limit() {
    // Only the actual Captured constructor may create a capability. This pure
    // relation check exercises policy without getenv, setenv or GPU access.
    for &(key, _) in FIXED {
        for changed in [None, Some(&b""[..]), Some(&b"unexpected"[..])] {
            assert!(validate(|name| if name == key {
                Ok(changed)
            } else {
                valid(name)
            })
            .is_err());
        }
    }
    for &key in ABSENT {
        for changed in [&b""[..], &b"0"[..], &b"1"[..]] {
            assert!(validate(|name| if name == key {
                Ok(Some(changed))
            } else {
                valid(name)
            })
            .is_err());
        }
    }
    for changed in [&b"00"[..], &b"64"[..], &b"-1"[..], &b""[..]] {
        assert!(validate(|name| if name == INDEX {
            Ok(Some(changed))
        } else {
            valid(name)
        })
        .is_err());
    }
    assert!(validate(|name| if name == UUID {
        Ok(Some(b"GPU-invalid"))
    } else {
        valid(name)
    })
    .is_err());
}
