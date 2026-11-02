use super::*;
use crate::block_v2::machine::compiler_constants::Constants;
use p3_field::PrimeCharacteristicRing;

fn budget() -> Budget {
    let mut value = Budget::new(Constants::cpu(), 0).unwrap();
    value.limit = Some(32 << 20);
    value
}

#[test]
fn compact_maps_preserve_full_keys_values_and_reduce_requested_storage() {
    let mut packed = Map::new();
    let mut original = RawMap::new();
    let (mut small, mut large) = (budget(), budget());
    for i in 0..4096 {
        let key = (
            (i % 3) as u8,
            [Wire(i), Wire(i + 1), Wire(i + 2)],
            [Wire(i + 3), Wire(i + 4), Wire(MAX_WIRES - 1)],
        );
        let value = [Wire(i + 7), Wire(i + 8), Wire(i + 9)];
        assert_eq!(
            packed.insert(key, value, &mut small),
            original.insert(key, value, &mut large)
        );
        assert_eq!(packed.get(&key), original.get(&key).copied());
    }
    assert!(!small.failed && !large.failed);
    assert!(small.live * 4 <= large.live * 3);
    assert!(small.peak * 4 <= large.peak * 3);
    let retained = packed.reset_retained().unwrap();
    assert_eq!(retained, small.live);
    assert!(packed
        .get(&(
            0,
            [Wire(0), Wire(1), Wire(2)],
            [Wire(3), Wire(4), Wire(MAX_WIRES - 1)]
        ))
        .is_none());
}

#[test]
fn compact_wire_conversion_bypasses_invalid_interning_without_aliasing_valid_keys() {
    let mut map = Map::<Wire, Wire>::new();
    let mut memory = budget();
    map.insert(Wire(0), Wire(1), &mut memory);
    assert_eq!(map.get(&Wire(0)), Some(Wire(1)));
    for invalid in [MAX_WIRES, usize::MAX] {
        assert!(map.get(&Wire(invalid)).is_none());
        let vacant = map.probe(Wire(invalid)).err().unwrap();
        let mut denied = budget();
        map.insert_vacant(vacant, Wire(2), &mut denied);
        assert!(!denied.failed);
        assert_eq!(map.get(&Wire(0)), Some(Wire(1)));
    }
    let mut denied = budget();
    map.insert(Wire(3), Wire(MAX_WIRES), &mut denied);
    assert!(!denied.failed);
    assert_eq!(map.get(&Wire(3)), None);
}

#[test]
fn compact_vacant_tokens_remain_safe_after_growth_reset_and_cross_map_use() {
    let mut first = Map::<Wire, Wire>::new();
    let mut second = Map::<Wire, Wire>::new();
    let mut memory = budget();
    let token = first.probe(Wire(7)).err().unwrap();
    for i in 10..100 {
        first.insert(Wire(i), Wire(i + 1), &mut memory);
    }
    first.insert_vacant(token, Wire(8), &mut memory);
    assert_eq!(first.get(&Wire(7)), Some(Wire(8)));
    let token = first.probe(Wire(2)).err().unwrap();
    first.reset_retained().unwrap();
    second.insert_vacant(token, Wire(3), &mut memory);
    assert_eq!(second.get(&Wire(2)), Some(Wire(3)));
    assert_eq!(first.get(&Wire(7)), None);
    assert!(!memory.failed);
}

#[test]
fn nonzero_wire_slots_reduce_constant_map_padding_and_preserve_zero() {
    let mut packed = Map::<u64, Wire>::new();
    let mut previous = RawMap::<u64, u32>::new();
    let (mut small, mut large) = (budget(), budget());
    for i in 0..4096 {
        packed.insert(i, Wire(i as usize), &mut small);
        previous.insert(i, i as u32, &mut large);
    }
    assert_eq!(packed.get(&0), Some(Wire(0)));
    assert_eq!(
        Wire::load(Wire(MAX_WIRES - 1).store().unwrap()),
        Wire(MAX_WIRES - 1)
    );
    assert!(small.live < large.live && small.peak < large.peak);
    let held = packed.retained_bytes().unwrap();
    assert_eq!(packed.release_retained(), Some(held));
    assert_eq!(packed.retained_bytes(), Some(0));
    assert!(packed.get(&0).is_none());
}

#[test]
fn fixed_tuple_keys_hash_once_without_changing_storage_layout() {
    use std::hash::Hasher;
    #[derive(Default)]
    struct Writes {
        calls: usize,
        bytes: Vec<u8>,
    }
    impl Hasher for Writes {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, bytes: &[u8]) {
            self.calls += 1;
            self.bytes.extend_from_slice(bytes);
        }
    }
    fn encoded<K: Compact>(key: K) -> Writes {
        let mut hash = Writes::default();
        key.store().unwrap().hash(&mut hash);
        hash
    }
    let a = encoded((3u8, Wire(0), Wire(MAX_WIRES - 1)));
    assert_eq!((a.calls, a.bytes.len()), (1, 9));
    assert_eq!(&a.bytes[1..5], &1u32.to_le_bytes());
    assert_ne!(a.bytes, encoded((3u8, Wire(MAX_WIRES - 1), Wire(0))).bytes);
    let a = encoded((Wire(0), Wire(1), Wire(2)));
    assert_eq!((a.calls, a.bytes.len()), (1, 12));
    let a = encoded((1u8, [Wire(0); 3], [Wire(MAX_WIRES - 1); 3]));
    assert_eq!((a.calls, a.bytes.len()), (1, 25));
    // The hasher changes neither packed niches nor any allocation census.
    type W = NonZeroU32;
    assert_eq!(
        std::mem::size_of::<Option<(Triple<u8, W, W>, W)>>(),
        std::mem::size_of::<Option<((u8, W, W), W)>>()
    );
    assert_eq!(
        std::mem::size_of::<Option<(Triple<u8, [W; 3], [W; 3]>, [W; 3])>>(),
        std::mem::size_of::<Option<((u8, [W; 3], [W; 3]), [W; 3])>>()
    );
    assert!((1u8, Wire(0), Wire(MAX_WIRES)).store().is_none());
}

#[test]
fn known_constant_filter_preserves_sparse_values_and_clears_retained_storage() {
    let mut known = KnownConstants::new();
    let mut memory = budget();
    for index in [0, 63, 64, 257, 4096, MAX_WIRES - 1] {
        known.insert(Wire(index), Val::from_u64(index as u64 + 1), &mut memory);
    }
    assert!(!memory.failed);
    for index in [0, 63, 64, 257, 4096, MAX_WIRES - 1] {
        assert_eq!(
            known.get(&Wire(index)),
            Some(Val::from_u64(index as u64 + 1))
        );
    }
    for index in [1, 62, 65, 256, 4095, MAX_WIRES, usize::MAX] {
        assert_eq!(known.get(&Wire(index)), None);
    }
    let live = memory.live;
    known.insert(Wire(63), Val::ONE, &mut memory);
    known.insert(Wire(usize::MAX), Val::ONE, &mut memory);
    assert_eq!(known.get(&Wire(63)), Some(Val::ONE));
    assert_eq!(memory.live, live);
    assert!(!memory.failed);
    assert_eq!(known.reset_retained(), Some(live));
    assert_eq!(known.get(&Wire(63)), None);
    assert_eq!(known.get(&Wire(MAX_WIRES - 1)), None);
    known.insert(Wire(65), Val::ONE, &mut memory);
    assert_eq!(memory.live, live);
    assert_eq!(known.get(&Wire(65)), Some(Val::ONE));
    assert_eq!(known.release_retained(), Some(live));
    assert_eq!(known.retained_bytes(), Some(0));
    assert_eq!(known.get(&Wire(65)), None);
}

#[test]
fn known_constant_filter_charges_growth_overlap_before_allocating() {
    for admitted in [false, true] {
        let mut known = KnownConstants::new();
        let mut memory = budget();
        known.insert(Wire(0), Val::ONE, &mut memory);
        assert_eq!(known.present.capacity(), 4);
        let before = memory.live;
        memory.limit = Some(before + 64 - usize::from(!admitted));
        known.insert(Wire(256), Val::ONE, &mut memory);
        assert_eq!(memory.failed, !admitted);
        assert_eq!(memory.byte_limit_exceeded, !admitted);
        assert_eq!(known.get(&Wire(0)), Some(Val::ONE));
        assert_eq!(known.get(&Wire(256)), admitted.then_some(Val::ONE));
        assert_eq!(memory.live, before + if admitted { 32 } else { 0 });
        assert_eq!(known.retained_bytes(), Some(memory.live));
        if admitted {
            assert_eq!(memory.peak, before + 64);
        }
    }
}
