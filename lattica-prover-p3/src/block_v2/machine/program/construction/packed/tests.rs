use super::*;
use crate::block_v2::machine::compiler_constants::Constants;

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
