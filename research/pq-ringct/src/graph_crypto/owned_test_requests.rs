//! Fixed test fixtures owned by graph_crypto. Payload and the unchecked request
//! constructor remain private in production and inaccessible to workflow code.
use super::*;

fn partition_policy() -> Policy {
    Policy {
        maximum_aes_blocks: 64,
        maximum_shake_permutations: 8,
        child_memory_budget_bytes: 8 << 30,
        admission: Admission::Estimated,
    }
}

pub(crate) fn shake_partition() -> Request {
    let input = vec![7; 16 * crate::shake_air::RATE + 3];
    Request::new([3; 32], 0, 0,
        RequestDescriptor::Shake(crate::shake_air::Descriptor {
            input_len: input.len(), output_len: 273,
        }), Payload::Shake(input), partition_policy()).unwrap()
}

pub(crate) fn aes_partition() -> Request {
    Request::new([3; 32], 0, 0,
        RequestDescriptor::Aes(crate::aes_lane_air::Descriptor {
            domain: 0x4368, start_counter: u32::MAX, output_len: 64 * 16 + 1,
        }), Payload::Aes([7; 32]), partition_policy()).unwrap()
}
