//! Full-column differential oracle, compiled only by explicit diagnostic feature.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::audit_generated_trace;

#[test]
#[ignore = "requires an exclusive bounded OpenCL service; no proving or benchmark"]
fn gpu_crypto_native_traces_match_every_cpu_column() {
    let session = crate::opencl::Session::start(crate::opencl::Limits {
        host_bytes: 32 << 30,
        device_bytes: 8 << 30,
        max_rows: 1 << 20,
    })
    .unwrap();
    let key = core::array::from_fn(|i| (i * 7 + 13) as u8);
    let budget = 512usize << 20;
    for output_len in [1, 16, 17, 33] {
        let air = crate::aes_air::AesAir::new(crate::aes_air::Descriptor {
            domain: 0x1234567812345678,
            start_counter: u32::MAX,
            output_len,
        })
        .unwrap();
        let expected = air.generate(key).unwrap();
        audit_generated_trace(
            "audit_aes_wide",
            air.height,
            air.width(),
            air.num_public_values(),
            budget,
            &expected.trace.values,
            &expected.public_values,
            |context| air.generate_gpu(context, &key),
        )
        .unwrap();
    }
    // Every column of every row checks all seven input-header prefixes,
    // pre/post byte updates through all 14 rounds, both output half-commitments,
    // final pre-reset row, counter wrap, and inactive padded units. The retained
    // wide-AES loop above remains the control for the unchanged wide route.
    for (first_block, blocks, output_len) in [
        (0, 1, 1),
        (1, 3, 49),
        (0, 2, 17),
        (0, 1, 8),
        (0, 1, 9),
        (1, 1, 25),
        (0, 1, 16),
        (0, 3, 48),
        (7, 5, 257),
        (11, 5, 256),
    ] {
        let air = crate::aes_lane_air::AesLaneAir::segment(
            crate::aes_air::Descriptor {
                domain: 0x1020304050607080,
                start_counter: u32::MAX,
                output_len,
            },
            first_block,
            blocks,
        )
        .unwrap();
        let expected = air.generate(key).unwrap();
        audit_generated_trace(
            "audit_aes_lane",
            air.height,
            air.width(),
            air.num_public_values(),
            budget,
            &expected.trace.values,
            &expected.public_values,
            |context| air.generate_gpu(context, &key),
        )
        .unwrap();
    }
    for (input_len, output_len) in [(0, 0), (135, 137), (136, 272), (273, 409)] {
        let input = (0..input_len)
            .map(|i| (i * 17 + 23) as u8)
            .collect::<Vec<_>>();
        let descriptor = shake_air::Descriptor {
            input_len,
            output_len,
        };
        let air = shake_air::ShakeAir::whole(descriptor).unwrap();
        let expected = air.generate(&input).unwrap();
        assert_eq!(
            air.expected_public_values(&input).unwrap(),
            expected.public_values
        );
        audit_generated_trace(
            "audit_shake_wide",
            air.height,
            air.width(),
            air.num_public_values(),
            budget,
            &expected.trace.values,
            &expected.public_values,
            |context| air.generate_gpu(context, &input),
        )
        .unwrap();
        let permutation = input_len / shake_air::RATE;
        let air = shake_air::lane::LaneShakeAir::new(descriptor, permutation).unwrap();
        let expected = air.generate(&input).unwrap();
        audit_generated_trace(
            "audit_shake_lane",
            shake_air::lane::HEIGHT,
            air.width(),
            air.num_public_values(),
            budget,
            &expected.trace.values,
            &expected.public_values,
            |context| air.generate_gpu(context, &input),
        )
        .unwrap();
    }
    let descriptor = shake_air::Descriptor {
        input_len: 3 * 136 + 5,
        output_len: 4 * 136 + 3,
    };
    let input = (0..descriptor.input_len)
        .map(|i| (i * 31 + 11) as u8)
        .collect::<Vec<_>>();
    for air in [
        shake_air::lane::batch::BatchShakeAir::full_absorb(descriptor, 0, 2).unwrap(),
        shake_air::lane::batch::BatchShakeAir::full_absorb(descriptor, 1, 2).unwrap(),
        shake_air::lane::batch::BatchShakeAir::full_squeeze(descriptor, 4, 2).unwrap(),
    ] {
        let expected = air.generate(&input).unwrap();
        audit_generated_trace(
            "audit_shake_batch",
            air.height(),
            air.width(),
            air.num_public_values(),
            budget,
            &expected.trace.values,
            &expected.public_values,
            |context| air.generate_gpu(context, &input),
        )
        .unwrap();
    }
    drop(session);
}
