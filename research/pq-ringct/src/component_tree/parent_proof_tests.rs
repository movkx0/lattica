//! Actual two-wrapper parent proof milestone. This proves one complete AES
//! request, not a full MatRiCT transaction or graph acceptance predicate.
use super::*;
use std::{io::Write, path::Path, time::Instant};

fn report_geometry(phase: &str, geometry: &Geometry) {
    eprintln!(
        "PHASE_GEOMETRY {}",
        serde_json::json!({
            "phase": phase,
            "active_rows": geometry.active_rows,
            "padded_rows": geometry.padded_rows,
            "wires": geometry.wires,
            "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks,
            "constraints": geometry.constraints,
            "max_constraint_degree": geometry.max_constraint_degree,
            "fri_ali_bits": geometry.fri_ali_bits,
            "retained_lde_bytes": geometry.retained_lde_bytes,
        })
    );
}

fn report_time(phase: &str, start: Instant) {
    eprintln!(
        "PHASE_TIME {}",
        serde_json::json!({"phase": phase, "seconds": start.elapsed().as_secs_f64()})
    );
}

/// The test's own fixture roundtrip has a fixed serialized-byte ceiling. This
/// is a diagnostic JSON artifact, not a protocol codec or untrusted decoder.
fn persist_and_roundtrip(key: &NodeKey, proof: NodeProof, label: &str) -> NodeProof {
    const LIMIT: usize = 32 << 20;
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > LIMIT.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other(
                    "component proof artifact exceeds 32 MiB",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, &(&proof.public, &proof.proof)).unwrap();
    // Decode only these locally produced bytes, then independently verify the
    // reconstructed proof against the actual registered source cap.
    let (public, decoded): (Vec<Val>, BatchProof<Config>) =
        serde_json::from_slice(&output.0).unwrap();
    let decoded = NodeProof {
        public,
        proof: decoded,
    };
    key.verify(&decoded).unwrap();
    if let Some(directory) = std::env::var_os("LATTICA_COMPONENT_PARENT_ARTIFACT_DIR") {
        let directory = Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join(format!("{label}.json")), &output.0).unwrap();
    }
    eprintln!(
        "ARTIFACT {}",
        serde_json::json!({"phase": label, "format": "diagnostic-json", "bytes": output.0.len(), "limit_bytes": LIMIT, "roundtrip_verified": true})
    );
    decoded
}

#[test]
#[ignore = "actual two wide recursive leaf proofs and parent proof; exclusive 48 GiB guard required"]
fn actual_two_wrapper_parent_proof_and_constrained_mutation_rejection() {
    use lattica_prover_p3::block_v2::profile;
    let started = Instant::now();
    let descriptor = aes_lane_air::Descriptor {
        domain: 0x4368,
        start_counter: 161,
        output_len: 31,
    };
    let secret = [17; 32];
    let whole = aes_lane_air::AesLaneAir::new(descriptor)
        .unwrap()
        .generate(secret)
        .unwrap();
    let contract = Contract::aes([1; 32], 3, descriptor).unwrap();
    let context = EndpointContext {
        context: [7; 32],
        statement: [Val::from_u32(11); 4],
        input: shake_air::commit_bytes(
            aes_lane_air::AES_INPUT_DOMAIN,
            &descriptor.input_bytes(&secret),
        ),
        output: shake_air::commit_bytes(aes_lane_air::AES_OUTPUT_DOMAIN, &whole.output),
    };
    drop(whole);
    let config = profile::make_config();
    let mut children = Vec::new();
    for first in 0..2 {
        let phase = format!("leaf-{first}");
        let tick = Instant::now();
        let air = aes_lane_air::AesLaneAir::segment(descriptor, first, 1).unwrap();
        let witness = air.generate(secret).unwrap();
        let proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
        p3_uni_stark::verify(&config, &air, &proof, &witness.public_values).unwrap();
        let native = aes_lane_air::join::AesLaneSegmentProof {
            public_values: witness.public_values,
            proof,
        };
        report_time(&format!("{phase}-native-prove-verify"), tick);
        let tick = Instant::now();
        let compiled = compile_aes(&contract, first as u32, 1, &context, &native).unwrap();
        compiled.evaluate().unwrap();
        report_geometry(&phase, &compiled.geometry().unwrap());
        report_time(&format!("{phase}-compile-trace-analyze"), tick);
        drop(native);
        let tick = Instant::now();
        let prepared = compiled.prepare(48_u64 << 30).unwrap();
        let key = prepared.key();
        report_time(&format!("{phase}-register"), tick);
        let tick = Instant::now();
        let proof = prepared.prove().unwrap();
        report_time(&format!("{phase}-outer-prove-verify"), tick);
        // Only the compact verifier/cap and actual proof survive this scope;
        // neither leaf's preprocessing LDE overlaps the next proving phase.
        drop(prepared);
        let proof = persist_and_roundtrip(&key, proof, &phase);
        assert!(key.verify_request(&proof, &context).is_err());
        children.push((key, proof));
    }
    let tick = Instant::now();
    let (left, right) = (&children[0], &children[1]);
    assert!(compile_merge(&left.0, &left.0, [&left.1, &left.1]).is_err());
    assert!(compile_merge(&right.0, &left.0, [&right.1, &left.1]).is_err());
    if let Ok(swapped) = compile_merge(&left.0, &right.0, [&right.1, &left.1]) {
        assert!(swapped.evaluate().is_err());
    }
    let mut compiled = compile_merge(&left.0, &right.0, [&left.1, &right.1]).unwrap();
    compiled.evaluate().unwrap();
    report_geometry("parent", &compiled.geometry().unwrap());
    report_time("parent-compile-trace-analyze", tick);

    let tick = Instant::now();
    // Exercise the actual recursive program, including both full child
    // verifiers. The first child public values occupy the first witness slots.
    for index in [
        CONTEXT,
        STATEMENT,
        EXPECTED_INPUT,
        EXPECTED_OUTPUT,
        FIRST,
        COUNT,
        HEADER,
        HEADER + 4,
    ] {
        compiled.witness[index] += Val::ONE;
        assert!(
            compiled.evaluate().is_err(),
            "accepted constrained child mutation {index}"
        );
        compiled.witness[index] -= Val::ONE;
    }
    for index in [
        CONTEXT,
        STATEMENT,
        EXPECTED_INPUT,
        EXPECTED_OUTPUT,
        FIRST,
        COUNT,
        HEADER,
        HEADER + 4,
    ] {
        compiled.public[index] += Val::ONE;
        assert!(
            compiled.evaluate().is_err(),
            "accepted parent public mutation {index}"
        );
        compiled.public[index] -= Val::ONE;
    }
    compiled.evaluate().unwrap();
    report_time("parent-constrained-mutation-rejection", tick);
    drop(children);
    let tick = Instant::now();
    let prepared = compiled.prepare(48_u64 << 30).unwrap();
    let key = prepared.key();
    report_time("parent-register", tick);
    let tick = Instant::now();
    let proof = prepared.prove().unwrap();
    report_time("parent-outer-prove-verify", tick);
    drop(prepared);
    let mut proof = persist_and_roundtrip(&key, proof, "parent");
    key.verify_request(&proof, &context).unwrap();
    for index in [
        CONTEXT,
        STATEMENT,
        EXPECTED_INPUT,
        EXPECTED_OUTPUT,
        FIRST,
        COUNT,
        HEADER,
        HEADER + 4,
    ] {
        proof.public[index] += Val::ONE;
        assert!(
            key.verify(&proof).is_err(),
            "accepted altered proven public field {index}"
        );
        assert!(key.verify_request(&proof, &context).is_err());
        proof.public[index] -= Val::ONE;
    }
    let mut foreign = context.clone();
    foreign.context[0] ^= 1;
    assert!(key.verify_request(&proof, &foreign).is_err());
    foreign = context.clone();
    foreign.statement[0] += Val::ONE;
    assert!(key.verify_request(&proof, &foreign).is_err());
    foreign = context.clone();
    foreign.input[0] += Val::ONE;
    assert!(key.verify_request(&proof, &foreign).is_err());
    foreign = context.clone();
    foreign.output[0] += Val::ONE;
    assert!(key.verify_request(&proof, &foreign).is_err());
    key.verify_request(&proof, &context).unwrap();
    report_time("complete-test", started);
    eprintln!("actual_two_wrapper_parent_verified=true constrained_context_endpoint_order_rejection=true complete_matrict_transaction=false");
}
