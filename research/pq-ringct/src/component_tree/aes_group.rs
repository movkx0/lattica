//! Direct recursion over unchanged serial AES native segments. A single outer
//! proof checks the whole contiguous batch, avoiding singleton/binary wrappers.
use super::*;
use core::mem::size_of;

pub(crate) struct Member<'a> {
    pub first: u32,
    pub count: u32,
    pub proof: &'a aes_lane_air::join::AesLaneSegmentProof,
}

fn check_spans(contract: &Contract, spans: impl Iterator<Item = (u32, u32)>) -> Result<Spec> {
    require(
        matches!(contract.kind, Kind::Aes(_)),
        "AES group contract family",
    )?;
    let mut spans = spans.peekable();
    let first = spans.peek().ok_or_else(|| err("empty AES group"))?.0;
    let mut end = first;
    let mut members = 0;
    for (start, count) in spans {
        require(
            start == end,
            "missing, duplicate, overlapping or reordered AES segment",
        )?;
        end = contract.span(start, count)?.end();
        members += 1;
        require(members <= 16, "AES native group limit")?;
    }
    contract.span(first, end - first)
}

pub(crate) fn compile(
    contract: &Contract,
    members: &[Member<'_>],
    context: &EndpointContext,
    limits: ConstructionLimits,
) -> Result<CompiledNode> {
    let spec = check_spans(contract, members.iter().map(|m| (m.first, m.count)))?;
    let Kind::Aes(descriptor) = contract.kind else {
        unreachable!()
    };
    // The scheduler reserves 512 MiB of auxiliary backing in addition to the
    // bounded program. Pin the input ceiling and fixed AIR before allocating:
    // 2*Val + Wire per input, the symbolic recorder/graph, and <1 MiB of fixed
    // periodic/endpoint helpers all fit that reservation.
    let symbolic = verifier::uni::BoundedSymbolicAllowance::REQUIRED;
    let auxiliary = limits
        .max_input_values
        .checked_mul(2 * size_of::<Val>() + size_of::<Wire>())
        .and_then(|n| n.checked_add(symbolic.workspace_bytes))
        .and_then(|n| n.checked_add(symbolic.retained_graph_bytes))
        .and_then(|n| n.checked_add(1 << 20))
        .ok_or_else(|| err("AES compiler auxiliary overflow"))?;
    require(
        limits.max_input_values <= 8 << 20 && auxiliary <= 512 << 20,
        "AES compiler auxiliary allowance",
    )?;
    for (i, member) in members.iter().enumerate() {
        require(
            member.proof.public_values[..4] == context.input,
            "AES native input commitment",
        )?;
        if i > 0 {
            require(
                members[i - 1].proof.public_values[8..12] == member.proof.public_values[4..8],
                "AES native endpoint discontinuity",
            )?;
        }
    }
    with_endpoint_preparation(None, |endpoint_root| {
        let mut public = header(&spec, context)?;
        public[HEADER..HEADER + 4].copy_from_slice(&endpoint_root(
            contract,
            &members[0].proof.public_values[4..8],
        )?);
        public[HEADER + 4..].copy_from_slice(&endpoint_root(
            contract,
            &members.last().unwrap().proof.public_values[8..12],
        )?);
        let mut b =
            ProgramBuilder::new_with_construction_limits(spec.width(), limits).map_err(err)?;
        let outer = public_wires(&mut b, &spec)?;
        let mut inputs = ProofInputs::default();
        let mut initial = None;
        let mut previous: Option<[Wire; 4]> = None;
        for member in members {
            let air = aes_lane_air::AesLaneAir::segment(
                descriptor,
                member.first as usize,
                member.count as usize,
            )
            .map_err(err)?;
            let columns = air.periodic_columns();
            require(
                columns.len() == 31 && columns.iter().all(|column| column.len() == 64),
                "AES periodic geometry",
            )?;
            let child = inputs
                .bases(&mut b, &member.proof.public_values)
                .map_err(err)?;
            verifier::uni::verify_bounded(
                &mut b,
                &mut inputs,
                &air,
                air.height,
                &child,
                &member.proof.proof,
                &columns,
                symbolic,
            )
            .map_err(err)?;
            for i in 0..4 {
                b.assert_equal(
                    child[aes_lane_air::INPUT_COMMITMENT + i],
                    outer[EXPECTED_INPUT + i],
                );
                if let Some(prior) = previous {
                    b.assert_equal(prior[i], child[aes_lane_air::OUTPUT_START + i]);
                }
            }
            if initial.is_none() {
                initial = Some(<[Wire; 4]>::try_from(&child[4..8]).map_err(err)?);
            }
            previous = Some(child[8..12].try_into().map_err(err)?);
        }
        bind_endpoints(&mut b, &spec, &outer, &initial.unwrap(), &previous.unwrap());
        Ok(CompiledNode {
            spec,
            program: Arc::new(b.finish(None).map_err(err)?),
            public,
            witness: inputs.values,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aes_batch_requires_exact_contiguous_coverage() {
        let contract = Contract::aes(
            [1; 32],
            3,
            aes_lane_air::Descriptor {
                domain: 0x4368,
                start_counter: 161,
                output_len: 64,
            },
        )
        .unwrap();
        let full = check_spans(&contract, [(0, 2), (2, 2)].into_iter()).unwrap();
        assert_eq!((full.first, full.count), (0, 4));
        for bad in [
            vec![],
            vec![(0, 0)],
            vec![(0, 2), (1, 2)],
            vec![(2, 2), (0, 2)],
            vec![(0, 1), (2, 2)],
            vec![(0, 4), (4, 1)],
            vec![(u32::MAX, 2)],
        ] {
            assert!(check_spans(&contract, bad.into_iter()).is_err());
        }
        let shake = Contract::shake(
            [1; 32],
            3,
            shake_air::Descriptor {
                input_len: 0,
                output_len: 32,
            },
        )
        .unwrap();
        assert!(check_spans(&shake, [(0, 1)].into_iter()).is_err());
    }

    #[test]
    fn complete_aes_batch_constrains_initial_state_and_final_output() {
        let descriptor = aes_lane_air::Descriptor {
            domain: 0x4368,
            start_counter: 161,
            output_len: 64,
        };
        let contract = Contract::aes([1; 32], 3, descriptor).unwrap();
        let context = EndpointContext {
            context: [7; 32],
            statement: [Val::ONE; 4],
            input: [Val::TWO; 4],
            output: [Val::from_u32(3); 4],
        };
        let spec = check_spans(&contract, [(0, 2), (2, 2)].into_iter()).unwrap();
        let start = [
            Val::from_u64(aes_lane_air::AES_OUTPUT_DOMAIN),
            Val::from_usize(64),
            Val::ZERO,
            Val::ZERO,
        ];
        let end = context.output;
        let mut public = header(&spec, &context).unwrap();
        public[HEADER..HEADER + 4].copy_from_slice(&endpoint_root(&contract, &start).unwrap());
        public[HEADER + 4..].copy_from_slice(&endpoint_root(&contract, &end).unwrap());
        let mut b = ProgramBuilder::new(spec.width()).unwrap();
        let outer = public_wires(&mut b, &spec).unwrap();
        let mut inputs = ProofInputs::default();
        let start_wires = inputs.bases(&mut b, &start).unwrap();
        let end_wires = inputs.bases(&mut b, &end).unwrap();
        bind_endpoints(&mut b, &spec, &outer, &start_wires, &end_wires);
        let air = MachineAir::new(b.finish(None).unwrap());
        air.trace(&public, &inputs.values).unwrap();
        for column in 0..8 {
            let mut wrong = inputs.values.clone();
            wrong[column] += Val::ONE;
            // Even matching claimed endpoint hashes cannot change the full
            // request's initial accumulator or expected final output.
            let mut claimed = public.clone();
            claimed[HEADER..HEADER + 4]
                .copy_from_slice(&endpoint_root(&contract, &wrong[..4]).unwrap());
            claimed[HEADER + 4..].copy_from_slice(&endpoint_root(&contract, &wrong[4..]).unwrap());
            assert!(air.trace(&claimed, &wrong).is_err());
        }
    }
}
