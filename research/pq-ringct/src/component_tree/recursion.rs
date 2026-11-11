//! Research multi-child aggregation with pinned low-degree child verifiers.
use super::*;
use lattica_prover_p3::block_v2::machine::recursion::{RecursionExecutionProof, RecursionVerifier};

/// A verified child drops its source program and all GPU preprocessing. Its
/// statement and key can only be paired while the original owner is present.
pub struct ProvenNode {
    spec: Spec,
    public: Vec<Val>,
    key: RecursionVerifier,
    proof: RecursionExecutionProof,
}
impl ProvenNode {
    pub(crate) fn retained_bytes(&self, maximum: usize) -> Result<usize> {
        // Publics, compact AIR descriptors/cap and all inline owner frames.
        let fixed = self
            .public
            .capacity()
            .checked_mul(core::mem::size_of::<Val>())
            .and_then(|n| n.checked_add(64 << 10))
            .ok_or_else(|| err("typed retained metadata overflow"))?;
        let remaining = maximum
            .checked_sub(fixed)
            .ok_or_else(|| err("typed retained node limit"))?;
        self.proof
            .retained_backing_bytes(remaining)
            .map_err(err)?
            .checked_add(fixed)
            .ok_or_else(|| err("typed retained node overflow"))
    }
    pub(crate) fn public_values(&self) -> &[Val] {
        &self.public
    }
    pub(crate) fn verify_request(
        &self,
        contract: &Contract,
        context: &EndpointContext,
    ) -> Result<()> {
        require(
            &self.spec.contract == contract
                && self.spec.first == 0
                && self.spec.count == contract.total,
            "incomplete typed request",
        )?;
        let expected = header(&self.spec, context)?;
        require(
            self.public.len() == expected.len() && self.public[..HEADER] == expected[..HEADER],
            "typed request context or endpoints",
        )?;
        self.key.verify(&self.proof, &self.public).map_err(err)
    }
    pub(crate) fn manifest_shape(&self) -> Result<crate::obligation_manifest::CryptoShape> {
        require(
            self.spec.first == 0 && self.spec.count == self.spec.contract.total,
            "incomplete typed request manifest",
        )?;
        let index = self.spec.contract.request;
        Ok(match self.spec.contract.kind {
            Kind::Shake(d) => crate::obligation_manifest::CryptoShape::Shake {
                index,
                input_len: d.input_len,
                output_len: d.output_len,
            },
            Kind::Aes(d) => crate::obligation_manifest::CryptoShape::Aes {
                index,
                domain: d.domain,
                start_counter: d.start_counter,
                output_len: d.output_len,
            },
        })
    }
    pub(crate) fn compile_manifest_record(
        &self,
        b: &mut lattica_prover_p3::block_v2::machine::program::ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        context: &crate::obligation_manifest::ContextWires,
    ) -> Result<[[Wire; 4]; 2]> {
        self.manifest_shape()?;
        let public = inputs.bases(b, &self.public).map_err(err)?;
        self.key
            .constrain(b, inputs, &public, &self.proof)
            .map_err(err)?;
        for (i, expected) in context
            .profile
            .iter()
            .chain(&context.context)
            .chain(&context.statement)
            .enumerate()
        {
            b.assert_equal(public[i], *expected);
        }
        Ok([
            public[EXPECTED_INPUT..EXPECTED_INPUT + 4]
                .try_into()
                .map_err(err)?,
            public[EXPECTED_OUTPUT..EXPECTED_OUTPUT + 4]
                .try_into()
                .map_err(err)?,
        ])
    }
    pub(crate) fn prove_gpu(
        node: CompiledNode,
        cache: &mut lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache,
        limits: lattica_prover_p3::block_v2::machine::recursion::GpuTemplateLimits,
        source_released: impl FnOnce(),
    ) -> Result<(
        Self,
        f64,
        lattica_prover_p3::block_v2::machine::recursion::GpuProofMeasurement,
    )> {
        use lattica_prover_p3::block_v2::machine::recursion::RecursionTemplate;
        let started = std::time::Instant::now();
        let template = RecursionTemplate::new(
            Arc::clone(&node.program),
            crate::graph_proofs::compiled_source_fingerprint(),
        )
        .map_err(err)?;
        let template_seconds = started.elapsed().as_secs_f64();
        let (node, setup_seconds, measurement) =
            Self::prove_prepared_gpu(node, template, cache, limits, source_released)?;
        Ok((node, template_seconds + setup_seconds, measurement))
    }
    pub(crate) fn prove_prepared_gpu(
        node: CompiledNode,
        template: lattica_prover_p3::block_v2::machine::recursion::RecursionTemplate,
        cache: &mut lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache,
        limits: lattica_prover_p3::block_v2::machine::recursion::GpuTemplateLimits,
        source_released: impl FnOnce(),
    ) -> Result<(
        Self,
        f64,
        lattica_prover_p3::block_v2::machine::recursion::GpuProofMeasurement,
    )> {
        require(
            template.matches_program(&node.program),
            "prepared crypto source ownership",
        )?;
        let started = std::time::Instant::now();
        let owner = cache.prepare(template, limits).map_err(err)?;
        let setup_seconds = started.elapsed().as_secs_f64();
        let (node, measurement) = Self::from_cached_gpu(node, owner, source_released)?;
        Ok((node, setup_seconds, measurement))
    }
    pub(crate) fn from_cached_gpu(
        node: CompiledNode,
        owner: lattica_prover_p3::block_v2::machine::recursion::CachedGpuRecursionTemplate<'_>,
        source_released: impl FnOnce(),
    ) -> Result<(
        Self,
        lattica_prover_p3::block_v2::machine::recursion::GpuProofMeasurement,
    )> {
        let key = owner.verifier();
        require(
            key.matches_program(&node.program),
            "cached source ownership",
        )?;
        let CompiledNode {
            spec,
            program,
            public,
            witness,
        } = node;
        drop(program);
        let (proof, measurement) = owner
            .into_prove(&public, &witness, source_released)
            .map_err(err)?;
        Ok((
            Self {
                spec,
                public,
                key,
                proof,
            },
            measurement,
        ))
    }
    pub(crate) fn from_gpu_owner(
        node: CompiledNode,
        owner: lattica_prover_p3::block_v2::machine::recursion::PreparedGpuRecursionTemplate,
        source_released: impl FnOnce(),
    ) -> Result<(
        Self,
        lattica_prover_p3::block_v2::machine::recursion::GpuProofMeasurement,
    )> {
        let key = owner.verifier();
        require(key.matches_program(&node.program), "typed source ownership")?;
        let CompiledNode {
            spec,
            program,
            public,
            witness,
        } = node;
        drop(program);
        let (proof, measurement) = owner
            .into_prove(&public, &witness, source_released)
            .map_err(err)?;
        Ok((
            Self {
                spec,
                public,
                key,
                proof,
            },
            measurement,
        ))
    }
    pub(crate) fn rejects_altered_statement(&self) -> bool {
        let mut wrong = self.public.clone();
        wrong[STATEMENT] += Val::ONE;
        self.key.verify(&self.proof, &wrong).is_err()
    }
    pub(crate) fn new(
        node: CompiledNode,
        key: RecursionVerifier,
        proof: RecursionExecutionProof,
    ) -> Result<Self> {
        require(
            key.matches_program(&node.program),
            "recursion child program ownership",
        )?;
        key.verify(&proof, &node.public).map_err(err)?;
        Ok(Self {
            spec: node.spec,
            public: node.public,
            key,
            proof,
        })
    }
}
pub(crate) fn compile_proven(
    children: &[&ProvenNode],
    limits: ConstructionLimits,
) -> Result<CompiledNode> {
    let children = children
        .iter()
        .map(|n| (&n.spec, n.public.as_slice(), &n.key, &n.proof))
        .collect::<Vec<_>>();
    compile_bound(&children, limits)
}
pub(crate) fn compile_merge(
    children: &[(&CompiledNode, &RecursionVerifier, &RecursionExecutionProof)],
    limits: ConstructionLimits,
) -> Result<CompiledNode> {
    for (node, key, _) in children {
        require(
            key.matches_program(&node.program),
            "recursion child program ownership",
        )?;
    }
    let children = children
        .iter()
        .map(|(n, k, p)| (&n.spec, n.public.as_slice(), *k, *p))
        .collect::<Vec<_>>();
    compile_bound(&children, limits)
}
fn compile_bound(
    children: &[(&Spec, &[Val], &RecursionVerifier, &RecursionExecutionProof)],
    limits: ConstructionLimits,
) -> Result<CompiledNode> {
    require((2..=8).contains(&children.len()), "recursion merge fan-in")?;
    let mut spec = children[0].0.clone();
    for (spec_child, _, _, _) in &children[1..] {
        spec = Spec::merge(&spec, spec_child)?;
    }
    let mut public = children[0].1.to_vec();
    public[FIRST] = Val::from_u32(spec.first);
    public[COUNT] = Val::from_u32(spec.count);
    public[LEVEL] = Val::from_u32(spec.level);
    public[HEADER + 4..].copy_from_slice(&children.last().unwrap().1[HEADER + 4..]);
    let mut b = ProgramBuilder::new_with_construction_limits(spec.width(), limits).map_err(err)?;
    let outer = public_wires(&mut b, &spec)?;
    let mut inputs = ProofInputs::default();
    let mut previous: Option<Vec<Wire>> = None;
    let mut count = b.constant(Val::ZERO);
    for (_, child_public, key, proof) in children {
        require(
            child_public.len() == spec.width(),
            "recursion child public width",
        )?;
        let child = inputs.bases(&mut b, child_public).map_err(err)?;
        key.constrain(&mut b, &mut inputs, &child, proof)
            .map_err(err)?;
        for i in 0..HEADER {
            if ![FIRST, COUNT, LEVEL].contains(&i) {
                b.assert_equal(child[i], outer[i]);
            }
        }
        if let Some(prior) = previous.take() {
            let adjacent = b.add(prior[FIRST], prior[COUNT]);
            b.assert_equal(adjacent, child[FIRST]);
            for i in 0..4 {
                b.assert_equal(prior[HEADER + 4 + i], child[HEADER + i]);
            }
        } else {
            b.assert_equal(child[FIRST], outer[FIRST]);
            for i in 0..4 {
                b.assert_equal(child[HEADER + i], outer[HEADER + i]);
            }
        }
        count = b.add(count, child[COUNT]);
        previous = Some(child);
    }
    b.assert_equal(count, outer[COUNT]);
    let last = previous.unwrap();
    for i in 0..4 {
        b.assert_equal(last[HEADER + 4 + i], outer[HEADER + 4 + i]);
    }
    Ok(CompiledNode {
        spec,
        public,
        program: Arc::new(b.finish(None).map_err(err)?),
        witness: inputs.values,
    })
}

pub(crate) fn require_complete(node: &CompiledNode, contract: &Contract) -> Result<()> {
    require(
        &node.spec.contract == contract
            && node.spec.first == 0
            && node.spec.count == contract.total,
        "incomplete recursion request",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::machine::recursion::RecursionTemplate;

    #[test]
    fn typed_request_bridge_authenticates_shape_context_and_roots() {
        let descriptor = shake_air::Descriptor {
            input_len: 0,
            output_len: 32,
        };
        let contract = Contract::shake([1; 32], 3, descriptor).unwrap();
        let context = EndpointContext {
            context: [7; 32],
            statement: [Val::ONE; 4],
            input: [Val::TWO; 4],
            output: [Val::from_u32(3); 4],
        };
        let spec = contract.span(0, contract.total).unwrap();
        let public = header(&spec, &context).unwrap();
        let mut builder = ProgramBuilder::new(spec.width()).unwrap();
        public_wires(&mut builder, &spec).unwrap();
        let node = CompiledNode {
            spec,
            public,
            program: Arc::new(builder.finish(None).unwrap()),
            witness: vec![],
        };
        let owner = RecursionTemplate::new(Arc::clone(&node.program), [2; 32])
            .unwrap()
            .prepare_cpu_reference()
            .unwrap();
        let proof = owner.prove_cpu_reference(&node.public, &[]).unwrap();
        let node = ProvenNode::new(node, owner.verifier(), proof).unwrap();
        node.verify_request(&contract, &context).unwrap();
        assert!(node.rejects_altered_statement());
        let check = |index, descriptor, mutation| {
            let mut b = ProgramBuilder::new_with_construction_limits(
                0,
                ConstructionLimits {
                    max_requested_program_bytes: 2 << 30,
                    max_wires: 1 << 26,
                    max_input_values: 1 << 20,
                },
            )
            .unwrap();
            let c = crate::obligation_manifest::ContextWires {
                profile: words(&contract.profile).map(|v| b.constant(v)),
                context: words(&context.context).map(|v| b.constant(v)),
                statement: context
                    .statement
                    .map(|v| b.constant(v + if mutation == 1 { Val::ONE } else { Val::ZERO })),
            };
            let input = context.input.map(|v| b.constant(v));
            let output = context
                .output
                .map(|v| b.constant(v + if mutation == 2 { Val::ONE } else { Val::ZERO }));
            let mut inputs = ProofInputs::default();
            crate::request_bridge::verify_shake_request(
                &mut b,
                &mut inputs,
                descriptor,
                &input,
                &output,
                crate::request_bridge::ShakeRequest::TypedTree {
                    node: &node,
                    context: &c,
                    index,
                },
            )
            .map_err(err)?;
            MachineAir::new(b.finish(None).map_err(err)?)
                .trace(&[], &inputs.values)
                .map(|_| ())
                .map_err(err)
        };
        check(3, descriptor, 0).unwrap();
        assert!(check(4, descriptor, 0).is_err());
        assert!(check(
            3,
            shake_air::Descriptor {
                input_len: 1,
                ..descriptor
            },
            0
        )
        .is_err());
        assert!(check(3, descriptor, 1).is_err());
        assert!(check(3, descriptor, 2).is_err());
    }

    #[test]
    fn typed_aes_request_bridge_authenticates_descriptor_context_and_roots() {
        let descriptor = aes_lane_air::Descriptor {
            domain: 0x4368,
            start_counter: 161,
            output_len: 32,
        };
        let contract = Contract::aes([1; 32], 3, descriptor).unwrap();
        let context = EndpointContext {
            context: [7; 32],
            statement: [Val::ONE; 4],
            input: [Val::TWO; 4],
            output: [Val::from_u32(3); 4],
        };
        let spec = contract.span(0, contract.total).unwrap();
        let public = header(&spec, &context).unwrap();
        let mut builder = ProgramBuilder::new(spec.width()).unwrap();
        public_wires(&mut builder, &spec).unwrap();
        let node = CompiledNode {
            spec,
            public,
            program: Arc::new(builder.finish(None).unwrap()),
            witness: vec![],
        };
        let owner = RecursionTemplate::new(Arc::clone(&node.program), [2; 32])
            .unwrap()
            .prepare_cpu_reference()
            .unwrap();
        let proof = owner.prove_cpu_reference(&node.public, &[]).unwrap();
        let node = ProvenNode::new(node, owner.verifier(), proof).unwrap();
        node.verify_request(&contract, &context).unwrap();
        assert!(node.rejects_altered_statement());
        let check = |index, descriptor, mutation| {
            let mut b = ProgramBuilder::new_with_construction_limits(
                0,
                ConstructionLimits {
                    max_requested_program_bytes: 2 << 30,
                    max_wires: 1 << 26,
                    max_input_values: 1 << 20,
                },
            )
            .unwrap();
            let c = crate::obligation_manifest::ContextWires {
                profile: words(&contract.profile)
                    .map(|v| b.constant(v + if mutation == 3 { Val::ONE } else { Val::ZERO })),
                context: words(&context.context)
                    .map(|v| b.constant(v + if mutation == 4 { Val::ONE } else { Val::ZERO })),
                statement: context
                    .statement
                    .map(|v| b.constant(v + if mutation == 1 { Val::ONE } else { Val::ZERO })),
            };
            let input = context
                .input
                .map(|v| b.constant(v + if mutation == 5 { Val::ONE } else { Val::ZERO }));
            let output = context
                .output
                .map(|v| b.constant(v + if mutation == 2 { Val::ONE } else { Val::ZERO }));
            let mut inputs = ProofInputs::default();
            crate::request_bridge::verify_aes_request(
                &mut b,
                &mut inputs,
                descriptor,
                &input,
                &output,
                crate::request_bridge::AesRequest::TypedTree {
                    node: &node,
                    context: &c,
                    index,
                },
            )
            .map_err(err)?;
            MachineAir::new(b.finish(None).map_err(err)?)
                .trace(&[], &inputs.values)
                .map(|_| ())
                .map_err(err)
        };
        check(3, descriptor, 0).unwrap();
        assert!(check(4, descriptor, 0).is_err());
        assert!(check(
            3,
            aes_lane_air::Descriptor {
                domain: 1,
                ..descriptor
            },
            0
        )
        .is_err());
        assert!(check(3, descriptor, 1).is_err());
        assert!(check(3, descriptor, 2).is_err());
        assert!(check(
            3,
            aes_lane_air::Descriptor {
                start_counter: 162,
                ..descriptor
            },
            0
        )
        .is_err());
        assert!(check(
            3,
            aes_lane_air::Descriptor {
                output_len: 31,
                ..descriptor
            },
            0
        )
        .is_err());
        for mutation in 3..=5 {
            assert!(check(3, descriptor, mutation).is_err());
        }
    }

    #[test]
    fn recursion_merge_enforces_coverage_order_context_and_endpoints() {
        // Small predicates isolate the parent bindings; native predicates are
        // exercised separately by the revalidated-archive GPU request profile.
        let contract = Contract::shake(
            [1; 32],
            3,
            shake_air::Descriptor {
                input_len: 7 * 136 + 1,
                output_len: 32,
            },
        )
        .unwrap();
        let context = EndpointContext {
            context: [7; 32],
            statement: [Val::ONE; 4],
            input: [Val::TWO; 4],
            output: [Val::from_u64(3); 4],
        };
        let mut nodes = Vec::new();
        let mut owners = Vec::new();
        let mut keys = Vec::new();
        let mut proofs = Vec::new();
        assert_eq!(contract.total, 8);
        for i in 0..8 {
            let spec = contract.span(i, 1).unwrap();
            let mut public = header(&spec, &context).unwrap();
            public[HEADER..HEADER + 4].fill(Val::from_u32(i));
            public[HEADER + 4..].fill(Val::from_u32(i + 1));
            let mut b = ProgramBuilder::new(spec.width()).unwrap();
            public_wires(&mut b, &spec).unwrap();
            let program = Arc::new(b.finish(None).unwrap());
            let template = RecursionTemplate::new(Arc::clone(&program), [2; 32]).unwrap();
            let owner = template.prepare_cpu_reference().unwrap();
            let proof = owner.prove_cpu_reference(&public, &[]).unwrap();
            keys.push(owner.verifier());
            owners.push(owner);
            proofs.push(proof);
            nodes.push(CompiledNode {
                spec,
                program,
                public,
                witness: vec![],
            });
        }
        let limits = ConstructionLimits {
            // Match the expanded N4 compiler used for eight-child parents.
            max_requested_program_bytes: 6 << 30,
            max_wires: 1 << 26,
            max_input_values: 8 << 20,
        };
        let children: Vec<_> = nodes
            .iter()
            .zip(&keys)
            .zip(&proofs)
            .map(|((n, k), p)| (n, k, p))
            .collect();
        let mut root = compile_merge(&children, limits).unwrap();
        require_complete(&root, &contract).unwrap();
        root.evaluate().unwrap();
        let compact = nodes
            .iter()
            .zip(&owners)
            .map(|(node, owner)| {
                let proof = owner.prove_cpu_reference(&node.public, &[]).unwrap();
                ProvenNode::new(
                    CompiledNode {
                        spec: node.spec.clone(),
                        public: node.public.clone(),
                        program: Arc::clone(&node.program),
                        witness: vec![],
                    },
                    owner.verifier(),
                    proof,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut compact_children = compact.iter().collect::<Vec<_>>();
        let compact_root = compile_proven(&compact_children, limits).unwrap();
        require_complete(&compact_root, &contract).unwrap();
        compact_root.evaluate().unwrap();
        let too_many = compact
            .iter()
            .chain(compact[..1].iter())
            .collect::<Vec<_>>();
        assert!(compile_proven(&too_many, limits).is_err());
        compact_children.swap(0, 1);
        assert!(compile_proven(&compact_children, limits).is_err());
        root.public[COUNT] += Val::ONE;
        assert!(root.evaluate().is_err());
        root.public[COUNT] -= Val::ONE;
        assert!(compile_merge(&[children[1], children[0], children[2]], limits).is_err());
        assert!(compile_merge(&[children[0], children[0], children[2]], limits).is_err());
        assert!(compile_merge(&[children[0], children[2]], limits).is_err());
        let incomplete = compile_merge(&children[..2], limits).unwrap();
        assert!(require_complete(&incomplete, &contract).is_err());
        drop(incomplete);
        drop(root);
        drop(children);
        for column in [HEADER, STATEMENT] {
            nodes[7].public[column] += Val::ONE;
            proofs[7] = owners[7]
                .prove_cpu_reference(&nodes[7].public, &[])
                .unwrap();
            let children: Vec<_> = nodes
                .iter()
                .zip(&keys)
                .zip(&proofs)
                .map(|((n, k), p)| (n, k, p))
                .collect();
            let invalid = compile_merge(&children, limits).unwrap();
            assert!(invalid.evaluate().is_err());
            nodes[7].public[column] -= Val::ONE;
        }
    }
}
