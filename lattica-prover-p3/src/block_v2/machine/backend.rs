//! Native backend for registered execution programs. Not an aggregate verifier.
use super::program::Val;
use super::{ExecutionError, MachineAir};
use crate::block_v2::profile::{self, Config};
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;

pub struct RegisteredProgram {
    air: MachineAir,
    data: ProverData<Config>,
    id: [u64; 4],
    analysis: super::analysis::MachineAnalysis,
}

/// Verification-only state. It contains no preprocessing LDE, program witness,
/// inner proof, or wallet data. The caller must authenticate the supplied cap.
pub struct RegisteredVerifier {
    air: MachineAir,
    common: p3_batch_stark::CommonData<Config>,
}

impl RegisteredVerifier {
    pub(crate) fn from_trusted_cap(
        publics: usize,
        height: usize,
        cap: p3_batch_stark::Commitment<Config>,
    ) -> Result<Self, ExecutionError> {
        use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
        use p3_lookup::{LogUpGadget, Lookups};
        let air = MachineAir::new(super::ProgramBuilder::new(publics)?.finish(Some(height))?);
        let degree = height.ilog2() as usize + 1;
        if cap.roots().len() != 1 << (degree + profile::LOG_BLOWUP).min(profile::CAP_HEIGHT) {
            return Err(ExecutionError::InvalidHeight);
        }
        let gadget = LogUpGadget::new();
        let unpacked = Lookups::from_air::<profile::Challenge, _>(&air);
        let log_chunks =
            p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, profile::Challenge, _, _>(
                &air,
                AirLayout::from_air::<Val>(&air),
                &unpacked,
                1,
                &gadget,
            );
        if log_chunks > profile::LOG_BLOWUP {
            return Err(ExecutionError::InvalidHeight);
        }
        let common = p3_batch_stark::CommonData {
            preprocessed: Some(GlobalPreprocessed {
                commitment: cap,
                instances: vec![Some(PreprocessedInstanceMeta {
                    matrix_index: 0,
                    width: air.preprocessed_width(),
                    degree_bits: degree,
                })],
                matrix_to_instance: vec![0],
            }),
            lookups: vec![unpacked.pack_same_bus(&gadget, 1 << log_chunks)],
        };
        Ok(Self { air, common })
    }

    pub fn verify(&self, proof: &BatchProof<Config>, public: &[Val]) -> Result<(), String> {
        verify_registered(&self.air, &self.common, proof, public)
    }
}

fn verify_registered(
    air: &MachineAir,
    common: &p3_batch_stark::CommonData<Config>,
    proof: &BatchProof<Config>,
    public: &[Val],
) -> Result<(), String> {
    if public.len() != air.program().public_values() {
        return Err("public input count".into());
    }
    if proof.degree_bits != [air.program().height().ilog2() as usize + 1] {
        return Err("unregistered degree".into());
    }
    if proof.lookup_terminals.len() != 1
        || !proof.lookup_terminals[0]
            .as_ref()
            .is_some_and(|t| t.0 == profile::Challenge::ZERO)
    {
        return Err("single-table lookup terminal must be zero".into());
    }
    verify_batch(
        &profile::make_config(),
        core::slice::from_ref(air),
        proof,
        &[public.to_vec()],
        common,
    )
    .map_err(|e| format!("{e:?}"))
}

impl RegisteredProgram {
    pub fn new(air: MachineAir) -> Result<Self, super::analysis::AdmissionError> {
        Self::new_with_memory_budget(air, super::super::feasibility::RAM_BUDGET_BYTES)
    }

    /// Research callers pass the admitted worker allocation. This lower-bound
    /// check does not replace phase-aware host/spill/GPU admission.
    pub fn new_with_memory_budget(
        air: MachineAir,
        budget: u64,
    ) -> Result<Self, super::analysis::AdmissionError> {
        let _phase =
            tracing::info_span!(target: "lattica_block_v2_perf", "preprocessing setup").entered();
        let analysis = super::analysis::analyze(&air)?;
        analysis.check_ram_lower_bound_with_budget(budget)?;
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if super::super::resident_pcs::compact_prover_data() {
            assert!(
                analysis.quotient_chunks <= (1 << profile::LOG_BLOWUP),
                "compact prover data requires quotient domain within half LDE"
            );
        }
        let data = ProverData::from_airs_and_degrees(
            &profile::preprocessing_config(),
            core::slice::from_ref(&air),
            &[air.program().height().ilog2() as usize + 1],
        );
        // An execution-program identity, NOT the not-yet-defined recursive
        // profile identity. Bind parameters, program, AIR and lookup constraints,
        // including their emission order, and deterministic preprocessing key.
        let mut manifest = vec![
            1,
            super::WIDTH as u64,
            air.preprocessed_width() as u64,
            profile::LOG_BLOWUP as u64,
            profile::NUM_QUERIES as u64,
            profile::CAP_HEIGHT as u64,
            profile::NUM_RANDOM_CODEWORDS as u64,
            profile::QUERY_POW_BITS as u64,
            3,
            1,
        ];
        manifest.extend(air.program().manifest_fields());
        // Goldilocks modulus (u32 limbs), cubic X^3-X-1, hash geometry,
        // MMCS salt width, zero commit PoW and prefix-free duplex revision.
        manifest.extend([
            1,
            0xffff_ffff,
            3,
            crate::block_v2::commitment::MODULUS - 1,
            crate::block_v2::commitment::MODULUS - 1,
            0,
            1,
            8,
            4,
            4,
            4,
            0,
            1,
            analysis.permutation_width_base as u64,
            analysis.quotient_chunks as u64,
            analysis.constraints as u64,
            analysis.max_constraint_degree as u64,
            analysis.query_multiplicity_bound,
        ]);
        let lookup = &data.common.lookups[0];
        let constraints =
            p3_batch_stark::symbolic::get_symbolic_constraints::<Val, profile::Challenge, _, _>(
                &air,
                AirLayout::from_air::<Val>(&air),
                lookup,
                &p3_lookup::LogUpGadget::new(),
            );
        let layout = p3_batch_stark::symbolic::get_constraint_layout::<Val, profile::Challenge, _, _>(
            &air,
            AirLayout::from_air::<Val>(&air),
            lookup,
            &p3_lookup::LogUpGadget::new(),
        );
        manifest.extend(super::fingerprint::encode(
            &constraints.0,
            &constraints.1,
            &layout,
        ));
        let prep = data
            .common
            .preprocessed
            .as_ref()
            .expect("machine always has preprocessing");
        for root in prep.commitment.roots() {
            manifest.extend(root.iter().map(|x| x.as_canonical_u64()));
        }
        let id = crate::block_v2::commitment::hash_fields(0x4c42563210, &manifest)
            .expect("canonical program metadata");
        Ok(Self {
            air,
            data,
            id,
            analysis,
        })
    }
    pub fn air(&self) -> &MachineAir {
        &self.air
    }
    pub fn id(&self) -> [u64; 4] {
        self.id
    }
    /// Trusted public preprocessing key. Recursive callers must authenticate
    /// this cap against their registered-program policy, never a proof header.
    pub fn preprocessing_cap(&self) -> &p3_batch_stark::Commitment<Config> {
        &self
            .data
            .common
            .preprocessed
            .as_ref()
            .expect("machine preprocessing")
            .commitment
    }
    pub fn analysis(&self) -> &super::analysis::MachineAnalysis {
        &self.analysis
    }
    pub fn verifier(&self) -> RegisteredVerifier {
        RegisteredVerifier::from_trusted_cap(
            self.air.program().public_values(),
            self.air.program().height(),
            self.preprocessing_cap().clone(),
        )
        .expect("registered program has validated geometry")
    }
    pub fn prove(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<BatchProof<Config>, ExecutionError> {
        let trace = tracing::info_span!(target: "lattica_block_v2_perf", "execution trace")
            .in_scope(|| self.air.trace(public, witness))?;
        let instance = StarkInstance {
            air: &self.air,
            trace: &trace,
            public_values: public.to_vec(),
        };
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if super::super::quotient_pcs::gpu_quotient_enabled() {
            return Ok(
                tracing::info_span!(target: "lattica_block_v2_perf", "native batch prove")
                    .in_scope(|| {
                        super::super::gpu_quotient_prover::prove_batch(
                            &profile::make_proving_config(),
                            &[instance],
                            &self.data,
                            |data| {
                                super::super::gpu_hash::CandidateMmcs::release_quotient_prefix(data)
                            },
                            |pcs, groups| {
                                pcs.commit_quotient_evaluations(groups)
                                    .expect("GPU quotient commitment failed; no silent fallback")
                            },
                        )
                    }),
            );
        }
        Ok(
            tracing::info_span!(target: "lattica_block_v2_perf", "native batch prove")
                .in_scope(|| prove_batch(&profile::make_proving_config(), &[instance], &self.data)),
        )
    }
    pub fn verify(&self, proof: &BatchProof<Config>, public: &[Val]) -> Result<(), String> {
        verify_registered(&self.air, &self.data.common, proof, public)
    }
}

#[cfg(test)]
mod tests {
    use super::super::air::{a_column, b_column, c_column};
    use super::*;
    use crate::block_v2::machine::ProgramBuilder;
    use p3_field::{BasedVectorSpace, Field};
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_symmetric::Permutation;

    #[test]
    fn standalone_verifier_uses_only_the_trusted_cap_and_public_statement() {
        // Exercise both public-count banks, including the highest supported slot.
        let mut b = ProgramBuilder::new(64).unwrap();
        for i in 0..64 {
            let public = b.public(i).unwrap();
            let input = b.input();
            b.assert_equal(public, input);
        }
        let registered = RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
        let public: Vec<_> = (17..81).map(Val::from_u64).collect();
        let proof = registered.prove(&public, &public).unwrap();
        let verifier = registered.verifier();
        drop(registered); // No prover state, preprocessed LDE, or program is retained.
        assert_eq!(verifier.air.program().active_rows(), 2);
        verifier.verify(&proof, &public).unwrap();
        let mut wrong = public;
        wrong[63] += Val::ONE;
        assert!(verifier.verify(&proof, &wrong).is_err());
    }

    #[test]
    fn hinted_merkle_cap_paths_are_constrained_in_the_proof() {
        use super::super::program::{Op, Row};
        use p3_symmetric::CryptographicHasher;
        let leaf = crate::config::MyHash::new(default_goldilocks_poseidon2_8()).hash_iter([
            Val::ONE,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
        ]);
        let mut b = ProgramBuilder::new(1).unwrap();
        let bit = b.public(0).unwrap();
        let row = b.input();
        let zero = b.constant(Val::ZERO);
        let cap = [leaf.map(|v| b.constant(v)), [zero; 4]];
        b.authenticate_equal_height_mmcs(&cap, &[bit], &[vec![row]], &[[zero; 4]], &[])
            .unwrap();
        let registered = RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
        let public = [Val::ZERO];
        let proof = registered.prove(&public, &[Val::ONE]).unwrap();
        registered.verify(&proof, &public).unwrap();
        assert!(registered.verify(&proof, &[Val::ONE]).is_err());
        let clean = registered.air.trace(&public, &[Val::ONE]).unwrap();
        let mut hints = 0;
        for (r, row) in registered.air.program.rows.iter().enumerate() {
            if let Row::Alu(ops) = row {
                for (lane, op) in ops.iter().enumerate() {
                    if matches!(op, Op::SelectHint { .. }) {
                        hints += 1;
                        let mut trace = clean.clone();
                        trace.values[r * super::super::WIDTH + c_column(lane)] += Val::ONE;
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            prove_batch(
                                &profile::make_config(),
                                &[StarkInstance {
                                    air: &registered.air,
                                    trace: &trace,
                                    public_values: public.to_vec(),
                                }],
                                &registered.data,
                            )
                        }));
                        if let Ok(proof) = result {
                            assert!(registered.verify(&proof, &public).is_err());
                        }
                    }
                }
            }
        }
        assert_eq!(hints, 4);
    }

    #[test]
    fn cubic_and_selection_instructions_are_proved() {
        for bit in [0, 1] {
            let mut b = ProgramBuilder::new(3).unwrap();
            let a = core::array::from_fn(|_| b.input());
            let c = core::array::from_fn(|_| b.input());
            let select = b.input();
            let product = b.ext_mul(a, c);
            let inverse = b.ext_inverse(a);
            let unit = b.ext_mul(a, inverse);
            let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
            b.ext_assert_equal(unit, one);
            let chosen = b.ext_select(select, product, inverse);
            for (i, &w) in chosen.iter().enumerate() {
                let public = b.public(i).unwrap();
                b.assert_equal(w, public);
            }
            let registered =
                RegisteredProgram::new(MachineAir::new(b.finish(None).unwrap())).unwrap();
            let av = [17, 31, 47].map(Val::from_u64);
            let cv = [59, 71, 97].map(Val::from_u64);
            let a = profile::Challenge::from_basis_coefficients_slice(&av).unwrap();
            let c = profile::Challenge::from_basis_coefficients_slice(&cv).unwrap();
            let result = if bit == 0 { a * c } else { a.inverse() };
            let public = result.as_basis_coefficients_slice();
            let mut witness = av
                .into_iter()
                .chain(cv)
                .chain([Val::from_u64(bit)])
                .collect::<Vec<_>>();
            let proof = registered.prove(public, &witness).unwrap();
            registered.verify(&proof, public).unwrap();
            let mut wrong = public.to_vec();
            wrong[1] += Val::ONE;
            assert!(registered.verify(&proof, &wrong).is_err());
            witness[6] = Val::from_u64(2);
            assert!(registered.prove(public, &witness).is_err());
            witness[6] = Val::ZERO;
            witness[..3].fill(Val::ZERO);
            assert!(registered.prove(public, &witness).is_err());

            // Bypass the interpreter to test the AIR, not just witness generation.
            let witness = av
                .into_iter()
                .chain(cv)
                .chain([Val::from_u64(bit)])
                .collect::<Vec<_>>();
            let clean = registered.air.trace(public, &witness).unwrap();
            for (row, kind) in registered.air.program.rows.iter().enumerate() {
                if let super::super::program::Row::Cubic(_) = kind {
                    let mut trace = clean.clone();
                    trace.values[row * super::super::WIDTH + c_column(0)] += Val::ONE;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        prove_batch(
                            &profile::make_config(),
                            &[StarkInstance {
                                air: &registered.air,
                                trace: &trace,
                                public_values: public.to_vec(),
                            }],
                            &registered.data,
                        )
                    }));
                    if let Ok(proof) = result {
                        assert!(registered.verify(&proof, public).is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn arithmetic_and_hash_execution_proof() {
        let mut b = ProgramBuilder::new(8).unwrap();
        let x = b.input();
        let y = b.input();
        let sum = b.add(x, y);
        let product = b.mul(x, sum);
        let inverse = b.inverse(product);
        let one = b.mul(product, inverse);
        let c1 = b.constant(Val::ONE);
        b.assert_equal(one, c1);
        let zero = b.constant(Val::ZERO);
        b.assert_bool(zero);
        let input = [sum, product, inverse, one, x, y, zero, c1];
        let hash = b.poseidon(input);
        for (i, w) in hash.iter().enumerate() {
            let public = b.public(i).unwrap();
            b.assert_equal(*w, public);
        }
        let program = b.finish(None).unwrap();
        let registered = RegisteredProgram::new(MachineAir::new(program)).unwrap();
        let x = Val::from_u64(19);
        let y = Val::from_u64(23);
        let product = x * (x + y);
        use p3_field::Field;
        let mut public = [
            x + y,
            product,
            product.inverse(),
            Val::ONE,
            x,
            y,
            Val::ZERO,
            Val::ONE,
        ];
        default_goldilocks_poseidon2_8().permute_mut(&mut public);
        let mut proof = registered.prove(&public, &[x, y]).unwrap();
        registered.verify(&proof, &public).unwrap();
        let mut wrong = public;
        wrong[0] += Val::ONE;
        assert!(registered.verify(&proof, &wrong).is_err());
        proof.lookup_terminals[0].as_mut().unwrap().0 += profile::Challenge::ONE;
        assert!(registered.verify(&proof, &public).is_err());
    }

    #[cfg(feature = "block-v2-wide-lanes")]
    #[test]
    fn wide_lane_overlap_and_padding_mutations_are_rejected_by_real_proofs() {
        use super::super::air::d_column;
        use super::super::program::{Op, Row, EXT_LANES, LANES};
        use super::super::WIDTH;
        assert_eq!((LANES, EXT_LANES), (23, 7));
        let mut b = ProgramBuilder::new(8).unwrap();
        let inputs: Vec<_> = (0..LANES * 2).map(|_| b.input()).collect();
        let bit = b.input();
        for i in 0..LANES {
            b.add(inputs[i], inputs[i + 1]);
            b.mul(inputs[i], inputs[i + 1]);
            b.select(bit, inputs[i], inputs[i + 1]);
            b.inverse(inputs[i]);
        }
        for group in 0..EXT_LANES {
            let a = core::array::from_fn(|i| inputs[group * 3 + i]);
            let c = core::array::from_fn(|i| inputs[i]);
            b.cubic_mul(a, c);
            b.cubic_inverse(a);
        }
        let hash = b.poseidon(core::array::from_fn(|i| inputs[i]));
        for (i, value) in hash.into_iter().enumerate() {
            let public = b.public(i).unwrap();
            b.assert_equal(value, public);
        }
        let program = b.finish(Some(32)).unwrap();
        let hash_row = program
            .rows
            .iter()
            .position(|r| matches!(r, Row::Poseidon { .. }))
            .unwrap();
        let cubic_row = program
            .rows
            .iter()
            .position(|r| matches!(r, Row::Cubic(ops) if ops.len() == EXT_LANES))
            .unwrap();
        let alu_row = program.rows.iter().position(|r| matches!(r, Row::Alu(ops)
            if ops.len() == LANES && matches!(ops.last(), Some(Op::Add { .. } | Op::Mul { .. } | Op::Inverse { .. } | Op::Select { .. })))).unwrap();
        let padding_row = program.active_rows();
        assert!(padding_row < program.height());
        let mut witness: Vec<_> = (0..LANES * 2).map(|i| Val::from_usize(i + 2)).collect();
        witness.push(Val::ONE);
        let mut public = core::array::from_fn::<_, 8, _>(|i| Val::from_usize(i + 2));
        default_goldilocks_poseidon2_8().permute_mut(&mut public);
        let registered = RegisteredProgram::new(MachineAir::new(program)).unwrap();
        assert_eq!(registered.analysis().max_constraint_degree, 8);
        let proof = registered.prove(&public, &witness).unwrap();
        registered.verify(&proof, &public).unwrap();
        assert_eq!(proof.lookup_terminals.len(), 1);
        assert_eq!(
            proof.lookup_terminals[0].as_ref().unwrap().0,
            profile::Challenge::ZERO
        );
        let clean = registered.air.trace(&public, &witness).unwrap();
        // Bypass the interpreter: mutate active high lanes, overlapping fixed
        // hash checkpoints, unused arithmetic tail cells, public and padding rows.
        let mutations = [
            (alu_row, c_column(LANES - 1)),
            (alu_row, 4 * LANES),
            (cubic_row, c_column(3 * (EXT_LANES - 1))),
            (cubic_row, d_column(LANES - 1)),
            (hash_row, a_column(0)),
            (hash_row, b_column(0)),
            (hash_row, c_column(0)),
            (hash_row, d_column(0)),
            (hash_row, a_column(LANES - 1)),
            (hash_row, c_column(LANES - 1)),
            (hash_row, WIDTH - 1),
            (0, c_column(LANES - 1)),
            (padding_row, a_column(0)),
            (padding_row, a_column(LANES - 1)),
            (padding_row, b_column(LANES - 1)),
            (padding_row, c_column(LANES - 1)),
            (padding_row, WIDTH - 1),
        ];
        assert_eq!(mutations.len(), 17);
        assert_eq!(
            mutations
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            mutations.len()
        );
        for (row, column) in mutations {
            let mut trace = clean.clone();
            trace.values[row * WIDTH + column] += Val::ONE;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_batch(
                    &profile::make_config(),
                    &[StarkInstance {
                        air: &registered.air,
                        trace: &trace,
                        public_values: public.to_vec(),
                    }],
                    &registered.data,
                )
            }));
            if let Ok(proof) = result {
                assert!(
                    registered.verify(&proof, &public).is_err(),
                    "accepted mutation row={row} column={column}"
                );
            }
        }
    }

    fn copy_program(constant: u64, height: Option<usize>) -> MachineAir {
        let mut b = ProgramBuilder::new(1).unwrap();
        let x = b.input();
        let c = b.constant(Val::from_u64(constant));
        let y = b.add(x, c);
        let public = b.public(0).unwrap();
        b.assert_equal(y, public);
        MachineAir::new(b.finish(height).unwrap())
    }

    #[test]
    fn registration_is_deterministic_and_rejects_key_substitution() {
        let a = RegisteredProgram::new(copy_program(7, None)).unwrap();
        let b = RegisteredProgram::new(copy_program(7, None)).unwrap();
        let c = RegisteredProgram::new(copy_program(8, None)).unwrap();
        assert_eq!(a.id(), b.id());
        assert_ne!(a.id(), c.id());
        let public = [Val::from_u64(12)];
        let witness = [Val::from_u64(5)];
        let proof = a.prove(&public, &witness).unwrap();
        b.verify(&proof, &public).unwrap();
        assert!(c.verify(&proof, &public).is_err());
        let second = a.prove(&public, &witness).unwrap();
        assert_ne!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&second).unwrap()
        );
        let analysis = a.analysis();
        assert!(analysis.constraints > 100);
        assert!(analysis.permutation_width_base > 0);
        assert!(analysis.max_constraint_degree >= 8);
        assert!(analysis.fri_ali_bits >= 100); // Still NOT total lookup/composition security.
    }

    #[test]
    fn rejects_unconstrained_copy_and_program_tampering() {
        let registered = RegisteredProgram::new(copy_program(7, None)).unwrap();
        let public = vec![Val::from_u64(12)];
        let mut trace = registered.air.trace(&public, &[Val::from_u64(5)]).unwrap();
        // First ALU row lanes: input, constant, add, assert_equal. Change the add's
        // reads and matching local output/assertion so its algebra remains true,
        // but make the read disagree with the wire's unique definition.
        let row = registered
            .air
            .program
            .rows
            .iter()
            .position(|row| matches!(row, super::super::program::Row::Alu(_)))
            .unwrap();
        trace.values[row * super::super::WIDTH + a_column(2)] += Val::ONE; // x becomes x+1
        trace.values[row * super::super::WIDTH + b_column(2)] -= Val::ONE; // 7 becomes 6
                                                                           // Debug prover intentionally panics on a bad lookup witness; release
                                                                           // emits an invalid proof. Both are rejections, never a valid aggregate.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_batch(
                &profile::make_config(),
                &[StarkInstance {
                    air: &registered.air,
                    trace: &trace,
                    public_values: public.clone(),
                }],
                &registered.data,
            )
        }));
        if let Ok(proof) = result {
            assert!(registered.verify(&proof, &public).is_err());
        }

        let mut proof = registered.prove(&public, &[Val::from_u64(5)]).unwrap();
        proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
        assert!(registered.verify(&proof, &public).is_err());
        proof.degree_bits[0] += 1;
        assert!(registered.verify(&proof, &public).is_err());
    }

    #[test]
    fn resource_rejection_precedes_preprocessing_allocation() {
        let air = copy_program(7, Some(1 << 24));
        assert!(matches!(
            RegisteredProgram::new(air),
            Err(super::super::analysis::AdmissionError::RamLowerBound { .. })
        ));
    }
}
