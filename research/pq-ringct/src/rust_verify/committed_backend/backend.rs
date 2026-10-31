use super::*;
impl Backend for CommittedBackend<'_> {
    type Residue = ResidueRef;
    type Signed = SignedRef;
    type Byte = ByteRef;
    fn constant(&mut self, value: u64, q: u64) -> ResidueRef {
        assert!(matches!(q, Q | QHAT));
        // Constants belong to the public expression topology, never a private
        // value. Their canonical encoding is static metadata in both modes.
        let value = value % q;
        let expr = if let Some(&expr) = self.constants.get(&(q, value)) {
            expr
        } else {
            let expr = self.expression(Expression::CanonicalConstant { modulus: q, value });
            self.constants.insert((q, value), expr);
            expr
        };
        ResidueRef {
            owner: self.graph.owner,
            expr,
            modulus: q,
            value,
        }
    }
    fn add(&mut self, a: ResidueRef, b: ResidueRef, q: u64) -> ResidueRef {
        self.check_residue(a, q);
        self.check_residue(b, q);
        let value = witness_value!(self, device => device.canonical_add(a.value, b.value, q),
            arithmetic::add(a.value, b.value, q), 0);
        if self.canonical_constant(a).is_some() && self.canonical_constant(b).is_some() {
            return self.constant(value, q);
        }
        let expr = self.expression(Expression::Add {
            left: a.expr,
            right: b.expr,
            modulus: q,
        });
        ResidueRef {
            owner: self.graph.owner,
            expr,
            modulus: q,
            value,
        }
    }
    fn sub(&mut self, a: ResidueRef, b: ResidueRef, q: u64) -> ResidueRef {
        self.check_residue(a, q);
        self.check_residue(b, q);
        let value = witness_value!(self, device => device.canonical_sub(a.value, b.value, q),
            arithmetic::sub(a.value, b.value, q), 0);
        if self.canonical_constant(a).is_some() && self.canonical_constant(b).is_some() {
            return self.constant(value, q);
        }
        let expr = self.expression(Expression::Sub {
            left: a.expr,
            right: b.expr,
            modulus: q,
        });
        ResidueRef {
            owner: self.graph.owner,
            expr,
            modulus: q,
            value,
        }
    }
    fn mont(&mut self, a: ResidueRef, b: ResidueRef, q: u64) -> ResidueRef {
        self.check_residue(a, q);
        self.check_residue(b, q);
        let value = witness_value!(self, device => device.canonical_mont(a.value, b.value, q),
            arithmetic::mont(a.value, b.value, q), 0);
        let (input, constant) = match (self.canonical_constant(a), self.canonical_constant(b)) {
            (Some(_), Some(_)) => return self.constant(value, q),
            (Some(c), None) => (b.expr, c),
            (None, Some(c)) => (a.expr, c),
            (None, None) => panic!(
                "unsupported scalar product: use a typed whole-polynomial product obligation"
            ),
        };
        // This factor is derived solely from a public constant and defines the
        // symbolic Scale operation; the private product above runs on GPU.
        let factor = arithmetic::mont(1, constant, q);
        let expr = self.expression(Expression::Scale {
            input,
            factor,
            modulus: q,
        });
        ResidueRef {
            owner: self.graph.owner,
            expr,
            modulus: q,
            value,
        }
    }
    fn to_residue(&mut self, a: SignedRef, q: u64) -> ResidueRef {
        self.check_signed(a);
        assert!(
            u64::from(a.bound) < q,
            "signed conversion requires one bounded correction"
        );
        let expr = self.expression(Expression::ConvertCoefficient {
            input: a.expr,
            bound: a.bound,
            modulus: q,
        });
        let value = witness_value!(self, device => device.signed_to_canonical(a.value, q),
            arithmetic::signed(a.value, q), 0);
        ResidueRef {
            owner: self.graph.owner,
            expr,
            modulus: q,
            value,
        }
    }
    fn signed_neg(&mut self, a: SignedRef) -> SignedRef {
        self.check_signed(a);
        let expr = self.expression(Expression::SignedNeg {
            input: a.expr,
            bound: a.bound,
        });
        let value = witness_value!(self, device => device.signed_neg(a.value), -a.value, 0);
        SignedRef {
            owner: self.graph.owner,
            expr,
            bound: a.bound,
            value,
        }
    }
    fn signed_sub(&mut self, a: SignedRef, b: SignedRef) -> SignedRef {
        self.check_signed(a);
        self.check_signed(b);
        let bound = a
            .bound
            .checked_add(b.bound)
            .filter(|&v| v <= i32::MAX as u32)
            .expect("fixed signed affine bound");
        let expr = self.expression(Expression::SignedSub {
            left: a.expr,
            right: b.expr,
            bound,
        });
        let value = witness_value!(self, device => device.signed_sub(a.value, b.value),
            a.value - b.value, 0);
        SignedRef {
            owner: self.graph.owner,
            expr,
            bound,
            value,
        }
    }
    fn add_poly(
        &mut self,
        a: &Polynomial<ResidueRef>,
        b: &Polynomial<ResidueRef>,
        q: u64,
    ) -> Polynomial<ResidueRef> {
        let left = self.canonical_id(a, q);
        let right = self.canonical_id(b, q);
        let values = witness_value!(self,
            device => device.add_poly(&a.map(|v| v.value), &b.map(|v| v.value), q),
            core::array::from_fn(|i| arithmetic::add(a[i].value, b[i].value, q)), [0; D]);
        let output = self.derived_canonical(values, q);
        self.graph.operations.push(Operation::Add {
            modulus: q,
            left,
            right,
            output,
        });
        self.canonical_refs(output)
    }
    fn sub_poly(
        &mut self,
        a: &Polynomial<ResidueRef>,
        b: &Polynomial<ResidueRef>,
        q: u64,
    ) -> Polynomial<ResidueRef> {
        let left = self.canonical_id(a, q);
        let right = self.canonical_id(b, q);
        let values = witness_value!(self,
            device => device.sub_poly(&a.map(|v| v.value), &b.map(|v| v.value), q),
            core::array::from_fn(|i| arithmetic::sub(a[i].value, b[i].value, q)), [0; D]);
        let output = self.derived_canonical(values, q);
        self.graph.operations.push(Operation::Sub {
            modulus: q,
            left,
            right,
            output,
        });
        self.canonical_refs(output)
    }
    fn aut_poly(&mut self, a: &Polynomial<ResidueRef>) -> Polynomial<ResidueRef> {
        let input = self.canonical_id(a, Q);
        let values = witness_value!(self, device => device.aut_poly(&a.map(|v| v.value)),
            arithmetic::aut(&a.map(|v| v.value)), [0; D]);
        let output = self.derived_canonical(values, Q);
        self.graph
            .operations
            .push(Operation::AutomorphismQ { input, output });
        self.canonical_refs(output)
    }
    fn mul_poly(
        &mut self,
        a: &Polynomial<ResidueRef>,
        b: &Polynomial<ResidueRef>,
        q: u64,
    ) -> Polynomial<ResidueRef> {
        let left = self.canonical_id(a, q);
        let right = self.canonical_id(b, q);
        let values = witness_value!(self,
            device => device.mul_poly(&a.map(|v| v.value), &b.map(|v| v.value), q),
            arithmetic::mul(&a.map(|v| v.value), &b.map(|v| v.value), q), [0; D]);
        let output = self.derived_canonical(values, q);
        self.graph.operations.push(Operation::Mul {
            modulus: q,
            left,
            right,
            output,
        });
        self.canonical_refs(output)
    }
    fn ntt_poly(&mut self, a: &Polynomial<SignedRef>, q: u64) -> Polynomial<ResidueRef> {
        let input = self.signed_id(a);
        let bound = a.iter().map(|v| v.bound).max().unwrap();
        assert!(u64::from(bound) < q);
        let values = witness_value!(self,
            device => device.signed_poly_to_canonical(&a.map(|v| v.value), q),
            a.map(|v| arithmetic::signed(v.value, q)), [0; D]);
        let canonical = self.derived_canonical(values, q);
        self.graph.operations.push(Operation::SignedToCanonical {
            bound,
            modulus: q,
            input,
            output: canonical,
        });
        let values = witness_value!(self, device => device.ntt_poly(&a.map(|v| v.value), q),
            arithmetic::ntt(&a.map(|v| v.value), q), [0; D]);
        let output = self.derived_canonical(values, q);
        self.graph.operations.push(Operation::Ntt {
            modulus: q,
            input: canonical,
            output,
        });
        self.canonical_refs(output)
    }
    fn norm(&mut self, a: &[Polynomial<SignedRef>], maximum: u64) -> Result<(), VerifyError> {
        let inputs = a.iter().map(|value| self.signed_id(value)).collect();
        self.graph
            .operations
            .push(Operation::Norm { inputs, maximum });
        Ok(())
    }
    fn g_bound(
        &mut self,
        f: &Polynomial<SignedRef>,
        x: &Polynomial<SignedRef>,
        bound: u32,
    ) -> Result<(), VerifyError> {
        let fb = u128::from(f.iter().map(|v| v.bound).max().unwrap());
        let xb = u128::from(x.iter().map(|v| v.bound).max().unwrap());
        assert!(
            (D as u128) * fb * (fb + xb) + u128::from(bound) < 0xffff_ffff_0000_0001,
            "integer convolution uniqueness"
        );
        let f = self.signed_id(f);
        let x = self.signed_id(x);
        self.graph
            .operations
            .push(Operation::GBound { f, x, bound });
        Ok(())
    }
    fn equal_bytes(&mut self, a: &[ByteRef; 32], b: &[ByteRef; 32]) -> Result<(), VerifyError> {
        let left = self.byte_id(a);
        let right = self.byte_id(b);
        self.graph
            .operations
            .push(Operation::EqualBytes { left, right });
        Ok(())
    }
    fn equal_signed(
        &mut self,
        a: &Polynomial<SignedRef>,
        b: &Polynomial<SignedRef>,
    ) -> Result<(), VerifyError> {
        let left = self.signed_id(a);
        let right = self.signed_id(b);
        self.graph
            .operations
            .push(Operation::EqualSigned { left, right });
        Ok(())
    }
    fn parameters(
        &mut self,
        seed: &[ByteRef; 32],
        context: &[ByteRef; 32],
    ) -> Result<GParameters<ResidueRef, ByteRef>, VerifyError> {
        let setup = self.graph.setup_seed;
        let fixed = self.import_bytes(setup, Source::Fixed);
        self.equal_bytes(seed, &fixed)?;
        let context_id = self.byte_id(context);
        let native = witness_value!(self,
            device => device.parameters(&setup, &context.map(|b| b.value)).map(Ok),
            primitives::parameters(&setup, &context.map(|b| b.value)), Err(VerifyError::Rejected))?;
        let output = self.derived_bytes(native.pp);
        self.graph.operations.push(Operation::ParametersPp {
            setup_seed: setup,
            context: context_id,
            output,
        });
        let pp = self.byte_refs(output);
        let mat1 = native
            .mat1
            .iter()
            .map(|row| row.iter().map(|p| self.fixed_polynomial(p, Q)).collect())
            .collect();
        let mat2 = native
            .mat2
            .iter()
            .map(|row| row.iter().map(|p| self.fixed_polynomial(p, Q)).collect())
            .collect();
        let mat3 = native
            .mat3
            .iter()
            .map(|row| row.iter().map(|p| self.fixed_polynomial(p, QHAT)).collect())
            .collect();
        Ok(GParameters {
            mat1,
            mat2,
            mat3,
            pp,
        })
    }
    fn sample_g(
        &mut self,
        seed: &[ByteRef; 32],
    ) -> Result<Vec<Polynomial<ResidueRef>>, VerifyError> {
        let seed_id = self.byte_id(seed);
        let native = witness_value!(self,
            device => device.sample_g(&seed.map(|v| v.value)).map(Ok),
            primitives::sample_g(&seed.map(|v| v.value)), Err(VerifyError::Rejected))?;
        let output: [PolyId; 4] = native
            .into_iter()
            .map(|values| self.derived_canonical(values, Q))
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixed sample_g profile");
        self.graph.operations.push(Operation::SampleG {
            seed: seed_id,
            output,
        });
        Ok(output.map(|id| self.canonical_refs(id)).to_vec())
    }
    fn expand_alpha(
        &mut self,
        seed: &[ByteRef; 32],
    ) -> Result<(Vec<Polynomial<ResidueRef>>, Polynomial<SignedRef>), VerifyError> {
        let seed_id = self.byte_id(seed);
        let (native, signed) = witness_value!(self,
            device => device.expand_alpha(&seed.map(|v| v.value)).map(Ok),
            primitives::expand_alpha(&seed.map(|v| v.value)), Err(VerifyError::Rejected))?;
        let canonical: [PolyId; 2] = native
            .into_iter()
            .map(|values| self.derived_canonical(values, Q))
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixed alpha profile");
        let signed = self.derived_signed(signed, 1);
        self.graph.operations.push(Operation::ExpandAlpha {
            seed: seed_id,
            canonical,
            signed,
        });
        Ok((
            canonical.map(|id| self.canonical_refs(id)).to_vec(),
            self.signed_refs(signed),
        ))
    }
    fn hash_alpha(
        &mut self,
        pp: &[ByteRef; 32],
        s: &GStatement<ResidueRef, ByteRef>,
        w_out: &[Vec<Polynomial<ResidueRef>>],
        w0: &[Polynomial<ResidueRef>],
        v: &[Polynomial<ResidueRef>],
        v2: &Polynomial<ResidueRef>,
        c: &Polynomial<ResidueRef>,
        w: &Polynomial<ResidueRef>,
        w1: &[Polynomial<ResidueRef>],
        w2: &[Polynomial<ResidueRef>],
    ) -> [ByteRef; 32] {
        let mut parts = vec![TranscriptPart::Bytes(self.byte_id(pp))];
        for pair in &s.ring {
            for account in pair {
                self.append_polys(&mut parts, &account.pk, Q);
                self.append_polys(&mut parts, &account.cn, Q);
            }
        }
        for serial in &s.serials {
            parts.push(TranscriptPart::Bytes(self.byte_id(serial)));
        }
        for polys in &s.recipients {
            self.append_polys(&mut parts, polys, Q);
        }
        for polys in &s.coins {
            self.append_polys(&mut parts, polys, Q);
        }
        for polys in w_out {
            self.append_polys(&mut parts, polys, Q);
        }
        self.append_polys(&mut parts, w0, Q);
        self.append_polys(&mut parts, v, Q);
        for poly in [v2, c, w] {
            self.append_polys(&mut parts, std::slice::from_ref(poly), Q);
        }
        self.append_polys(&mut parts, w1, Q);
        self.append_polys(&mut parts, w2, Q);
        let cpu = || {
            let native = Statement {
                seed: s.seed.map(|v| v.value),
                ring: s
                    .ring
                    .iter()
                    .map(|pair| {
                        pair.each_ref().map(|account| Account {
                            pk: account.pk.iter().map(|p| p.map(|v| v.value)).collect(),
                            cn: account.cn.iter().map(|p| p.map(|v| v.value)).collect(),
                        })
                    })
                    .collect(),
                recipients: s
                    .recipients
                    .iter()
                    .map(|polys| polys.iter().map(|p| p.map(|v| v.value)).collect())
                    .collect(),
                coins: s
                    .coins
                    .iter()
                    .map(|polys| polys.iter().map(|p| p.map(|v| v.value)).collect())
                    .collect(),
                serials: s.serials.map(|serial| serial.map(|v| v.value)),
            };
            let unpack = |polys: &[Polynomial<ResidueRef>]| {
                polys.iter().map(|p| p.map(|v| v.value)).collect::<Vec<_>>()
            };
            primitives::hash_alpha(
                &pp.map(|v| v.value),
                &native,
                &w_out.iter().map(|polys| unpack(polys)).collect::<Vec<_>>(),
                &unpack(w0),
                &unpack(v),
                &v2.map(|v| v.value),
                &c.map(|v| v.value),
                &w.map(|v| v.value),
                &unpack(w1),
                &unpack(w2),
            )
        };
        #[cfg(feature = "opencl")]
        let encoded = self
            .device
            .map(|_| gpu::transcript_bytes(&self.graph, &parts));
        let output_values = witness_value!(self, device => {
            let encoded = encoded.ok_or("missing GPU transcript")??;
            device.hash_alpha(&encoded)
        }, cpu(), [0; 32]);
        let output = self.derived_bytes(output_values);
        self.graph
            .operations
            .push(Operation::HashAlpha { parts, output });
        self.byte_refs(output)
    }
    fn hash_x(
        &mut self,
        alpha: &[ByteRef; 32],
        v0: &Polynomial<ResidueRef>,
        v1: &Polynomial<ResidueRef>,
        a: &[Polynomial<ResidueRef>],
        b: &[Polynomial<ResidueRef>],
        e: &[Polynomial<ResidueRef>],
    ) -> Result<Polynomial<SignedRef>, VerifyError> {
        let mut parts = vec![TranscriptPart::Bytes(self.byte_id(alpha))];
        for p in [v0, v1] {
            self.append_polys(&mut parts, std::slice::from_ref(p), Q);
        }
        self.append_polys(&mut parts, a, QHAT);
        self.append_polys(&mut parts, b, QHAT);
        self.append_polys(&mut parts, e, Q);
        let cpu = || {
            let unpack = |polys: &[Polynomial<ResidueRef>]| {
                polys.iter().map(|p| p.map(|v| v.value)).collect::<Vec<_>>()
            };
            primitives::hash_x(
                &alpha.map(|v| v.value),
                &v0.map(|v| v.value),
                &v1.map(|v| v.value),
                &unpack(a),
                &unpack(b),
                &unpack(e),
            )
        };
        #[cfg(feature = "opencl")]
        let encoded = self
            .device
            .map(|_| gpu::transcript_bytes(&self.graph, &parts));
        let values = witness_value!(self, device => {
            let encoded = encoded.ok_or("missing GPU transcript")??;
            device.hash_x(&encoded).map(Ok)
        }, cpu(), Err(VerifyError::Rejected))?;
        let output = self.derived_signed(values, 1);
        self.graph
            .operations
            .push(Operation::HashX { parts, output });
        Ok(self.signed_refs(output))
    }
}
