use super::*;
use std::collections::BTreeSet;
impl CommittedBackend<'_> {
    pub(super) fn expression(&mut self, expression: Expression) -> usize {
        let index = self.graph.expressions.len();
        self.graph.expressions.push(expression);
        index
    }
    pub(super) fn check_residue(&self, value: ResidueRef, q: u64) {
        assert_eq!(
            value.owner, self.graph.owner,
            "foreign coefficient reference"
        );
        assert_eq!(value.modulus, q, "coefficient modulus");
    }
    pub(super) fn check_signed(&self, value: SignedRef) {
        assert_eq!(value.owner, self.graph.owner, "foreign signed reference");
    }
    pub(super) fn canonical_node(
        &mut self,
        values: [u64; D],
        modulus: u64,
        source: Source,
    ) -> PolyId {
        assert!(matches!(modulus, Q | QHAT));
        // The GPU commitment kernel validates residues before hashing. Keep
        // legacy CPU checks in its own path; GPU rejection poisons the graph.
        #[cfg(feature = "opencl")]
        if self.device.is_none() {
            assert!(values.iter().all(|&value| value < modulus));
        }
        #[cfg(not(feature = "opencl"))]
        assert!(values.iter().all(|&value| value < modulus));
        let id = PolyId {
            owner: self.graph.owner,
            index: self.graph.polynomials.len(),
        };
        let expressions = core::array::from_fn(|index| {
            self.expression(Expression::CanonicalInput {
                polynomial: id,
                index,
            })
        });
        let commitment = witness_value!(self, device => device.commit_canonical(&values, modulus),
            commit_values(POLYNOMIAL_DOMAIN, modulus, &values), [Val::ZERO; 4]);
        self.graph.polynomials.push(PolynomialNode {
            kind: PolynomialKind::Canonical { modulus },
            source,
            commitment,
            values: PolynomialValues::Canonical(values),
            expressions,
        });
        id
    }
    pub(super) fn signed_node(&mut self, values: [i64; D], bound: u32, source: Source) -> PolyId {
        assert!(bound <= i32::MAX as u32);
        let id = PolyId {
            owner: self.graph.owner,
            index: self.graph.polynomials.len(),
        };
        let expressions = core::array::from_fn(|index| {
            self.expression(Expression::SignedInput {
                polynomial: id,
                index,
            })
        });
        let commitment = witness_value!(self, device => device.commit_signed(&values),
            commit_signed_values(&values), [Val::ZERO; 4]);
        self.graph.polynomials.push(PolynomialNode {
            kind: PolynomialKind::Signed { bound },
            source,
            commitment,
            values: PolynomialValues::Signed(values),
            expressions,
        });
        id
    }
    pub(super) fn canonical_refs(&self, id: PolyId) -> Polynomial<ResidueRef> {
        let node = self.graph.polynomial(id);
        let PolynomialKind::Canonical { modulus } = node.kind else {
            panic!("canonical polynomial kind")
        };
        let PolynomialValues::Canonical(values) = &node.values else {
            unreachable!()
        };
        core::array::from_fn(|index| ResidueRef {
            owner: self.graph.owner,
            expr: node.expressions[index],
            modulus,
            value: values[index],
        })
    }
    pub(super) fn signed_refs(&self, id: PolyId) -> Polynomial<SignedRef> {
        let node = self.graph.polynomial(id);
        let PolynomialKind::Signed { bound } = node.kind else {
            panic!("signed polynomial kind")
        };
        let PolynomialValues::Signed(values) = &node.values else {
            unreachable!()
        };
        core::array::from_fn(|index| SignedRef {
            owner: self.graph.owner,
            expr: node.expressions[index],
            bound,
            value: values[index],
        })
    }
    pub(super) fn byte_node(&mut self, values: [u8; 32], source: Source) -> BytesId {
        let id = BytesId {
            owner: self.graph.owner,
            index: self.graph.bytes.len(),
        };
        let commitment = witness_value!(self, device => device.commit_bytes(&values),
            commit_bytes(BYTES32_DOMAIN, &values), [Val::ZERO; 4]);
        self.graph.bytes.push(BytesNode {
            source,
            commitment,
            values,
        });
        id
    }
    pub(super) fn byte_refs(&self, id: BytesId) -> [ByteRef; 32] {
        let node = self.graph.byte_string(id);
        core::array::from_fn(|index| ByteRef {
            buffer: id,
            index,
            value: node.values[index],
        })
    }
    pub fn import_bytes(&mut self, values: [u8; 32], source: Source) -> [ByteRef; 32] {
        assert!(
            !matches!(source, Source::Derived { .. }),
            "derived bytes require an obligation"
        );
        let id = self.byte_node(values, source);
        self.byte_refs(id)
    }
    pub(super) fn byte_id(&mut self, bytes: &[ByteRef; 32]) -> BytesId {
        for byte in bytes {
            assert_eq!(
                byte.buffer.owner, self.graph.owner,
                "foreign byte reference"
            );
            assert!(byte.index < 32);
        }
        let first = bytes[0].buffer;
        if bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| byte.buffer == first && byte.index == index)
        {
            return first;
        }
        let source = Source::Derived {
            operation: self.graph.operations.len(),
        };
        let output = self.byte_node(bytes.map(|byte| byte.value), source);
        self.graph.operations.push(Operation::ByteMap {
            inputs: bytes.map(|byte| (byte.buffer, byte.index)),
            output,
        });
        output
    }
    fn dependencies(&self, expressions: &[usize; D]) -> Vec<PolyId> {
        let mut todo = expressions.to_vec();
        let mut seen = BTreeSet::new();
        let mut inputs = BTreeSet::new();
        while let Some(index) = todo.pop() {
            if !seen.insert(index) {
                continue;
            }
            match &self.graph.expressions[index] {
                Expression::CanonicalInput { polynomial, .. }
                | Expression::SignedInput { polynomial, .. } => {
                    inputs.insert(*polynomial);
                }
                Expression::CanonicalConstant { .. } => {}
                Expression::Add { left, right, .. }
                | Expression::Sub { left, right, .. }
                | Expression::SignedSub { left, right, .. } => todo.extend([*left, *right]),
                Expression::Scale { input, .. }
                | Expression::SignedNeg { input, .. }
                | Expression::ConvertCoefficient { input, .. } => todo.push(*input),
            }
        }
        inputs.into_iter().collect()
    }
    pub(super) fn canonical_id(&mut self, values: &Polynomial<ResidueRef>, modulus: u64) -> PolyId {
        for &value in values {
            self.check_residue(value, modulus);
        }
        let expressions = values.map(|value| value.expr);
        if let Expression::CanonicalInput { polynomial, .. } =
            self.graph.expressions[expressions[0]]
        {
            if expressions.iter().enumerate().all(|(index,&expression)|matches!(self.graph.expressions[expression],Expression::CanonicalInput{polynomial:p,index:i}if p==polynomial&&i==index)){return polynomial;}
        }
        if let Some(id) = self.canonical_maps.get(&(modulus, expressions)) {
            return *id;
        }
        let fixed = expressions.iter().all(|&index| {
            matches!(
                self.graph.expressions[index],
                Expression::CanonicalConstant { .. }
            )
        });
        let source = if fixed {
            Source::Fixed
        } else {
            Source::Derived {
                operation: self.graph.operations.len(),
            }
        };
        let inputs = self.dependencies(&expressions);
        let output = self.canonical_node(values.map(|value| value.value), modulus, source);
        if !fixed {
            self.graph.operations.push(Operation::CanonicalMap {
                modulus,
                inputs,
                expressions,
                output,
            });
        }
        self.canonical_maps.insert((modulus, expressions), output);
        output
    }
    pub(super) fn signed_id(&mut self, values: &Polynomial<SignedRef>) -> PolyId {
        for &value in values {
            self.check_signed(value);
        }
        let expressions = values.map(|value| value.expr);
        if let Expression::SignedInput { polynomial, .. } = self.graph.expressions[expressions[0]] {
            if expressions.iter().enumerate().all(|(index,&expression)|matches!(self.graph.expressions[expression],Expression::SignedInput{polynomial:p,index:i}if p==polynomial&&i==index)){return polynomial;}
        }
        if let Some(id) = self.signed_maps.get(&expressions) {
            return *id;
        }
        let bound = values.iter().map(|value| value.bound).max().unwrap();
        let inputs = self.dependencies(&expressions);
        let output = self.signed_node(
            values.map(|value| value.value),
            bound,
            Source::Derived {
                operation: self.graph.operations.len(),
            },
        );
        self.graph.operations.push(Operation::SignedMap {
            bound,
            inputs,
            expressions,
            output,
        });
        self.signed_maps.insert(expressions, output);
        output
    }
    pub(super) fn fixed_polynomial(
        &mut self,
        values: &[u64; D],
        modulus: u64,
    ) -> Polynomial<ResidueRef> {
        let values = values.map(|value| self.constant(value, modulus));
        let id = self.canonical_id(&values, modulus);
        self.canonical_refs(id)
    }
    pub(super) fn derived_canonical(&mut self, values: [u64; D], modulus: u64) -> PolyId {
        self.canonical_node(
            values,
            modulus,
            Source::Derived {
                operation: self.graph.operations.len(),
            },
        )
    }
    pub(super) fn derived_signed(&mut self, values: [i64; D], bound: u32) -> PolyId {
        self.signed_node(
            values,
            bound,
            Source::Derived {
                operation: self.graph.operations.len(),
            },
        )
    }
    pub(super) fn derived_bytes(&mut self, values: [u8; 32]) -> BytesId {
        self.byte_node(
            values,
            Source::Derived {
                operation: self.graph.operations.len(),
            },
        )
    }
    pub(super) fn canonical_constant(&self, value: ResidueRef) -> Option<u64> {
        match self.graph.expressions[value.expr] {
            Expression::CanonicalConstant { value, .. } => Some(value),
            _ => None,
        }
    }
    pub(super) fn append_polys(
        &mut self,
        parts: &mut Vec<TranscriptPart>,
        values: &[Polynomial<ResidueRef>],
        modulus: u64,
    ) {
        for value in values {
            parts.push(TranscriptPart::Polynomial(
                self.canonical_id(value, modulus),
            ));
        }
    }
}
