use super::*;
impl CommittedBackend<'_> {
    pub fn import_statement(&mut self, statement: &Statement) -> GStatement<ResidueRef, ByteRef> {
        let seed = self.import_bytes(statement.seed, Source::StatementSeed);
        let mut position = 0;
        let mut import = |values: &[u64; D]| {
            let id = self.canonical_node(*values, Q, Source::StatementPolynomial { position });
            position += 1;
            self.canonical_refs(id)
        };
        let ring = statement
            .ring
            .iter()
            .map(|pair| {
                pair.each_ref().map(|account| GAccount {
                    pk: account.pk.iter().map(&mut import).collect(),
                    cn: account.cn.iter().map(&mut import).collect(),
                })
            })
            .collect();
        let recipients = statement
            .recipients
            .iter()
            .map(|polys| polys.iter().map(&mut import).collect())
            .collect();
        let coins = statement
            .coins
            .iter()
            .map(|polys| polys.iter().map(&mut import).collect())
            .collect();
        assert_eq!(position, 198, "fixed public statement profile");
        let serials = core::array::from_fn(|position| {
            self.import_bytes(
                statement.serials[position],
                Source::StatementSerial { position },
            )
        });
        GStatement {
            seed,
            ring,
            recipients,
            coins,
            serials,
        }
    }
    pub fn import_proof(&mut self, proof: &Proof) -> GProof<ResidueRef, SignedRef, ByteRef> {
        let mut position = 0;
        let mut canonical = |values: &[u64; D], modulus: u64| {
            let id = self.canonical_node(*values, modulus, Source::ProofPolynomial { position });
            position += 1;
            self.canonical_refs(id)
        };
        let c = canonical(&proof.c, Q);
        let v = proof.v.iter().map(|value| canonical(value, Q)).collect();
        let v1 = canonical(&proof.v1, Q);
        let v2 = canonical(&proof.v2, Q);
        let b = proof.b.iter().map(|value| canonical(value, QHAT)).collect();
        assert_eq!(position, 12, "fixed residue proof profile");
        let mut signed = |values: &[i64; D], bound: u32| {
            let id = self.signed_node(*values, bound, Source::ProofPolynomial { position });
            position += 1;
            self.signed_refs(id)
        };
        let x = signed(&proof.x, 1);
        let z_out = proof
            .z_out
            .iter()
            .map(|polys| polys.iter().map(|value| signed(value, 38346)).collect())
            .collect();
        let z0 = proof.z0.iter().map(|value| signed(value, 38346)).collect();
        let z1 = proof.z1.iter().map(|value| signed(value, 38346)).collect();
        let z2 = proof.z2.iter().map(|value| signed(value, 38346)).collect();
        let f1 = proof.f1.iter().map(|value| signed(value, 565)).collect();
        let zb = proof.zb.iter().map(|value| signed(value, 38346)).collect();
        let z = proof.z.iter().map(|value| signed(value, 6212586)).collect();
        assert_eq!(position, 91, "fixed complete proof profile");
        let alpha = self.import_bytes(proof.alpha, Source::ProofAlpha);
        GProof {
            c,
            v,
            v1,
            v2,
            b,
            alpha,
            x,
            z_out,
            z0,
            z1,
            z2,
            f1,
            zb,
            z,
        }
    }
}
