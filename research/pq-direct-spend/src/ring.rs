//! Direct ring relation, independent of generating/verifying a MatRiCT proof.
//!
//! Public ring entries must be authenticated by the caller's ledger snapshot.
//! This profile selects one of exactly ten ordered *pairs*, not two independently
//! selected accounts. The selected pair index is never a public output.
use crate::{amounts, ring_native as native, Context, Error, Profile, INPUTS, OUTPUTS};
pub use lattica_pq_ringct_research::rust_verify::{Poly, SignedPoly, D, Q, QHAT};

pub const RING_PAIRS: usize = 10;
pub const SPENDING_POLYS: usize = 8;
pub const OPENING_POLYS: usize = 9;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    pub public_key: [Poly; 4],
    pub coin: [Poly; 5],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statement {
    pub profile: Profile,
    pub context: Context,
    pub setup_seed: [u8; 32],
    pub ring: Vec<[Account; INPUTS]>,
    pub recipients: [[Poly; 4]; OUTPUTS],
    pub output_coins: [[Poly; 5]; OUTPUTS],
    pub serials: [[u8; 32]; INPUTS],
}

/// Private keys are neither Debug nor serializable. Experimental callers must
/// supply fresh output openings; fixture-derived openings are test data only.
pub struct Witness {
    pub selected_pair: usize,
    pub spending: [[SignedPoly; SPENDING_POLYS]; INPUTS],
    pub input_openings: [[SignedPoly; OPENING_POLYS]; INPUTS],
    pub output_openings: [[SignedPoly; OPENING_POLYS]; OUTPUTS],
    pub input_values: [u64; INPUTS],
    pub output_values: [u64; OUTPUTS],
}

impl Drop for Witness {
    fn drop(&mut self) {
        for x in self
            .spending
            .iter_mut()
            .flatten()
            .flatten()
            .chain(self.input_openings.iter_mut().flatten().flatten())
            .chain(self.output_openings.iter_mut().flatten().flatten())
        {
            // SAFETY: exclusively borrowed, live owned secret storage.
            unsafe { std::ptr::write_volatile(x, 0) };
        }
        for x in self
            .input_values
            .iter_mut()
            .chain(self.output_values.iter_mut())
        {
            unsafe { std::ptr::write_volatile(x, 0) };
        }
        unsafe { std::ptr::write_volatile(&mut self.selected_pair, 0) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Statement {
    /// Deterministic public-only identity. It is never a digest supplied by a
    /// secret witness; a future verifier must rebuild the full program as well.
    #[cfg(any(test, feature = "ring-circuit"))]
    pub(crate) fn binding(&self) -> [p3_goldilocks::Goldilocks; 4] {
        let mut bytes = self.profile.tag().as_bytes().to_vec();
        bytes.extend_from_slice(&self.context.0);
        bytes.extend_from_slice(&self.setup_seed);
        for poly in self
            .ring
            .iter()
            .flatten()
            .flat_map(|a| a.public_key.iter().chain(a.coin.iter()))
            .chain(self.recipients.iter().flatten())
            .chain(self.output_coins.iter().flatten())
        {
            for v in poly {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
        for serial in self.serials {
            bytes.extend_from_slice(&serial);
        }
        crate::context_binding(
            Profile::RingDirectV1,
            Context(crate::shake(&bytes, 32).try_into().unwrap()),
        )
    }
    pub fn admit(&self, expected: Context) -> Result<(), Error> {
        if self.profile != Profile::RingDirectV1 {
            return Err(Error::Profile);
        }
        if self.context != expected {
            return Err(Error::Context);
        }
        if self.ring.len() != RING_PAIRS {
            return Err(Error::Geometry);
        }
        if self.serials[0] == self.serials[1] {
            return Err(Error::DuplicateSpend);
        }
        let ring_polys = self
            .ring
            .iter()
            .flatten()
            .flat_map(|a| a.public_key.iter().chain(a.coin.iter()));
        if ring_polys
            .chain(self.recipients.iter().flatten())
            .chain(self.output_coins.iter().flatten())
            .flatten()
            .any(|&c| c >= Q)
        {
            return Err(Error::NonCanonical);
        }
        Ok(())
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    #[test]
    fn public_binding_includes_order_serials_seed_context_and_profile() {
        let (s, _) = fixture(Context([19; 32])).unwrap();
        let binding = s.binding();
        let mut x = s.clone();
        x.recipients.swap(0, 1);
        assert_ne!(x.binding(), binding);
        x = s.clone();
        x.ring.swap(0, 1);
        assert_ne!(x.binding(), binding);
        x = s.clone();
        x.serials.swap(0, 1);
        assert_ne!(x.binding(), binding);
        x = s.clone();
        x.output_coins.swap(0, 1);
        assert_ne!(x.binding(), binding);
        x = s.clone();
        x.setup_seed[0] ^= 1;
        assert_ne!(x.binding(), binding);
        x = s.clone();
        x.context.0[0] ^= 1;
        assert_ne!(x.binding(), binding);
        x = s.clone();
        x.profile = Profile::PrivateNoteDirectV1;
        assert_ne!(x.binding(), binding);
    }
}

pub(crate) fn admit_witness(w: &Witness) -> Result<(), Error> {
    if w.selected_pair >= RING_PAIRS {
        return Err(Error::Geometry);
    }
    amounts(w.input_values, w.output_values)?;
    // Keygen/mint sample S_1; using arbitrary short vectors changes the relation.
    if w.spending
        .iter()
        .flatten()
        .flatten()
        .chain(w.input_openings.iter().flatten().flatten())
        .chain(w.output_openings.iter().flatten().flatten())
        .any(|&x| !(-1..=1).contains(&x))
    {
        return Err(Error::NonCanonical);
    }
    Ok(())
}

/// Differential oracle/admission only. Success is not a proof and does not
/// authorize ledger insertion or production transaction acceptance.
pub fn check_relation(s: &Statement, w: &Witness, expected: Context) -> Result<(), Error> {
    s.admit(expected)?;
    admit_witness(w)?;
    let params = native::parameters(&s.setup_seed)?;
    let pair = &s.ring[w.selected_pair];
    for i in 0..INPUTS {
        if native::key(&w.spending[i], &params, &s.serials[i])? != pair[i].public_key {
            return Err(Error::Ownership);
        }
        if native::coin(&w.input_openings[i], w.input_values[i], &params) != pair[i].coin {
            return Err(Error::Opening);
        }
    }
    for i in 0..OUTPUTS {
        if native::coin(&w.output_openings[i], w.output_values[i], &params) != s.output_coins[i] {
            return Err(Error::Opening);
        }
    }
    Ok(())
}

/// There is deliberately no artifact or success path until full registered
/// proving, independent verification and resource-envelope validation exist.
pub fn prove(
    s: &Statement,
    w: &Witness,
    expected: Context,
) -> Result<std::convert::Infallible, Error> {
    s.admit(expected)?;
    admit_witness(w)?;
    Err(Error::IncompleteProofCoverage)
}

/// Deterministic, public test fixture. Never use these keys/openings in a wallet.
pub fn fixture(context: Context) -> Result<(Statement, Witness), Error> {
    let seed = [7; 32];
    let params = native::parameters(&seed)?;
    let secret = |domain: u8, who: usize, p: usize| -> SignedPoly {
        let bytes = crate::shake(&[domain, who as u8, p as u8], D);
        std::array::from_fn(|j| (bytes[j] % 3) as i64 - 1)
    };
    let selected_pair = 4;
    let serials = [[51; 32], [52; 32]];
    let spending =
        std::array::from_fn(|i| std::array::from_fn(|p| secret(1, selected_pair * 2 + i, p)));
    let input_openings =
        std::array::from_fn(|i| std::array::from_fn(|p| secret(2, selected_pair * 2 + i, p)));
    let output_openings = std::array::from_fn(|i| std::array::from_fn(|p| secret(3, i, p)));
    let input_values = [1000, 500];
    let output_values = [900, 600];
    let mut ring: Vec<[Account; INPUTS]> = Vec::with_capacity(RING_PAIRS);
    for pair in 0..RING_PAIRS {
        let mut accounts = Vec::with_capacity(2);
        for i in 0..2 {
            let sk = std::array::from_fn(|p| secret(1, pair * 2 + i, p));
            let ck = std::array::from_fn(|p| secret(2, pair * 2 + i, p));
            let gamma = if pair == selected_pair {
                serials[i]
            } else {
                [(100 + pair * 2 + i) as u8; 32]
            };
            accounts.push(Account {
                public_key: native::key(&sk, &params, &gamma)?,
                coin: native::coin(&ck, input_values[i], &params),
            });
        }
        ring.push(accounts.try_into().unwrap());
    }
    let recipients = [ring[0][0].public_key, ring[0][1].public_key];
    let output_coins =
        std::array::from_fn(|i| native::coin(&output_openings[i], output_values[i], &params));
    Ok((
        Statement {
            profile: Profile::RingDirectV1,
            context,
            setup_seed: seed,
            ring,
            recipients,
            output_coins,
            serials,
        },
        Witness {
            selected_pair,
            spending,
            input_openings,
            output_openings,
            input_values,
            output_values,
        },
    ))
}
