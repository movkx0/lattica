//! Public deterministic test data; never wallet randomness. Every account is
//! generated through the original key/commitment equations, including decoys.
use super::*;
use crate::{ring_native as native, VALUE_LIMIT};
use ring::{Account, SignedPoly, Statement, Witness, D, RING_PAIRS};
use serde::Serialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Shake256,
};

const DOMAIN: &[u8] = b"lattica/research/direct-ring/seven-case-fixture-v1";
const SELECTED: [usize; CASES] = [0, 1, 3, 4, 6, 8, 9];
const L: u64 = VALUE_LIMIT;
const VALUES: [([u64; 2], [u64; 2]); CASES] = [
    ([0, 1], [1, 0]),
    ([1, 1], [0, 2]),
    ([1000, 500], [900, 600]),
    ([L - 1, 0], [L - 2, 1]),
    ([L - 1, 1], [L - 1, 1]),
    ([L - 1, L - 1], [L - 1, L - 1]),
    ([L - 3, L - 5], [L - 4, L - 4]),
];

fn material<const N: usize>(case: usize, domain: u8, account: usize, poly: usize) -> [u8; N] {
    let mut h = Shake256::default();
    Update::update(&mut h, DOMAIN);
    Update::update(&mut h, &[case as u8, domain, account as u8, poly as u8]);
    let mut out = [0; N];
    h.finalize_xof().read(&mut out);
    out
}

fn secret(case: usize, domain: u8, account: usize, poly: usize) -> SignedPoly {
    let bytes = material::<D>(case, domain, account, poly);
    std::array::from_fn(|i| i64::from(bytes[i] % 3) - 1)
}

pub(super) fn generate(case: usize) -> std::result::Result<(Statement, Witness), Error> {
    let &(input_values, output_values) = VALUES.get(case).ok_or(Error::Geometry)?;
    let selected_pair = SELECTED[case];
    let setup_seed = [7; 32];
    let params = native::parameters(&setup_seed)?;
    // Capacity checks are on the actual native owners; the preceding staging
    // census covers their source-fixed allocations, including AES scratch.
    if params.mat1.capacity() != 7 || params.mat2.capacity() != 4 {
        return Err(Error::ResourceLimit);
    }
    let serials = std::array::from_fn(|i| material::<32>(case, 4, selected_pair * 2 + i, 0));
    let spending =
        std::array::from_fn(|i| std::array::from_fn(|p| secret(case, 1, selected_pair * 2 + i, p)));
    let input_openings =
        std::array::from_fn(|i| std::array::from_fn(|p| secret(case, 2, selected_pair * 2 + i, p)));
    let output_openings = std::array::from_fn(|i| std::array::from_fn(|p| secret(case, 3, i, p)));
    let mut ring = Vec::<[Account; 2]>::new();
    ring.try_reserve_exact(RING_PAIRS)
        .map_err(|_| Error::ResourceLimit)?;
    if ring.capacity() != RING_PAIRS {
        return Err(Error::ResourceLimit);
    }
    for pair in 0..RING_PAIRS {
        let mut accounts = std::array::from_fn(|_| Account {
            public_key: [[0; D]; 4],
            coin: [[0; D]; 5],
        });
        for (i, account) in accounts.iter_mut().enumerate() {
            let who = pair * 2 + i;
            let sk = std::array::from_fn(|p| secret(case, 1, who, p));
            let ck = std::array::from_fn(|p| secret(case, 2, who, p));
            let gamma = material::<32>(case, 4, who, 0);
            account.public_key = native::key(&sk, &params, &gamma)?;
            account.coin = native::coin(&ck, input_values[i], &params);
        }
        ring.push(accounts);
    }
    let recipients = [ring[0][0].public_key, ring[0][1].public_key];
    let output_coins =
        std::array::from_fn(|i| native::coin(&output_openings[i], output_values[i], &params));
    Ok((
        Statement {
            profile: Profile::RingDirectV1,
            context: CONTEXT,
            setup_seed,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct Identity {
    pub case: usize,
    pub statement_sha3_256: [u8; 32],
    pub serials: [[u8; 32]; 2],
}

pub(super) type Manifest = [Option<Identity>; CASES];

pub(super) fn identity(case: usize, statement: &Statement) -> Identity {
    // Streaming public-only identity; no Statement::binding-sized temporary Vec.
    let mut h = Sha3_256::new();
    Digest::update(&mut h, b"lattica/research/direct-ring/screen-statement/v1");
    Digest::update(&mut h, statement.profile.tag().as_bytes());
    Digest::update(&mut h, statement.context.0);
    Digest::update(&mut h, statement.setup_seed);
    Digest::update(&mut h, (statement.ring.len() as u64).to_le_bytes());
    for p in statement
        .ring
        .iter()
        .flatten()
        .flat_map(|a| a.public_key.iter().chain(a.coin.iter()))
        .chain(statement.recipients.iter().flatten())
        .chain(statement.output_coins.iter().flatten())
    {
        for coefficient in p {
            Digest::update(&mut h, coefficient.to_le_bytes());
        }
    }
    for serial in statement.serials {
        Digest::update(&mut h, serial);
    }
    Identity {
        case,
        statement_sha3_256: h.finalize().into(),
        serials: statement.serials,
    }
}

pub(super) fn insert(manifest: &mut Manifest, item: Identity) -> std::result::Result<(), Error> {
    if item.case >= CASES || manifest[item.case].is_some() || item.serials[0] == item.serials[1] {
        return Err(Error::DuplicateSpend);
    }
    for previous in manifest.iter().flatten() {
        if previous.statement_sha3_256 == item.statement_sha3_256
            || previous
                .serials
                .iter()
                .any(|old| item.serials.contains(old))
        {
            return Err(Error::DuplicateSpend);
        }
    }
    manifest[item.case] = Some(item);
    Ok(())
}

pub(super) fn preflight() -> Result<Manifest> {
    let mut manifest = [None; CASES];
    for case in 0..CASES {
        let (statement, witness) = generate(case)?;
        ring::check_relation(&statement, &witness, CONTEXT)?;
        insert(&mut manifest, identity(case, &statement))?;
        // Only the fixed public manifest survives into the next iteration.
        drop(witness);
        drop(statement);
    }
    Ok(manifest)
}
