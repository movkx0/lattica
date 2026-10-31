//! Account membership for compact transport, independent of spend acceptance.
//!
//! A checkpoint must come from the receiver's trusted ledger state. A root
//! supplied alongside a packet is not an authenticated checkpoint. The source
//! below may be untrusted: every returned account and path is checked locally.
use super::{statement, Error};
use crate::native_packet::PROFILE_PARAMETERS;
use sha3::{Digest, Sha3_256};

pub use statement::{ACCOUNT_BYTES, RING_ACCOUNTS};
pub type AccountBytes = [u8; ACCOUNT_BYTES];
pub type Hash = [u8; 32];
pub const MAX_DEPTH: usize = 32;
/// A bound for the convenience in-memory store, not for external ledger stores.
pub const MAX_SNAPSHOT_ACCOUNTS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerCheckpoint {
    domain: Hash,
    setup_seed: Hash,
    tree_root: Hash,
    account_count: u64,
}

impl LedgerCheckpoint {
    /// The caller, not the packet or account provider, authenticates these parts.
    pub fn from_trusted_parts(
        domain: Hash,
        setup_seed: Hash,
        tree_root: Hash,
        account_count: u64,
    ) -> Result<Self, Error> {
        if account_count == 0 || account_count > (1u64 << MAX_DEPTH) {
            return Err(Error::Capacity);
        }
        Ok(Self {
            domain,
            setup_seed,
            tree_root,
            account_count,
        })
    }

    pub fn domain(&self) -> Hash {
        self.domain
    }
    pub fn setup_seed(&self) -> Hash {
        self.setup_seed
    }
    pub fn tree_root(&self) -> Hash {
        self.tree_root
    }
    pub fn account_count(&self) -> u64 {
        self.account_count
    }

    pub fn id(&self) -> Hash {
        hash(
            b"lattica/ringct/compact-ledger/checkpoint/v1\0",
            &[
                &self.domain,
                &self.setup_seed,
                &self.account_count.to_le_bytes(),
                &self.tree_root,
            ],
        )
    }

    fn depth(&self) -> usize {
        self.account_count.next_power_of_two().trailing_zeros() as usize
    }
}

#[derive(Clone, Debug)]
pub struct AccountWitness<'a> {
    account: &'a [u8],
    siblings: [Hash; MAX_DEPTH],
    depth: usize,
}

impl<'a> AccountWitness<'a> {
    /// Bounded untrusted witness. Construction is not membership verification.
    pub fn new(account: &'a [u8], siblings: &[Hash]) -> Result<Self, Error> {
        if account.len() != ACCOUNT_BYTES {
            return Err(Error::Length);
        }
        if siblings.len() > MAX_DEPTH {
            return Err(Error::Capacity);
        }
        let mut result = Self {
            account,
            siblings: [[0; 32]; MAX_DEPTH],
            depth: siblings.len(),
        };
        result.siblings[..siblings.len()].copy_from_slice(siblings);
        Ok(result)
    }

    pub fn account(&self) -> &'a [u8] {
        self.account
    }
    pub fn siblings(&self) -> &[Hash] {
        &self.siblings[..self.depth]
    }

    pub fn verify(&self, index: u64, checkpoint: &LedgerCheckpoint) -> Result<&'a [u8], Error> {
        if index >= checkpoint.account_count {
            return Err(Error::Reference);
        }
        if self.depth != checkpoint.depth() {
            return Err(Error::LedgerMembership);
        }
        statement::validate_account(self.account)?;
        let scope = ledger_scope(&checkpoint.domain, &checkpoint.setup_seed);
        let mut node = leaf(&scope, index, self.account);
        let mut position = index;
        for (level, sibling) in self.siblings().iter().enumerate() {
            node = if position & 1 == 0 {
                branch(&scope, level + 1, &node, sibling)
            } else {
                branch(&scope, level + 1, sibling, &node)
            };
            position >>= 1;
        }
        if node != checkpoint.tree_root {
            return Err(Error::LedgerMembership);
        }
        Ok(self.account)
    }
}

/// Locally available account data and Merkle paths; no provider-supplied root is trusted.
pub trait LedgerSource {
    fn account(&self, index: u64) -> Option<AccountWitness<'_>>;
}

/// A bounded research/reference store. Its checkpoint still needs external trust
/// when used by a receiver; this does not implement chain consensus or spent state.
pub struct LedgerSnapshot {
    checkpoint: LedgerCheckpoint,
    accounts: Vec<AccountBytes>,
    levels: Vec<Vec<Hash>>,
}

impl LedgerSnapshot {
    pub fn new(domain: Hash, setup_seed: Hash, accounts: Vec<AccountBytes>) -> Result<Self, Error> {
        if accounts.is_empty() || accounts.len() > MAX_SNAPSHOT_ACCOUNTS {
            return Err(Error::Capacity);
        }
        for account in &accounts {
            statement::validate_account(account)?;
        }
        let scope = ledger_scope(&domain, &setup_seed);
        let mut bottom = Vec::with_capacity(accounts.len().next_power_of_two());
        for (i, account) in accounts.iter().enumerate() {
            bottom.push(leaf(&scope, i as u64, account));
        }
        for i in accounts.len()..accounts.len().next_power_of_two() {
            bottom.push(hash(
                b"lattica/ringct/compact-ledger/empty/v1\0",
                &[&scope, &(i as u64).to_le_bytes()],
            ));
        }
        let mut levels = vec![bottom];
        while levels.last().unwrap().len() != 1 {
            let height = levels.len();
            let next = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| branch(&scope, height, &pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        let checkpoint = LedgerCheckpoint::from_trusted_parts(
            domain,
            setup_seed,
            levels.last().unwrap()[0],
            accounts.len() as u64,
        )?;
        Ok(Self {
            checkpoint,
            accounts,
            levels,
        })
    }

    pub fn checkpoint(&self) -> LedgerCheckpoint {
        self.checkpoint
    }
}

impl LedgerSource for LedgerSnapshot {
    fn account(&self, index: u64) -> Option<AccountWitness<'_>> {
        let index = usize::try_from(index).ok()?;
        let account = self.accounts.get(index)?;
        let mut result = AccountWitness {
            account,
            siblings: [[0; 32]; MAX_DEPTH],
            depth: self.levels.len() - 1,
        };
        let mut position = index;
        for (level, nodes) in self.levels[..result.depth].iter().enumerate() {
            result.siblings[level] = nodes[position ^ 1];
            position >>= 1;
        }
        Some(result)
    }
}

fn hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(tag);
    h.update(PROFILE_PARAMETERS);
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn ledger_scope(domain: &Hash, setup_seed: &Hash) -> Hash {
    hash(
        b"lattica/ringct/compact-ledger/scope/v1\0",
        &[domain, setup_seed],
    )
}

fn leaf(domain: &Hash, index: u64, account: &[u8]) -> Hash {
    hash(
        b"lattica/ringct/compact-ledger/account/v1\0",
        &[domain, &index.to_le_bytes(), account],
    )
}

fn branch(domain: &Hash, height: usize, left: &Hash, right: &Hash) -> Hash {
    hash(
        b"lattica/ringct/compact-ledger/branch/v1\0",
        &[domain, &[height as u8], left, right],
    )
}
