//! Native AES proof data shared with the isolated research implementation.
//! This schema supplies no verification, transaction acceptance or ownership.
use super::profile::Config;
use crate::config::Val;

pub const PUBLIC_VALUES: usize = 12;

pub struct NativeAesProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
