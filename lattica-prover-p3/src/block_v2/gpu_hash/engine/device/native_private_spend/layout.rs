//! Generated public ABI offsets and pinned dispatch schedule. No private inputs.
pub(super) const ARENA_WORDS: usize = 336839;
pub(super) const SOURCE_SHA256: &str =
    "6c0ca18e5a54bee1e26a4ba7aa6fb516ec7a972c1c4c1e2a03ed307d038ed054";
pub(super) const SLOT_OFFSETS: [u64; 78] = [
    0, 4, 8, 12, 46092, 48140, 52236, 56844, 56852, 56857, 59417, 64025, 71193, 74265, 111385,
    111389, 134689, 134817, 134881, 134893, 137197, 141805, 146413, 148461, 150765, 153069, 154093,
    157165, 160237, 163309, 163565, 176365, 179181, 181997, 184813, 187629, 190445, 193261, 194285,
    195309, 195565, 195821, 196077, 196333, 196845, 197357, 197613, 197869, 198381, 218861, 219885,
    230125, 230381, 232429, 235501, 238061, 240621, 243181, 245741, 247021, 249069, 251117, 252141,
    255213, 255469, 255725, 255981, 258797, 260845, 263405, 268013, 270317, 273133, 275949, 304761,
    304779, 330135, 336835,
];
pub(super) const STATEMENT_BYTES_OFFSET: usize = 304779;
pub(super) const PROOF_BYTES_OFFSET: usize = 330135;
pub(super) const CK_OUT: usize = 59417;
pub(super) const REJECTION_OFFSETS: [u64; 10] = [
    114721, 121633, 124449, 119329, 130081, 263405, 270317, 273133, 268013, 260845,
];
pub(super) struct Step {
    pub name: &'static str,
    pub phase: u32,
    pub may_reject: bool,
}
pub(super) const STEPS: [Step; 26] = [
    Step {
        name: "pq_private_rng_init",
        phase: 0,
        may_reject: false,
    },
    Step {
        name: "pq_spend_import",
        phase: 10,
        may_reject: false,
    },
    Step {
        name: "pq_spend_setup",
        phase: 20,
        may_reject: false,
    },
    Step {
        name: "pq_sample_one",
        phase: 30,
        may_reject: false,
    },
    Step {
        name: "pq_sample_one",
        phase: 30,
        may_reject: false,
    },
    Step {
        name: "pq_spend_mint_static",
        phase: 30,
        may_reject: false,
    },
    Step {
        name: "pq_spend_begin_attempt",
        phase: 35,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_sample_one",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 40,
        may_reject: false,
    },
    Step {
        name: "pq_spend_equations",
        phase: 40,
        may_reject: true,
    },
    Step {
        name: "pq_sample_one",
        phase: 50,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 50,
        may_reject: false,
    },
    Step {
        name: "pq_sample_gaussian",
        phase: 50,
        may_reject: false,
    },
    Step {
        name: "pq_spend_equations",
        phase: 50,
        may_reject: false,
    },
    Step {
        name: "pq_spend_equations",
        phase: 60,
        may_reject: false,
    },
    Step {
        name: "pq_reject_f",
        phase: 60,
        may_reject: true,
    },
    Step {
        name: "pq_spend_equations",
        phase: 70,
        may_reject: true,
    },
    Step {
        name: "pq_reject_z",
        phase: 70,
        may_reject: true,
    },
    Step {
        name: "pq_spend_equations",
        phase: 80,
        may_reject: false,
    },
    Step {
        name: "pq_reject_op",
        phase: 80,
        may_reject: true,
    },
    Step {
        name: "pq_spend_encode",
        phase: 90,
        may_reject: false,
    },
];
