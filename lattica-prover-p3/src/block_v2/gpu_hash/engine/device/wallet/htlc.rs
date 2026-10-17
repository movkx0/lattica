//! HTLC raw witness encoding and AIR-owned layout. The shared wallet runner
//! bounds memory, scrubs private staging and records every completed kernel.
use super::*;
use crate::htlc_air as htlc;

const INPUT_WORDS: usize = htlc::N_IN * (24 + htlc::DEPTH * 5) + htlc::M_OUT * 11 + 7;
const GEOMETRY_WORDS: usize = 41;

fn input_words(w: &htlc::Witness) -> Result<InputWords, String> {
    let mut words = InputWords(staging_words(INPUT_WORDS)?);
    for v in &w.inputs {
        words.0.extend(v.nk);
        words.0.extend([
            v.div.as_canonical_u64(),
            v.asset.as_canonical_u64(),
            v.value,
        ]);
        words.0.extend(v.rho.map(|x| x.as_canonical_u64()));
        words.0.extend(v.rcm.map(|x| x.as_canonical_u64()));
        words
            .0
            .extend([v.note_type.as_canonical_u64(), v.mode.as_canonical_u64()]);
        for tag in [v.redeem_tag, v.refund_tag, v.hashlock] {
            words.0.extend(tag.map(|x| x.as_canonical_u64()));
        }
        words.0.push(v.timeout);
        for (sibling, bit) in v.sib.iter().zip(v.bits) {
            words.0.extend(sibling.map(|x| x.as_canonical_u64()));
            words.0.push(u64::from(bit));
        }
    }
    for v in &w.outputs {
        words.0.extend(v.recipient.map(|x| x.as_canonical_u64()));
        words.0.extend([v.asset.as_canonical_u64(), v.value]);
        words.0.extend(v.rho.map(|x| x.as_canonical_u64()));
        words.0.extend(v.rcm.map(|x| x.as_canonical_u64()));
        words.0.push(v.note_type.as_canonical_u64());
    }
    words.0.extend([w.fee, w.mint]);
    words.0.extend(w.tx_binding.map(|x| x.as_canonical_u64()));
    words.0.push(w.current_height);
    Ok(words)
}

pub(super) fn plan(host_allowance: usize) -> Result<Plan, String> {
    if host_allowance < (INPUT_WORDS + GEOMETRY_WORDS + 1) * 8 {
        return Err("HTLC input staging exceeds host allowance".into());
    }
    let g = htlc::device_trace_geometry();
    if !htlc::HEIGHT.is_power_of_two()
        || g[6] != 32
        || g[4] > 32
        || g[5] >= 64
        || g[7] != 8 + g[4]
        || g[8..11] != [2, 2, 2]
        || g[38] != 4
        || g[39] != 1
        || g[11] != g[2] * g[7] + g[3] * g[8] + g[9] + g[10]
        || g[12] * 32 != g[0]
        || g[11] > g[12]
        || g[13..24]
            .iter()
            .chain(g[28..36].iter())
            .any(|&col| col < 8 || col >= g[1])
        || [g[28], g[30], g[34]].iter().any(|&col| col + 3 >= g[1])
        || g[27] != 4 + 4 * g[2] + 4 * g[3] + 11
        || g[40] != 3 * 32
    {
        return Err("unsupported HTLC trace geometry".into());
    }
    Ok(Plan {
        trace: MatrixSpec::new(
            htlc::HEIGHT.ilog2(),
            htlc::WIDTH,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?,
        public: MatrixSpec::new(0, htlc::N_PUBLIC, Extension::Base, RowOrder::Natural, 1)?,
        regions: usize::try_from(g[2] + g[3] + 2 + g[12] - g[11])
            .map_err(|_| "HTLC region count overflow")?,
        input_words: INPUT_WORDS,
        geometry_words: GEOMETRY_WORDS,
    })
}

impl DeviceSession {
    pub(crate) fn htlc_witness(
        &self,
        witness: &htlc::Witness,
        host_allowance: usize,
        run: &crate::proving::Run,
    ) -> Result<WalletTrace, String> {
        self.generate_wallet(
            plan(host_allowance)?,
            &htlc::device_trace_geometry(),
            || input_words(witness),
            [
                "device_htlc_regions",
                "device_htlc_columns",
                "device_htlc_public",
            ],
            run,
        )
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests;
