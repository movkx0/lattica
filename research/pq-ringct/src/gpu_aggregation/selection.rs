//! Measured layout selection is a cost hint, never proof admission.
use super::*;
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub(crate) struct Cost {
    pub family: String,
    pub width: usize,
    pub baseline: Vec<f64>,
    pub candidate: Vec<f64>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Selection {
    schema: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    baseline_width: Option<usize>,
    #[serde(default)]
    memory: Option<serde_json::Value>,
    source_sha3: String,
    device_uuid: String,
    costs: Vec<Cost>,
}
fn median(values: &[f64]) -> Result<f64> {
    ensure(
        values.len() >= 3 && values.len() <= 9 && values.iter().all(|v| v.is_finite() && *v > 0.0),
        "cost samples must contain 3..9 positive finite observations",
    )?;
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    Ok(if values.len() % 2 == 1 {
        values[values.len() / 2]
    } else {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    })
}
pub(crate) fn choose(
    costs: &[Cost],
    family: &str,
    maximum: usize,
    default: usize,
) -> Result<usize> {
    ensure(
        matches!(maximum, 1 | 2 | 4 | 8),
        "invalid maximum grouping width",
    )?;
    let mut selected = (1.0, default.min(maximum));
    let mut seen = std::collections::BTreeSet::new();
    for cost in costs.iter().filter(|c| c.family == family) {
        ensure(
            matches!(cost.width, 1 | 2 | 4 | 8)
                && seen.insert(cost.width)
                && cost.baseline.len() == cost.candidate.len(),
            "duplicate/invalid grouping cost",
        )?;
        let baseline = median(&cost.baseline)?;
        let candidate = median(&cost.candidate)?;
        let ratio = candidate / baseline;
        if cost.width <= maximum
            && ratio <= 0.90
            && (ratio < selected.0 || (ratio == selected.0 && cost.width < selected.1))
        {
            selected = (ratio, cost.width);
        }
    }
    Ok(selected.1)
}
pub(crate) fn widths(options: &Options) -> Result<(usize, usize)> {
    if options.profile == "legacy" {
        return Ok((options.group_width, 1));
    }
    let Some(path) = &options.selection else {
        ensure(
            options.command != "run",
            "grouped-v2 run requires a measured selection file; use screen first",
        )?;
        return Ok((options.group_width, options.group_width));
    };
    ensure(
        std::fs::metadata(path).map_err(error)?.len() <= 1 << 20,
        "selection file too large",
    )?;
    let value: Selection =
        serde_json::from_slice(&std::fs::read(path).map_err(error)?).map_err(error)?;
    ensure(
        (if options.profile == "grouped-v4" {
            value.schema == "ringct-gpu-aggregation-selection-v3"
                && value.profile.as_deref() == Some("grouped-v4") && value.baseline_width == Some(4)
                && value.memory == Some(memory::signature(options)?)
        } else if options.profile == "grouped-v3" {
            value.schema == "ringct-gpu-aggregation-selection-v2"
                && value.profile.as_deref() == Some("grouped-v3")
                && value.baseline_width == Some(2)
        } else {
            value.schema == "ringct-gpu-aggregation-selection-v1"
        }) && value.source_sha3 == hex(&crate::graph_proofs::compiled_source_fingerprint())
            && value.device_uuid == std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap_or_default()
            && !value.device_uuid.is_empty()
            && value.costs.len() <= 32,
        "selection source/device identity mismatch",
    )?;
    Ok((
        choose(&value.costs, "shake", options.group_width, if options.profile == "grouped-v4" { 4 } else { 2 })?,
        choose(
            &value.costs,
            "graph",
            options.group_width,
            if options.profile == "grouped-v4" { 4 } else if options.profile == "grouped-v3" {
                2
            } else {
                1
            },
        )?,
    ))
}
pub(super) fn graph_costs(options: &Options, maximum: usize) -> Result<Vec<(usize, f64)>> {
    // widths() validates the source/device binding before this data is used.
    widths(options)?;
    let mut result = vec![(1, 1.0)];
    if matches!(options.profile.as_str(), "grouped-v3" | "grouped-v4") && maximum >= 2 {
        result.push((2, 1.0));
    }
    if options.profile == "grouped-v4" && maximum >= 4 { result.push((4, 1.0)); }
    if let Some(path) = &options.selection {
        let value: Selection =
            serde_json::from_slice(&std::fs::read(path).map_err(error)?).map_err(error)?;
        for cost in value
            .costs
            .iter()
            .filter(|c| c.family == "graph" && c.width > 1 && c.width <= maximum)
        {
            let ratio = median(&cost.candidate)? / median(&cost.baseline)?;
            if ratio <= 0.9 {
                result.retain(|(width, _)| *width != cost.width);
                result.push((cost.width, ratio));
            }
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn costs_require_repeatable_gain_and_choose_small_ties() {
        assert_eq!(choose(&[], "shake", 1, 2).unwrap(), 1);
        assert!(choose(&[], "shake", 0, 2).is_err());
        let mut costs = vec![Cost {
            family: "shake".into(),
            width: 4,
            baseline: vec![10.; 3],
            candidate: vec![9.1; 3],
        }];
        assert_eq!(choose(&costs, "shake", 8, 2).unwrap(), 2);
        costs[0].candidate = vec![8.; 3];
        assert_eq!(choose(&costs, "shake", 8, 2).unwrap(), 4);
        costs.push(Cost {
            width: 8,
            ..costs[0].clone()
        });
        assert_eq!(choose(&costs, "shake", 8, 2).unwrap(), 4);
        costs[0].candidate[0] = f64::NAN;
        assert!(choose(&costs, "shake", 8, 2).is_err());
    }
}
