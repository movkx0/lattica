use super::*;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

const ALL: Rounds = Rounds {
    random: true,
    preprocessed: true,
    permutation: true,
};
const LIMIT: usize = 1 << 20;

fn spare<T>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    let items: Vec<_> = items.into_iter().collect();
    let mut values = Vec::with_capacity(items.len() + 3);
    values.extend(items);
    values
}

fn fixture<T>(rounds: Rounds, mut value: impl FnMut(usize) -> T) -> (PcsValues<T>, Vec<Instance>) {
    let mut serial = 0;
    let mut matrix = |points: usize, width: usize| {
        spare((0..points).map(|_| {
            spare((0..width).map(|_| {
                serial += 1;
                value(serial)
            }))
        }))
    };
    let mut values = Vec::with_capacity(8);
    if rounds.random {
        values.push(spare((0..3).map(|_| matrix(1, 1))));
    }
    values.push(spare([matrix(2, 2), matrix(1, 3), matrix(2, 4)]));
    values.push(spare((0..6).map(|_| matrix(1, 3))));
    if rounds.preprocessed {
        values.push(spare([matrix(1, 5), matrix(2, 6)]));
    }
    if rounds.permutation {
        values.push(spare([matrix(2, 4), matrix(2, 5)]));
    }
    let layout = vec![
        Instance {
            main_next: true,
            quotient_start: 0,
            quotient_end: 2,
            preprocessed: rounds.preprocessed.then_some((1, true)),
            permutation: rounds.permutation,
        },
        Instance {
            main_next: false,
            quotient_start: 2,
            quotient_end: 3,
            preprocessed: None,
            permutation: false,
        },
        Instance {
            main_next: true,
            quotient_start: 3,
            quotient_end: 6,
            preprocessed: rounds.preprocessed.then_some((0, false)),
            permutation: rounds.permutation,
        },
    ];
    (values, layout)
}

// Preserve the old borrowing/cloning assembly as an encoding oracle. Round
// order and the native types are those of p3-batch-stark 0.6.1 (Apache-2.0).
fn reference<T: Clone>(
    values: &PcsValues<T>,
    layout: &[Instance],
    r: Rounds,
) -> Vec<OpenedValuesWithLookups<T>> {
    let trace_index = usize::from(r.random);
    let quotient_index = trace_index + 1;
    let preprocessed_index = quotient_index + 1;
    let permutation_index = preprocessed_index + usize::from(r.preprocessed);
    let mut permutation = 0;
    layout
        .iter()
        .enumerate()
        .map(|(i, meta)| {
            let (preprocessed_local, preprocessed_next) =
                meta.preprocessed.map_or((None, None), |(m, next)| {
                    (
                        Some(values[preprocessed_index][m][0].clone()),
                        next.then(|| values[preprocessed_index][m][1].clone()),
                    )
                });
            let (permutation_local, permutation_next) = if meta.permutation {
                let rows = &values[permutation_index][permutation];
                permutation += 1;
                (rows[0].clone(), rows[1].clone())
            } else {
                (vec![], vec![])
            };
            OpenedValuesWithLookups {
                base_opened_values: OpenedValues {
                    trace_local: values[trace_index][i][0].clone(),
                    trace_next: meta.main_next.then(|| values[trace_index][i][1].clone()),
                    preprocessed_local,
                    preprocessed_next,
                    quotient_chunks: (meta.quotient_start..meta.quotient_end)
                        .map(|m| values[quotient_index][m][0].clone())
                        .collect(),
                    random: r.random.then(|| values[0][i][0].clone()),
                },
                permutation_local,
                permutation_next,
            }
        })
        .collect()
}

// Deliberately not Clone: every element must move, and every failure must
// release its inputs exactly once without leaking partially assembled output.
#[derive(Debug)]
struct Token {
    id: usize,
    drops: Rc<Cell<usize>>,
}
impl Drop for Token {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn owned_fixture() -> (PcsValues<Token>, Vec<Instance>, Rc<Cell<usize>>, usize) {
    let drops = Rc::new(Cell::new(0));
    let mut created = 0;
    let (values, layout) = fixture(ALL, |id| {
        created += 1;
        Token {
            id,
            drops: drops.clone(),
        }
    });
    (values, layout, drops, created)
}

fn rows<T>(instances: &[OpenedValuesWithLookups<T>]) -> Vec<&Vec<T>> {
    let mut rows = Vec::new();
    for instance in instances {
        let base = &instance.base_opened_values;
        rows.push(&base.trace_local);
        rows.extend(base.trace_next.iter());
        rows.extend(base.preprocessed_local.iter());
        rows.extend(base.preprocessed_next.iter());
        rows.extend(&base.quotient_chunks);
        rows.extend(base.random.iter());
        if !instance.permutation_local.is_empty() {
            rows.push(&instance.permutation_local);
            rows.push(&instance.permutation_next);
        }
    }
    rows
}

#[test]
fn moves_non_clone_fields_with_their_original_pointers_and_capacities() {
    let (values, layout, drops, created) = owned_fixture();
    let originals: BTreeMap<_, _> = values
        .iter()
        .flatten()
        .flatten()
        .map(|row| (row[0].id, (row.as_ptr(), row.len(), row.capacity())))
        .collect();
    let output = assemble(values, layout.into_iter(), ALL, LIMIT).unwrap();
    assert_eq!(drops.get(), 0);
    let actual: BTreeMap<_, _> = rows(&output)
        .iter()
        .map(|row| (row[0].id, (row.as_ptr(), row.len(), row.capacity())))
        .collect();
    assert_eq!(actual, originals);
    assert_eq!(
        rows(&output).iter().map(|row| row.len()).sum::<usize>(),
        created
    );
    assert_eq!(output.capacity(), 3);
    for instance in &output {
        let chunks = &instance.base_opened_values.quotient_chunks;
        assert_eq!(chunks.len(), chunks.capacity());
    }
    // Reordered preprocessing is attached to its instance, not matrix order.
    assert_eq!(
        output[0]
            .base_opened_values
            .preprocessed_local
            .as_ref()
            .unwrap()
            .len(),
        6
    );
    assert!(output[1].base_opened_values.preprocessed_local.is_none());
    assert_eq!(
        output[2]
            .base_opened_values
            .preprocessed_local
            .as_ref()
            .unwrap()
            .len(),
        5
    );
    drop(output);
    assert_eq!(drops.get(), created);
}

#[test]
fn encoding_matches_reference_for_every_optional_round_combination() {
    for flags in 0..8 {
        let r = Rounds {
            random: flags & 1 != 0,
            preprocessed: flags & 2 != 0,
            permutation: flags & 4 != 0,
        };
        let (values, layout) = fixture(r, |n| n as u64);
        let expected = postcard::to_allocvec(&reference(&values, &layout, r)).unwrap();
        let output = assemble(values, layout.into_iter(), r, LIMIT).unwrap();
        assert_eq!(
            postcard::to_allocvec(&output).unwrap(),
            expected,
            "flags={flags}"
        );
    }
}

#[test]
fn single_instance_encoding_matches_frozen_native_layout() {
    let values = vec![vec![vec![vec![7u64], vec![8]]], vec![vec![vec![9]]]];
    let layout = vec![Instance {
        main_next: true,
        quotient_start: 0,
        quotient_end: 1,
        preprocessed: None,
        permutation: false,
    }];
    let r = Rounds {
        random: false,
        preprocessed: false,
        permutation: false,
    };
    let frozen = [1, 1, 7, 1, 1, 8, 0, 0, 1, 1, 9, 0, 0, 0];
    assert_eq!(
        postcard::to_allocvec(&reference(&values, &layout, r)).unwrap(),
        frozen
    );
    assert_eq!(
        postcard::to_allocvec(&assemble(values, layout.into_iter(), r, LIMIT).unwrap()).unwrap(),
        frozen
    );
}

#[test]
fn capacity_census_and_combined_exact_boundary_include_spare_storage() {
    let (values, layout) = fixture(ALL, |n| n as u64);
    let plan = Storage::plan(&values, layout.len(), ALL, LIMIT).unwrap();
    // Separate heap census, including unused slots of every nested vector.
    let mut used_slots = 0;
    let mut spare_slots = 0;
    macro_rules! census {
        ($v:expr) => {{
            let v = $v;
            used_slots += std::mem::size_of_val(v.as_slice());
            spare_slots += (v.capacity() - v.len()) * std::mem::size_of_val(&v[0]);
        }};
    }
    census!(&values);
    for round in &values {
        census!(round);
        for matrix in round {
            census!(matrix);
            for row in matrix {
                census!(row);
            }
        }
    }
    assert!(spare_slots > 0);
    assert_eq!(plan.input_bytes, used_slots + spare_slots);
    let exact = plan.total_bytes;
    assert!(Storage::plan(&values, layout.len(), ALL, exact - 1).is_err());
    let output = assemble(values, layout.into_iter(), ALL, exact).unwrap();
    let actual_new_descriptors = output.capacity() * size_of::<OpenedValuesWithLookups<u64>>()
        + output
            .iter()
            .map(|i| i.base_opened_values.quotient_chunks.capacity() * size_of::<Vec<u64>>())
            .sum::<usize>()
        + 3 * size_of::<Instance>()
        + 2 * size_of::<bool>();
    assert_eq!(plan.descriptor_bytes, actual_new_descriptors);
    assert_eq!(plan.total_bytes, plan.input_bytes + actual_new_descriptors);
}

#[test]
fn insufficient_allowance_releases_every_input_without_cloning() {
    let (values, layout, drops, created) = owned_fixture();
    let limit = Storage::plan(&values, layout.len(), ALL, LIMIT)
        .unwrap()
        .total_bytes
        - 1;
    assert!(assemble(values, layout.into_iter(), ALL, limit)
        .unwrap_err()
        .contains("allowance"));
    assert_eq!(drops.get(), created);
}

#[test]
fn malformed_geometry_rejects_and_releases_owned_inputs() {
    type Mutation = fn(&mut PcsValues<Token>, &mut Vec<Instance>);
    let mutations: &[Mutation] = &[
        |v, _| {
            v.clear();
        },
        |v, _| {
            v.push(Vec::new());
        },
        |v, _| {
            v[0].pop();
        },
        |v, _| {
            v[0][0].push(Vec::new());
        },
        |v, _| {
            v[1].pop();
        },
        |v, _| {
            v[1][0].pop();
        },
        |v, _| {
            v[1][0][1].pop();
        },
        |v, _| {
            v[2][0].push(Vec::new());
        },
        |v, _| {
            v[2].push(Vec::new());
        },
        |_, m| {
            m[0].quotient_start = 1;
        },
        |_, m| {
            m[1].quotient_start = 1;
        },
        |_, m| {
            m[1].quotient_end = 2;
        },
        |_, m| {
            m[2].quotient_end = usize::MAX;
        },
        |_, m| {
            m[2].quotient_end = 5;
        },
        |_, m| {
            m[2].preprocessed = m[0].preprocessed;
        },
        |_, m| {
            m[2].preprocessed = None;
        },
        |_, m| {
            m[2].preprocessed = Some((2, false));
        },
        |v, _| {
            v[3][0].push(Vec::new());
        },
        |v, _| {
            v[3].clear();
        },
        |v, _| {
            v[4].pop();
        },
        |v, _| {
            v[4][0].pop();
        },
        |_, m| {
            m[0].permutation = false;
        },
        |_, m| {
            m.clear();
        },
    ];
    for (case, mutation) in mutations.iter().enumerate() {
        let (mut values, mut layout, drops, created) = owned_fixture();
        mutation(&mut values, &mut layout);
        assert!(
            assemble(values, layout.into_iter(), ALL, LIMIT).is_err(),
            "case={case}"
        );
        assert_eq!(drops.get(), created, "case={case}");
    }
    for r in [
        Rounds {
            random: false,
            ..ALL
        },
        Rounds {
            preprocessed: false,
            ..ALL
        },
        Rounds {
            permutation: false,
            ..ALL
        },
    ] {
        let (values, layout, drops, created) = owned_fixture();
        assert!(assemble(values, layout.into_iter(), r, LIMIT).is_err());
        assert_eq!(drops.get(), created);
    }
}

#[test]
fn byte_overflow_and_invalid_allowances_are_rejected() {
    assert!(bytes::<u64>(usize::MAX).is_err());
    assert!(bytes::<u64>((isize::MAX as usize / 8) + 1).is_err());
    assert!(exact_vec::<u64>(usize::MAX).is_err());
    let mut total = usize::MAX;
    assert!(add(&mut total, 1).is_err());
    let (values, layout) = fixture(ALL, |n| n as u64);
    assert!(Storage::plan(&values, layout.len(), ALL, 0).is_err());
    assert!(Storage::plan(
        &values,
        layout.len(),
        ALL,
        crate::block_v2::resident_pcs::HOST_OUTPUT_BUDGET + 1
    )
    .is_err());
    let (values, layout) = fixture(ALL, |_| ());
    assert!(assemble(values, layout.into_iter(), ALL, LIMIT).is_err());
}

#[test]
fn supports_the_device_instance_bound_without_spare_output_descriptors() {
    let r = Rounds {
        random: false,
        preprocessed: false,
        permutation: false,
    };
    let values = vec![
        (0..256).map(|i| vec![vec![i as u64]]).collect(),
        (0..256).map(|i| vec![vec![i as u64 + 256]]).collect(),
    ];
    let layout = (0..256).map(|i| Instance {
        main_next: false,
        quotient_start: i,
        quotient_end: i + 1,
        preprocessed: None,
        permutation: false,
    });
    let output = assemble(values, layout, r, LIMIT).unwrap();
    assert_eq!(output.capacity(), 256);
    for (i, instance) in output.iter().enumerate() {
        let base = &instance.base_opened_values;
        assert_eq!(base.trace_local, [i as u64]);
        assert_eq!(base.quotient_chunks, [vec![i as u64 + 256]]);
        assert_eq!(base.quotient_chunks.capacity(), 1);
    }
}
