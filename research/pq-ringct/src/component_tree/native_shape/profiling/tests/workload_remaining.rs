//! Exact public recipes captured from the metadata-only N3 replay.
//! This contains no compiled bounds: qualification compiles every descriptor.
use super::*;
use cache::{PortableDescriptor, PortableRow};

pub(super) fn catalogue() -> Vec<Case> {
    #[derive(serde::Deserialize)]
    struct Entry { descriptor_key: [u8; 32], descriptor: PortableDescriptor }
    let entries: Vec<Entry> = serde_json::from_str(include_str!("workload_remaining.json")).unwrap();
    assert_eq!(entries.len(), 13);
    entries.into_iter().enumerate().map(|(i, entry)| {
        let (family, descriptor) = match entry.descriptor {
            PortableDescriptor::Aes { domain, start_counter, output_len, first, count } => (
                "aes", Descriptor::Native(NativeDescriptor::Aes {
                    descriptor: aes_lane_air::Descriptor { domain, start_counter, output_len }, first, count })),
            PortableDescriptor::Transcript { parts } => ("transcript", Descriptor::Transcript(parts.into_iter().map(|p| match p {
                0 => PartKind::Bytes32, 1 => PartKind::PolynomialQ, 2 => PartKind::PolynomialQhat,
                _ => panic!("unknown public transcript kind"),
            }).collect())),
            PortableDescriptor::Statement { setup_seed } => ("statement", Descriptor::Statement(setup_seed)),
            PortableDescriptor::Linear { descriptor, count } => {
                let kind = |(tag, value)| match tag {
                    0 => PolynomialKind::Canonical { modulus: value },
                    1 => PolynomialKind::Signed { bound: u32::try_from(value).unwrap() },
                    _ => panic!("unknown public linear kind"),
                };
                let row = |row: PortableRow| match row {
                    PortableRow::Uniform(value) => [value; D],
                    PortableRow::Dense(values) => values.try_into().expect("exact public coefficient width"),
                };
                let d = LinearMapDescriptor::new(descriptor.inputs.into_iter().map(kind).collect(), kind(descriptor.output),
                    descriptor.coefficients.into_iter().map(row).collect(), row(descriptor.constant)).unwrap();
                ("linear_map", Descriptor::Algebra(ComponentKind::LinearMap { descriptor: d }, count))
            }
            _ => panic!("unexpected remaining N3 family"),
        };
        let case = Case { name: format!("n3-remaining-{family}-{i}"), family, descriptor };
        assert_eq!(case.descriptor().key(), entry.descriptor_key, "public recipe differs from captured descriptor");
        case
    }).collect()
}

#[test]
fn captured_public_recipes_reconstruct_exact_keys() { assert_eq!(catalogue().len(), 13); }
