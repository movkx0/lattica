use super::*;
use crate::execution::retained_resources::{
    Bytes, Category, Ledger, Requirements, Reservation, Snapshot, WorkerAllowance,
};
use core::mem::{size_of, size_of_val};
use p3_field::PrimeCharacteristicRing;

const FIXTURE_INNER: usize = 16;
const FIXTURE_BYTES: usize = HEADER_BYTES + FIXTURE_INNER;

struct Fixture {
    public: [Val; PUBLICS],
    cap: [[Val; 4]; CAP_ROOTS],
    height: usize,
}

impl Fixture {
    fn new() -> Self {
        let mut result = Self {
            public: core::array::from_fn(|index| Val::from_u64(index as u64 + 5)),
            cap: core::array::from_fn(|root| core::array::from_fn(|column| {
                Val::from_u64((root * 4 + column + 71) as u64)
            })),
            height: 8,
        };
        result.public[0] = Val::ZERO;
        result.public[PUBLICS - 1] = Val::NEG_ONE;
        result.cap[0][0] = Val::ZERO;
        result.cap[CAP_ROOTS - 1][3] = Val::NEG_ONE;
        result
    }

    fn values(&self) -> RootHeaderValues<'_> {
        RootHeaderValues { height: self.height, public: &self.public, cap: &self.cap }
    }
}

// Test bootstrap is outside the measured phase. The reservation precedes all
// synthetic payloads; this is requested-storage evidence, never physical fit.
fn test_claim(ledger: &Ledger) -> Reservation {
    let parts = [
        size_of::<Fixture>(), size_of::<[u8; FIXTURE_BYTES]>(),
        size_of::<[u8; FIXTURE_BYTES + 1]>(), size_of::<[u8; 8]>(),
        size_of::<RootHeaderValues<'static>>(), size_of::<HeaderCheckedPacket<'static>>(),
        size_of::<Result<HeaderCheckedPacket<'static>, HeaderRefusal>>(),
        size_of::<HeaderProbeReport>(), size_of::<HeaderProbeError>(),
        size_of::<Result<HeaderProbeReport, HeaderProbeError>>(),
        size_of::<HeaderRefusal>(), size_of::<Result<(), HeaderRefusal>>(),
        size_of::<Vec<u8>>(), size_of::<std::collections::TryReserveError>(),
        size_of::<Ledger>(), size_of::<Reservation>(), size_of::<Snapshot>(),
        size_of::<Requirements>(), size_of::<Bytes>(), size_of::<WorkerAllowance>(),
        size_of::<[usize; 128]>(),
    ];
    let frames = parts.into_iter().try_fold(size_of_val(&parts), usize::checked_add).unwrap();
    let host = frames.checked_mul(16).unwrap()
        .checked_add(PACKET_LIMIT + 1).unwrap()
        .checked_add(64 << 10).unwrap();
    ledger.admit_phase(Requirements::single(Category::PhaseScratch, Bytes {
        host: u64::try_from(host).unwrap(), device: 0,
    })).unwrap()
}

fn packet(fixture: &Fixture) -> [u8; FIXTURE_BYTES] {
    let mut bytes = [0u8; FIXTURE_BYTES];
    bytes[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(codec::REGISTERED_PROOF_MAGIC);
    bytes[HEADER_BYTES + 8..].copy_from_slice(&[0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f]);
    encode_header(fixture.values(), FIXTURE_INNER, &mut bytes[..HEADER_BYTES]).unwrap();
    bytes
}

fn clean(ledger: &Ledger) {
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert!(ledger.snapshot().categories.iter().all(|entry| entry.current == Bytes::ZERO));
}

#[test]
fn fixed_header_has_explicit_little_endian_fields_and_preserves_inner_bytes() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let _original = test_claim(&ledger);
        let fixture = Fixture::new();
        let bytes = packet(&fixture);
        assert_eq!(&bytes[..8], b"LRCART01");
        assert_eq!(&bytes[8..24], b"RC_SHAKE_ROOT_V1");
        assert_eq!(&bytes[24..32], &[1, 0, 0xb0, 9, 46, 0, 64, 0]);
        assert_eq!(&bytes[32..40], &2u64.to_le_bytes());
        assert_eq!(&bytes[40..48], &16u64.to_le_bytes());
        assert_eq!(&bytes[48..56], &8u64.to_le_bytes());
        assert_eq!(&bytes[56..64], &1u64.to_le_bytes());
        assert_eq!(&bytes[64..72], &0u64.to_le_bytes());
        assert_eq!(&bytes[424..432], &(MODULUS - 1).to_le_bytes());
        assert_eq!(&bytes[432..440], &0u64.to_le_bytes());
        assert_eq!(&bytes[2472..2480], &(MODULUS - 1).to_le_bytes());
        let checked = validate_packet(&bytes, fixture.values()).unwrap();
        assert_eq!(checked.inner(), &bytes[2480..]);
        assert_eq!(&checked.inner()[8..], &[0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f]);
    }
    clean(&ledger);
}

#[test]
fn all_supported_heights_run_fixed_typed_probes_and_restore_scratch() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let _original = test_claim(&ledger);
        let mut fixture = Fixture::new();
        for log in 3..=20 {
            fixture.height = 1 << log;
            let original = packet(&fixture);
            let mut scratch = [0u8; FIXTURE_BYTES + 1];
            let report = probe_packet(&original, &mut scratch, fixture.values()).unwrap();
            assert_eq!(report.positive_checks, 2);
            assert_eq!(report.syntax_rejections, 24);
            assert_eq!(report.public_rejections, 46);
            assert_eq!(report.cap_rejections, 256);
            assert_eq!(report.height_rejections, 1);
            assert_eq!(report.canonical_rejections, 302);
            assert_eq!(&scratch[..FIXTURE_BYTES], &original);
            assert!(validate_packet(&original, fixture.values()).is_ok());
        }
    }
    clean(&ledger);
}

#[test]
fn every_short_prefix_and_untrusted_length_is_refused_before_inner_access() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let _original = test_claim(&ledger);
        let fixture = Fixture::new();
        let mut bytes = packet(&fixture);
        for cut in 0..MIN_PACKET {
            assert!(matches!(validate_packet(&bytes[..cut], fixture.values()), Err(HeaderRefusal::Truncated)));
        }
        for length in [0, 7, u64::MAX, (PACKET_LIMIT - HEADER_BYTES + 1) as u64] {
            write_u64(&mut bytes, INNER_LENGTH, length);
            assert!(matches!(validate_packet(&bytes, fixture.values()), Err(HeaderRefusal::InnerLength)));
        }
        write_u64(&mut bytes, INNER_LENGTH, 15);
        assert!(matches!(validate_packet(&bytes, fixture.values()), Err(HeaderRefusal::PacketLength)));
    }
    clean(&ledger);
}

#[test]
fn changed_local_profile_context_spec_endpoints_cap_and_height_refuse_equality() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let _original = test_claim(&ledger);
        let fixture = Fixture::new();
        let bytes = packet(&fixture);
        for index in [0, 8, 16, 20, 24, 28, 29, 30, 31, 32, 33, 34, 38, 45] {
            let mut changed = Fixture::new();
            changed.public[index] += Val::ONE;
            assert!(matches!(validate_packet(&bytes, changed.values()),
                Err(HeaderRefusal::PublicMismatch(actual)) if usize::from(actual) == index));
        }
        let mut changed = Fixture::new();
        changed.cap[63][3] += Val::ONE;
        assert!(matches!(validate_packet(&bytes, changed.values()), Err(HeaderRefusal::CapMismatch(255))));
        changed.cap = fixture.cap;
        changed.height = 16;
        assert!(matches!(validate_packet(&bytes, changed.values()), Err(HeaderRefusal::HeightMismatch)));
        changed.height = 7;
        assert!(matches!(validate_packet(&bytes, changed.values()), Err(HeaderRefusal::ExpectedHeight)));
    }
    clean(&ledger);
}

#[test]
fn full_packet_limit_includes_header_and_trailing_probe_uses_no_larger_buffer() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let _original = test_claim(&ledger);
        let fixture = Fixture::new();
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(PACKET_LIMIT + 1).unwrap();
        assert_eq!(bytes.capacity(), PACKET_LIMIT + 1);
        bytes.resize(PACKET_LIMIT + 1, 0);
        bytes[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(codec::REGISTERED_PROOF_MAGIC);
        encode_header(fixture.values(), PACKET_LIMIT - HEADER_BYTES, &mut bytes[..HEADER_BYTES]).unwrap();
        assert!(validate_packet(&bytes[..PACKET_LIMIT], fixture.values()).is_ok());
        assert!(matches!(validate_packet(&bytes, fixture.values()), Err(HeaderRefusal::PacketLimit)));
        assert!(matches!(probe_packet(&bytes[..PACKET_LIMIT], &mut [], fixture.values()), Err(HeaderProbeError::NoTrailingRoom)));
        assert_eq!(encode_header(fixture.values(), PACKET_LIMIT - HEADER_BYTES + 1, &mut bytes[..HEADER_BYTES]), Err(HeaderRefusal::InnerLength));
        assert_eq!(encode_header(fixture.values(), FIXTURE_INNER, &mut bytes), Err(HeaderRefusal::HeaderBuffer));
        assert_eq!(encode_header(fixture.values(), FIXTURE_INNER, &mut bytes[..HEADER_BYTES - 1]), Err(HeaderRefusal::HeaderBuffer));
    }
    clean(&ledger);
}

#[test]
fn short_probe_scratch_is_refused_without_changing_the_original_packet() {
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 0 });
    {
        let _original = test_claim(&ledger);
        let fixture = Fixture::new();
        let original = packet(&fixture);
        let mut scratch = [0u8; FIXTURE_BYTES];
        assert!(matches!(probe_packet(&original, &mut scratch, fixture.values()), Err(HeaderProbeError::ScratchTooSmall)));
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert!(validate_packet(&original, fixture.values()).is_ok());
    }
    clean(&ledger);
}
