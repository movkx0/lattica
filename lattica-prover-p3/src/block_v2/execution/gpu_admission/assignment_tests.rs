use super::*;
#[cfg(feature = "stream")]
use crate::spill_alloc::allocation_requests::measure;
#[cfg(feature = "stream")]
use std::io::Cursor;

#[test]
fn assignment_decoder_matches_json_values_and_rejections() {
    let corpus = [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "-9223372036854775808",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775809",
        "1.25",
        "1e308",
        "1e-308",
        r#""escaped\n\t\"\\\u0000\ud83e\udd80""#,
        r#"{"z":[null,true,false,1.25],"a":{"u":"é GPU 🦀"}}"#,
        r#"{"same":1,"same":{"last":[1,2,3]}}"#,
        r#"{"":"empty","\u0000":"nul","$serde_json::private::Number":"7"}"#,
        r#"{"array":[],"object":{}}"#,
        "",
        " ",
        "{",
        "[]{}",
        "01",
        "NaN",
        "1e999",
        "-1e999",
        r#""\ud800""#,
        r#"{"a":}"#,
        r#"{"a":1,}"#,
        r#"[1,]"#,
    ];
    for input in corpus {
        let reference = serde_json::from_str::<Value>(input);
        let bounded = decode(input.as_bytes(), DECODED_BYTES);
        match (reference, bounded) {
            (Ok(reference), Ok((bounded, charged))) => {
                assert_eq!(bounded, reference, "{input}");
                assert_eq!(
                    serde_json::to_vec(&bounded).unwrap(),
                    serde_json::to_vec(&reference).unwrap()
                );
                assert!(charged <= DECODED_BYTES);
            }
            (Err(_), Err(_)) => {}
            _ => panic!("assignment decoder differs for {input:?}"),
        }
    }
    for depth in [1, 32, 126, 127, 128, 129] {
        let input = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            decode(input.as_bytes(), DECODED_BYTES).is_ok(),
            serde_json::from_str::<Value>(&input).is_ok()
        );
    }
    assert!(decode(&[b'"', 0xff, b'"'], DECODED_BYTES).is_err());
    eprintln!(
        "gpu_assignment_json_equivalence corpus={} depth_cases=6 invalid_utf8_rejected=true",
        corpus.len()
    );
}

#[test]
#[cfg(feature = "stream")]
fn decoded_quota_covers_arrays_map_nodes_strings_and_replacements() {
    let mut cases = 0;
    for length in [
        0, 1, 3, 4, 5, 7, 8, 9, 31, 32, 33, 127, 128, 129, 4096, 4097, 32769,
    ] {
        let input = serde_json::to_vec(&vec![Value::Null; length]).unwrap();
        let ((value, charged), requested) = measure(|| decode(&input, DECODED_BYTES).unwrap());
        assert_eq!(value, serde_json::from_slice::<Value>(&input).unwrap());
        assert!(!requested.overflow && requested.bytes <= charged);
        if charged != 0 {
            assert!(decode(&input, charged - 1).is_err());
            assert!(decode(&input, charged).is_ok());
        }
        cases += 1;
    }
    for length in [1, 6, 11, 12, 35, 71, 1024, 8192] {
        let input = format!(
            "{{{}}}",
            (0..length)
                .map(|n| format!("\"k{n:05}\":\"v{n:05}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let ((value, charged), requested) =
            measure(|| decode(input.as_bytes(), DECODED_BYTES).unwrap());
        assert_eq!(value, serde_json::from_str::<Value>(&input).unwrap());
        assert!(!requested.overflow && requested.bytes <= charged);
        assert!(decode(input.as_bytes(), charged - 1).is_err());
        assert!(decode(input.as_bytes(), charged).is_ok());
        cases += 1;
    }
    for input in [
        r#"{"a":"one","a":["two","three"],"a":{"last":"four"}}"#.to_owned(),
        format!(r#"{{"large":"{}"}}"#, "x".repeat(1 << 18)),
    ] {
        let ((value, charged), requested) =
            measure(|| decode(input.as_bytes(), DECODED_BYTES).unwrap());
        assert_eq!(value, serde_json::from_str::<Value>(&input).unwrap());
        assert!(!requested.overflow && requested.bytes <= charged);
        assert!(decode(input.as_bytes(), charged - 1).is_err());
        assert!(decode(input.as_bytes(), charged).is_ok());
        cases += 1;
    }
    let input = format!(r#"{{"large":"{}"}}"#, "x".repeat(1 << 18));
    let (rejected, requested) = measure(|| decode(input.as_bytes(), MAP_ENTRY_BYTES + 5));
    assert!(rejected.is_err());
    assert!(!requested.overflow && requested.largest < 4096 && requested.bytes < 4096);
    let input = format!(
        "{{{}}}",
        (0..20000)
            .map(|n| format!("\"k{n}\":null"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(input.len() < MAX_ASSIGNMENT_BYTES as usize);
    assert!(decode(input.as_bytes(), DECODED_BYTES).is_err());
    eprintln!("gpu_assignment_payload_quota boundary_cases={cases} limit_bytes={DECODED_BYTES} map_entry_bytes={MAP_ENTRY_BYTES} large_value_rejected_before_copy=true dense_object_rejected=true");
}

#[test]
#[cfg(feature = "stream")]
fn escaped_input_keeps_parser_scratch_inside_its_envelope() {
    for length in [1, 4096, 131072] {
        let input = format!(r#"{{"escaped":"{}"}}"#, "\\u0000".repeat(length));
        assert!(input.len() <= MAX_ASSIGNMENT_BYTES as usize);
        let ((value, charged), requested) =
            measure(|| decode(input.as_bytes(), DECODED_BYTES).unwrap());
        assert_eq!(value, serde_json::from_str::<Value>(&input).unwrap());
        assert!(!requested.overflow && requested.bytes <= charged + PARSER_BYTES);
        eprintln!("gpu_assignment_parser escaped_values={length} charged_bytes={charged} requested_bytes={} parser_allowance_bytes={PARSER_BYTES}", requested.bytes);
    }
}

#[test]
#[cfg(feature = "stream")]
fn input_read_uses_one_exact_buffer_and_a_bounded_growth_probe() {
    for length in [0, 1, 31, 65536, MAX_ASSIGNMENT_BYTES as usize] {
        let input = vec![b' '; length];
        let (output, requested) = measure(|| read_bytes(input.as_slice()).unwrap());
        assert_eq!(output.len(), length);
        assert_eq!(output.capacity(), MAX_ASSIGNMENT_BYTES as usize + 1);
        assert_eq!(requested.calls, 1);
        assert_eq!(requested.bytes, MAX_ASSIGNMENT_BYTES as usize + 1);
    }
    let mut reader = Cursor::new(vec![b' '; MAX_ASSIGNMENT_BYTES as usize + 1024]);
    assert!(read_bytes(&mut reader).is_err());
    assert_eq!(reader.position(), MAX_ASSIGNMENT_BYTES + 1);
    struct Interrupted(bool, Cursor<Vec<u8>>);
    impl Read for Interrupted {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if !self.0 {
                self.0 = true;
                Err(ErrorKind::Interrupted.into())
            } else {
                let length = output.len().min(7);
                self.1.read(&mut output[..length])
            }
        }
    }
    let input = vec![b' '; 128];
    assert_eq!(
        read_bytes(Interrupted(false, Cursor::new(input.clone()))).unwrap(),
        input
    );
    eprintln!("gpu_assignment_input_buffer capacity_bytes={} exact_cases=5 bounded_probe=true interrupted_reads=true", MAX_ASSIGNMENT_BYTES + 1);
}

#[test]
fn startup_assignment_floor_fits_before_typed_input_decoding() {
    for bytes in [0, HOST_BYTES - 1] {
        assert!(admit_host(bytes).is_err());
    }
    admit_host(HOST_BYTES).unwrap();
    admit_host(u64::MAX).unwrap();
    assert!(DECODED_BYTES as u64 + MAX_ASSIGNMENT_BYTES + 1 + PARSER_BYTES as u64 <= HOST_BYTES);
    layout().unwrap();
    #[cfg(all(target_os = "linux", feature = "stream"))]
    {
        assert!(HOST_BYTES <= crate::block_v2::execution::worker::typed::storage::INPUT_HOST_BYTES);
        eprintln!("gpu_assignment_startup_floor host_bytes={HOST_BYTES} decoded_bytes={DECODED_BYTES} parser_bytes={PARSER_BYTES} typed_input_reservation_bytes={}", crate::block_v2::execution::worker::typed::storage::INPUT_HOST_BYTES);
    }
}
