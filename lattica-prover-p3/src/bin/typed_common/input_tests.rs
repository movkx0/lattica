use super::*;
use p3_field::PrimeCharacteristicRing;
use std::io::Cursor;

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lattica-preparation-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn all_body_counts_keep_json_and_task_order_with_bounded_capacities() {
    for count in 1..=profile::MAX_TRANSACTIONS as u8 {
        let (body, expected) = tests::candidate(count);
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let parsed: Body = serde_json::from_slice(&body_bytes).unwrap();
        validate_body(&parsed).unwrap();
        assert_eq!(serde_json::to_vec(&parsed).unwrap(), body_bytes);
        assert_eq!(parsed.transactions.capacity(), commitment::CAPACITY);
        assert!(parsed
            .transactions
            .iter()
            .all(|tx| tx.statement.capacity() == input::MAX_PUBLIC));
        let expected_bytes = serde_json::to_vec(&expected).unwrap();
        let parsed_expected: Expected = serde_json::from_slice(&expected_bytes).unwrap();
        parsed_expected.validate().unwrap();
        assert_eq!(
            serde_json::to_vec(&parsed_expected).unwrap(),
            expected_bytes
        );
        let tasks = tasks(&parsed, &parsed_expected).unwrap();
        assert_eq!(tasks.capacity(), input::MAX_TASKS);
        let priorities: Vec<_> = tasks
            .iter()
            .map(|t| task_priority(t.mode, t.level, t.index))
            .collect();
        assert!(priorities.windows(2).all(|pair| pair[0] < pair[1]));
        // The prior stable sort and new in-place sort give the same order:
        // each node has a distinct priority including its tree position.
        let mut reversed: Vec<_> = tasks.iter().rev().collect();
        reversed.sort_by_key(|task| task_priority(task.mode, task.level, task.index));
        assert_eq!(
            reversed.iter().map(|t| t.name()).collect::<Vec<_>>(),
            tasks.iter().map(Task::name).collect::<Vec<_>>()
        );
        assert_eq!(tasks.last().unwrap().public(), parsed_expected.public());
    }
    input::Storage::new()
        .unwrap()
        .print("bounded_preparation_ingress")
        .unwrap();
    println!("bounded_preparation_ingress_parity counts={} stable_order=true json_roundtrip=true exact_capacity=true", profile::MAX_TRANSACTIONS);
}

#[test]
fn oversized_json_collections_fail_before_decoding_the_extra_payload() {
    let (body, expected) = tests::candidate(profile::MAX_TRANSACTIONS as u8);
    let mut value = serde_json::to_value(&body).unwrap();
    value["transactions"]
        .as_array_mut()
        .unwrap()
        .push(json!({"unrecognized": []}));
    let encoded = serde_json::to_vec(&value).unwrap();
    let error = serde_json::from_slice::<Body>(&encoded)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("preparation collection limit"), "{error}");
    let error = serde_json::from_value::<Body>(value)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("preparation collection limit"), "{error}");
    let values = (0..input::MAX_PUBLIC)
        .map(|_| "0")
        .collect::<Vec<_>>()
        .join(",");
    let encoded =
        format!("{{\"kind\":\"joinsplit\",\"statement\":[{values},{{\"poison\":true}}]}}");
    let error = serde_json::from_str::<Transaction>(&encoded)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("preparation collection limit"), "{error}");
    let mut value = serde_json::to_value(&expected).unwrap();
    value["authorized_issuance"] = (0..=profile::MAX_TRANSACTIONS)
        .map(|i| (i.to_string(), json!(1)))
        .collect();
    let encoded = serde_json::to_vec(&value).unwrap();
    let error = serde_json::from_slice::<Expected>(&encoded)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("preparation collection limit"), "{error}");
    let error = serde_json::from_value::<Expected>(value)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("preparation authorization limit")
            || error.contains("preparation collection limit"),
        "{error}"
    );
}

#[test]
fn duplicate_authorizations_are_rejected_before_the_second_value() {
    #[derive(Deserialize)]
    struct Authorizations {
        #[serde(deserialize_with = "input::authorizations")]
        values: BTreeMap<usize, u64>,
    }
    let error = serde_json::from_str::<Authorizations>(r#"{"values":{"0":7,"0":{"poison":true}}}"#)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("duplicate preparation authorization"),
        "{error}"
    );
    let valid: Authorizations = serde_json::from_str(r#"{"values":{"0":7,"1":8}}"#).unwrap();
    assert_eq!(valid.values.len(), 2);
}

#[test]
fn exact_file_reads_reject_growth_shrink_and_nonregular_inputs() {
    let directory = Directory::new();
    let path = directory.0.join("artifact");
    for size in [0, 1, 4096, JSON_LIMIT, profile::MAX_PROOF_BYTES] {
        let bytes = vec![37u8; size];
        fs::write(&path, &bytes).unwrap();
        let actual = read_bytes(&path, size).unwrap();
        assert_eq!(actual, bytes);
        assert_eq!(actual.capacity(), size);
        if size > 0 {
            assert!(read_bytes(&path, size - 1).is_err());
        }
    }
    assert!(input::read_sized(&mut Cursor::new(vec![1; 4]), 3).is_err());
    assert!(input::read_sized(&mut Cursor::new(vec![1; 2]), 3).is_err());
    assert!(input::read_sized(&mut Cursor::new(vec![1]), usize::MAX).is_err());
    assert!(read_bytes(&directory.0, JSON_LIMIT).is_err());
    let link = directory.0.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_bytes(&link, profile::MAX_PROOF_BYTES).is_err());
}

#[test]
fn key_decoder_preserves_legacy_bytes_and_rejects_excess_roots_and_bad_envelopes() {
    let directory = Directory::new();
    let path = directory.0.join("key");
    let roots = 1 << profile::CAP_HEIGHT;
    for value in [Val::ZERO, Val::ONE, Val::from_u64(commitment::MODULUS - 1)] {
        let cap = vec![[value; 4]; roots];
        let mut bytes = KEY_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(&cap).unwrap());
        assert!(bytes.len() <= input::KEY_BYTES);
        fs::write(&path, &bytes).unwrap();
        let decoded = input::key(&path).unwrap();
        assert_eq!(decoded, cap);
        assert_eq!(decoded.capacity(), roots);
        assert_eq!(postcard::to_allocvec(&decoded).unwrap(), &bytes[8..]);
    }
    for count in [0, roots - 1, roots + 1, 256] {
        let mut bytes = KEY_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(&vec![[Val::ZERO; 4]; count]).unwrap());
        fs::write(&path, &bytes).unwrap();
        assert!(input::key(&path).is_err());
    }
    for bytes in [vec![], vec![0; 8], vec![0; input::KEY_BYTES + 1]] {
        fs::write(&path, &bytes).unwrap();
        assert!(input::key(&path).is_err());
    }
}
