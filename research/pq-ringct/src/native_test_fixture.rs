//! Public-only fixture persistence for replaying expensive research proofs.
//! A fixed public setup seed does not make the native private RNG deterministic.
//! This test helper never stores keys, openings, or private randomness.

use std::{fs, io::Read, path::Path};

const MAX_ARCHIVE_BYTES: u64 = 16 << 20;

pub(crate) struct PublicFixture {
    pub context: [u8; 32],
    pub setup_seed: [u8; 32],
    pub statement: Vec<u8>,
    pub proof: Vec<u8>,
}

/// The path is explicit. Missing archives are generated only when requested;
/// existing artifacts are bounded, decoded, context checked, and reverified.
pub(crate) fn load_or_create(
    path: &Path,
    context: [u8; 32],
    setup_seed: [u8; 32],
    index: u64,
    amounts: crate::native::FixtureAmounts,
    allow_create: bool,
) -> Result<PublicFixture, Box<dyn std::error::Error>> {
    if !path.exists() && allow_create {
        let generated =
            crate::native::generate_fixture_with_setup_seed(context, setup_seed, index, amounts)?;
        let fixture = PublicFixture {
            context,
            setup_seed,
            statement: generated.statement,
            proof: generated.proof,
        };
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "context": fixture.context,
            "setup_seed": fixture.setup_seed,
            "statement": fixture.statement,
            "proof": fixture.proof,
        }))?;
        if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
            return Err(std::io::Error::other("fixture archive exceeds byte limit").into());
        }
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture path parent"))?;
        fs::create_dir_all(parent)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let temporary = parent.join(format!(".fixture-{}-{nonce}.tmp", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            // Atomic publication without overwriting a concurrently created fixture.
            fs::hard_link(&temporary, path)?;
            fs::File::open(parent)?.sync_all()
        })();
        let _ = fs::remove_file(&temporary);
        result?;
    }
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > MAX_ARCHIVE_BYTES {
        return Err(std::io::Error::other("fixture archive exceeds byte limit").into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_ARCHIVE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(std::io::Error::other("fixture archive exceeds byte limit").into());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let fields = value
        .as_object()
        .ok_or_else(|| std::io::Error::other("fixture object"))?;
    if fields.len() != 5 || value["schema"].as_u64() != Some(1) {
        return Err(std::io::Error::other("fixture schema or fields").into());
    }
    let fixture = PublicFixture {
        context: serde_json::from_value(value["context"].clone())?,
        setup_seed: serde_json::from_value(value["setup_seed"].clone())?,
        statement: serde_json::from_value(value["statement"].clone())?,
        proof: serde_json::from_value(value["proof"].clone())?,
    };
    if fixture.context != context || fixture.setup_seed != setup_seed {
        return Err(std::io::Error::other("fixture schema/context/setup identity").into());
    }
    let statement = crate::rust_verify::Statement::decode(&fixture.statement)
        .map_err(|e| std::io::Error::other(format!("fixture statement: {e:?}")))?;
    if statement.seed != setup_seed
        || !crate::native::verify(&context, &fixture.statement, &fixture.proof)?
    {
        return Err(std::io::Error::other("fixture setup seed or native proof rejected").into());
    }
    Ok(fixture)
}

#[test]
fn public_fixture_archive_replays_exact_bytes_and_rejects_wrong_context() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/pq-fixture-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let path = directory.join("fixture.json");
    let amounts = crate::native::FixtureAmounts {
        input: [17, 23],
        output: [29, 11],
    };
    let first = load_or_create(&path, [71; 32], [29; 32], 3, amounts, true).unwrap();
    let reopened = load_or_create(&path, [71; 32], [29; 32], 3, amounts, false).unwrap();
    assert_eq!(first.statement, reopened.statement);
    assert_eq!(first.proof, reopened.proof);
    assert!(load_or_create(&path, [72; 32], [29; 32], 3, amounts, false).is_err());
    assert!(load_or_create(&path, [71; 32], [30; 32], 3, amounts, false).is_err());
    assert!(load_or_create(
        &directory.join("missing.json"),
        [71; 32],
        [29; 32],
        3,
        amounts,
        false
    )
    .is_err());
    fs::remove_dir_all(directory).unwrap();
}
