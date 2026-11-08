//! The guard resolves an immutable envelope; the worker independently rechecks it.
use super::*;
use std::io::Read;

pub(crate) fn selected(options: &Options) -> Result<Option<serde_json::Value>> {
    if options.profile != "grouped-v4" || options.command == "prepare-inputs" { return Ok(None); }
    let raw = std::env::var("LATTICA_V2_GPU_AGGREGATION_MEMORY").map_err(error)?;
    ensure(raw.len() <= 16384, "aggregation memory record too large")?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(error)?;
    ensure(value["source_sha3"].as_str() == Some(&hex(&crate::graph_proofs::compiled_source_fingerprint()))
        && value["query_gather"].as_str() == Some(&options.query_gather)
        && value["device_uuid"].as_str() == std::env::var("LATTICA_GPU_DEVICE_UUID").ok().as_deref(),
        "aggregation memory source/device/variant mismatch")?;
    Ok(Some(value))
}

pub(crate) fn recheck(options: &Options) -> Result<u64> {
    let Some(value) = selected(options)? else { return Ok(8 << 30); };
    let managed = value["managed_bytes"].as_u64().ok_or("missing managed bytes")?;
    let reserve = value["context_bytes"].as_u64().ok_or("missing context bytes")?;
    ensure((8 << 30..=12 << 30).contains(&managed) && managed % (256 << 20) == 0
        && (2 << 30..=4 << 30).contains(&reserve) && reserve % (256 << 20) == 0,
        "aggregation memory range")?;
    for (key, bytes) in [("LATTICA_V2_GPU_MANAGED_BYTES", managed), ("LATTICA_V2_GPU_CONTEXT_BYTES", reserve)] {
        ensure(std::env::var(key).map_err(error)? == bytes.to_string(), "memory environment changed")?;
    }
    let (_, _, device) = lattica_prover_p3::gpu_device::select().map_err(error)?;
    ensure(managed + reserve + (512 << 20) <= device.global_bytes,
        "aggregation memory exceeds physical OpenCL envelope")?;
    let uuid = value["device_uuid"].as_str().ok_or("missing device UUID")?;
    let output = std::process::Command::new("nvidia-smi")
        .args([format!("--id={uuid}"), "--query-gpu=uuid,driver_version,memory.free".into(),
               "--format=csv,noheader,nounits".into()]).output().map_err(error)?;
    ensure(output.status.success() && output.stdout.len() <= 4096, "memory availability query failed")?;
    let response = std::str::from_utf8(&output.stdout).map_err(error)?;
    let parts: Vec<_> = response.trim().split(',').map(str::trim).collect();
    ensure(parts.len() == 3 && parts[0] == uuid && Some(parts[1]) == value["driver"].as_str(),
        "memory inventory changed")?;
    let free = parts[2].parse::<u64>().map_err(error)?.checked_mul(1 << 20).ok_or("free VRAM overflow")?;
    ensure(managed + reserve + (512 << 20) <= free, "available VRAM changed before session creation")?;
    let mut file = std::fs::File::open(std::env::current_exe().map_err(error)?).map_err(error)?;
    let mut hash = Sha3_256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(error)?;
        if count == 0 { break; }
        hash.update(&buffer[..count]);
    }
    ensure(Some(hex(&hash.finalize()).as_str()) == value["executable_sha3"].as_str(),
        "memory qualification executable mismatch")?;
    if reserve < 4 << 30 {
        let path = options.memory_qualification.as_ref().ok_or("smaller reserve needs qualification")?;
        ensure(std::fs::metadata(path).map_err(error)?.len() <= 1 << 20, "qualification file too large")?;
        let q: serde_json::Value = serde_json::from_slice(&std::fs::read(path).map_err(error)?).map_err(error)?;
        for field in ["source_sha3", "executable_sha3", "device_uuid", "driver", "query_gather", "context_bytes", "max_rows"] {
            ensure(q[field] == value[field], "memory qualification binding changed")?;
        }
        ensure(q["geometries"] == value["qualified_geometries"], "qualified geometries changed")?;
        ensure(q["schema"] == "ringct-gpu-memory-qualification-v1" && q["verified"] == true
            && q["opaque_peak_bytes"].as_u64().and_then(|n| n.checked_add(512 << 20)).is_some_and(|n| n <= reserve),
            "memory reserve was not qualified")?;
    }
    Ok(managed)
}

pub(crate) fn signature(options: &Options) -> Result<serde_json::Value> {
    let value = selected(options)?.ok_or("memory selection required")?;
    let mut result = serde_json::Map::new();
    for field in ["managed_bytes", "context_bytes", "query_gather", "max_rows", "driver", "executable_sha3", "qualification_sha256"] {
        ensure(value.get(field).is_some(), "incomplete memory signature")?;
        result.insert(field.into(), value[field].clone());
    }
    Ok(serde_json::Value::Object(result))
}

pub(crate) fn check_program(program: &lattica_prover_p3::block_v2::machine::Program) -> Result<()> {
    if std::env::var("LATTICA_V2_GPU_AGGREGATION_V4").as_deref() != Ok("1") { return Ok(()); }
    let value: serde_json::Value = serde_json::from_str(&std::env::var("LATTICA_V2_GPU_AGGREGATION_MEMORY").map_err(error)?).map_err(error)?;
    if value["context_bytes"].as_u64().ok_or("missing context reserve")? < 4 << 30 {
        let expected = serde_json::json!({"rows":program.height(), "public_values":program.public_values()});
        ensure(value["qualified_geometries"].as_array().is_some_and(|g| g.contains(&expected)),
            "program geometry was not qualified for the smaller context reserve")?;
    }
    Ok(())
}
