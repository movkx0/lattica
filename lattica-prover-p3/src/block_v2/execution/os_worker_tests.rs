//! Native kernel/parser checks; these do not qualify live systemd recovery.
use super::*;
use std::io::Write;

fn name() -> String {
    format!("lattica-v2-worker-{}.service", "a1".repeat(32))
}
fn service_text() -> String {
    format!("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nControlPID=0\nInvocationID={}\nControlGroup=/user.slice/{}\n", "12".repeat(16), name())
}

#[test]
fn os_identity_hex_and_uuid_are_strict() {
    assert_eq!(hex16(&"12".repeat(16)).unwrap(), [0x12; 16]);
    for value in [
        "".to_owned(),
        "0".repeat(32),
        "A".repeat(32),
        "g".repeat(32),
        "1".repeat(31),
    ] {
        assert!(hex16(&value).is_err());
    }
    let uuid = "12121212-1212-1212-1212-121212121212";
    assert_eq!(parse_boot_id(uuid).unwrap(), [0x12; 16]);
    assert_eq!(parse_boot_id(&format!("{uuid}\n")).unwrap(), [0x12; 16]);
    for value in [
        uuid.replace('-', ""),
        format!("{uuid}\n\n"),
        uuid.replace('-', "_"),
        "0".repeat(36),
    ] {
        assert!(parse_boot_id(&value).is_err());
    }
    assert_ne!(boot_id().unwrap(), [0; 16]);
}

#[test]
fn os_unit_and_cgroup_paths_reject_substitution() {
    let unit = name();
    let valid = format!("/user.slice/{unit}");
    assert_eq!(
        group_path(&valid, &unit).unwrap(),
        Path::new("/sys/fs/cgroup").join(valid.trim_start_matches('/'))
    );
    for bad in [
        "../bad.service".to_owned(),
        unit.to_uppercase(),
        unit.replace("a1", "g1"),
        "lattica-v2-controller.service".to_owned(),
    ] {
        assert!(unit_name(&bad).is_err());
    }
    for path in [
        format!("relative/{unit}"),
        format!("//{unit}"),
        format!("/./{unit}"),
        format!("/../{unit}"),
        format!("/{unit}/"),
        format!("/a\n/{unit}"),
        "/wrong.service".to_owned(),
        format!("/{}/{unit}", "a/".repeat(65)),
    ] {
        assert!(group_path(&path, &unit).is_err(), "{path}");
    }
}

#[test]
fn os_service_fields_are_complete_bounded_and_unique() {
    let value = service_text();
    let parsed = parse_service(&value).unwrap();
    assert_eq!(parsed.pid, 123);
    assert_eq!(parsed.invocation, Some([0x12; 16]));
    for line in value.lines() {
        assert!(parse_service(&value.replace(&format!("{line}\n"), "")).is_err());
        assert!(parse_service(&format!("{value}{line}\n")).is_err());
    }
    for pid in ["-1", "+1", "0123", "2147483648", "4294967296", "", "x"] {
        assert!(parse_service(&value.replace("MainPID=123", &format!("MainPID={pid}"))).is_err());
    }
    assert!(parse_service(&format!("{value}Unexpected=x\n")).is_err());
    assert!(parse_service(&"x".repeat(MAX_CONTROL_BYTES + 1)).is_err());
    let missing = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nInvocationID=\nControlGroup=\n";
    let parsed = parse_service(missing).unwrap();
    assert_eq!(parsed.invocation, None); // Observation, never a stop receipt.
}

#[test]
fn os_proc_birth_parser_handles_parentheses_in_comm() {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "987654";
    let value = format!("123 (name ) with ( parens)) {} 0 0\n", fields.join(" "));
    assert_eq!(proc_start_from_stat(value.as_bytes(), 123).unwrap(), 987654);
    assert!(proc_start_from_stat(value.as_bytes(), 124).is_err());
    for bad in [
        "123 broken".to_owned(),
        "123 (name) S".to_owned(),
        value.replace("987654", "-1"),
        value.replace("987654", "0"),
        value.replace("987654", "18446744073709551616"),
    ] {
        assert!(proc_start_from_stat(bad.as_bytes(), 123).is_err());
    }
    assert!(proc_start(std::process::id()).unwrap() > 0);
    assert!(pidfd(0).is_err());
    assert!(pidfd(u32::MAX).is_err());
}

#[test]
fn os_population_requires_exact_unambiguous_value() {
    assert!(parse_population("populated 0\nfrozen 0\n").unwrap());
    assert!(!parse_population("populated 1\nfrozen 0\n").unwrap());
    for bad in [
        "",
        "frozen 0\n",
        "populated 2\n",
        "populated 00\n",
        "populated 0\npopulated 0\n",
        "populated 0 \n",
    ] {
        assert!(parse_population(bad).is_err());
    }
}

#[test]
fn os_pidfd_follows_owned_child_not_a_pid_observation() {
    let mut child = Command::new("/usr/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let handle = pidfd(child.id());
    // Reap our own helper even if a kernel prerequisite fails.
    let live = handle.as_ref().map(|fd| pidfd_exited(fd));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(!live.unwrap().unwrap());
    let handle = handle.unwrap();
    assert!(pidfd_exited(&handle).unwrap());
    assert!(pidfd_exited(&handle).unwrap());
}

#[test]
fn os_bounded_reader_and_pipe_drain_reject_overflow() {
    let mut bytes = &b"abcd"[..];
    let mut out = Vec::new();
    assert!(drain(&mut bytes, &mut out).unwrap());
    assert_eq!(out, b"abcd");
    let bytes = vec![1; MAX_CONTROL_BYTES + 1];
    assert!(drain(&mut bytes.as_slice(), &mut Vec::new()).is_err());
    assert!(read_bounded(Path::new("/proc/self/stat"), 1).is_err());
    assert!(read_bounded(Path::new("/proc/self"), 4096).is_err());
    let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    nonblocking(&reader).unwrap();
    let mut out = Vec::new();
    assert!(!drain(&mut reader, &mut out).unwrap());
    writer.write_all(b"ok").unwrap();
    drop(writer);
    assert!(drain(&mut reader, &mut out).unwrap());
    assert_eq!(out, b"ok");
}

#[test]
fn os_invalid_persisted_identity_fails_before_boot_shortcut() {
    let unit = name();
    let identity = Identity {
        boot: [1; 16],
        invocation: [2; 16],
        pid: 123,
        start_ticks: 1,
        group: format!("/user.slice/{unit}"),
        device: 1,
        inode: 1,
    };
    identity.validate(&unit).unwrap();
    for index in 0..6 {
        let mut invalid = identity.clone();
        match index {
            0 => invalid.boot = [0; 16],
            1 => invalid.invocation = [0; 16],
            2 => invalid.pid = 0,
            3 => invalid.start_ticks = 0,
            4 => invalid.inode = 0,
            _ => invalid.group = "/wrong.service".into(),
        }
        assert!(exited(&invalid, &unit).is_err());
        assert!(request_stop(&invalid, &unit).is_err());
    }
}
