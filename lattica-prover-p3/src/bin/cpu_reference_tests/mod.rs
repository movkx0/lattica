//! Exercise the actual CPU CLI workflows in separate policy environments.

pub(super) fn isolated(name: &str, policy: &str, report: &str, test: impl FnOnce()) {
    const CHILD: &str = "LATTICA_TEST_CPU_CLI_POLICY_CHILD";
    if let Some(child) = std::env::var_os(CHILD) {
        assert_eq!(child, name);
        test();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--include-ignored", "--nocapture"])
        .env(CHILD, name)
        .env("LATTICA_PROVING_POLICY", policy)
        .env("LATTICA_PROVING_REPORT", report)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    if policy == "gpu-required" || policy == "invalid" || report == "invalid" {
        for premature_output in [
            "Field comparison:",
            "candidate_status=",
            "lattica-prover-p3 demo:",
            "proving_stage_report ",
        ] {
            assert!(
                !stdout.contains(premature_output) && !stderr.contains(premature_output),
                "CLI started work before admission: {stdout}\n{stderr}"
            );
        }
    } else {
        print!("{stdout}");
        eprint!("{stderr}");
    }
}

#[test]
fn gpu_required_rejects_before_cli_work() {
    isolated(
        "policy_tests::gpu_required_rejects_before_cli_work",
        "gpu-required",
        "0",
        || {
            let error = super::run().expect_err("CPU CLI ignored GPU-required");
            assert!(error.contains("GpuRequired"), "{error}");
        },
    );
}

#[test]
fn invalid_policy_rejects_before_cli_work() {
    isolated(
        "policy_tests::invalid_policy_rejects_before_cli_work",
        "invalid",
        "0",
        || {
            let error = super::run().expect_err("CPU CLI ignored invalid policy");
            assert!(error.contains("LATTICA_PROVING_POLICY"), "{error}");
        },
    );
}

#[test]
fn invalid_report_switch_rejects_before_cli_work() {
    isolated(
        "policy_tests::invalid_report_switch_rejects_before_cli_work",
        "cpu-required",
        "invalid",
        || {
            let error = super::run().expect_err("CPU CLI ignored invalid report switch");
            assert!(error.contains("LATTICA_PROVING_REPORT"), "{error}");
        },
    );
}
