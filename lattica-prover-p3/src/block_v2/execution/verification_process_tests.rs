//! Actual process loss at the managed task/result boundaries. These tests use
//! public proofs only and never launch a prover. A wait on our exact child is
//! reconciliation evidence for this fixture, not arbitrary external verifiers.

use super::*;
use crate::block_v2::execution::{
    job::Operation,
    selection::{PublicInput, Selection},
    test_fixture::{self, Fixture},
};
use std::{
    os::unix::process::ExitStatusExt,
    process::{Child, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const CHILD_TEST: &str =
    "block_v2::execution::journal::tests::verification::process::guarded_process_helper";
const CASE_PATH: &str = "LATTICA_GUARDED_PROCESS_PATH";
const CASE_PHASE: &str = "LATTICA_GUARDED_PROCESS_PHASE";

fn budget() -> Resources {
    Resources {
        ram_bytes: 1 << 30,
        vram_bytes: 0,
        scratch_bytes: 128 << 20,
        threads: 2,
    }
}

fn case_limits() -> Limits {
    Limits {
        workers: budget(),
        ..limits()
    }
}

fn fixture() -> Result<(Fixture, Selection, Job, Vec<u8>), Error> {
    let f = test_fixture::load()?;
    let bytes = test_fixture::read(
        &PathBuf::from(std::env::var("LATTICA_V2_GUARDED_PAIR")?),
        MAX_PROOF_BYTES,
    )?;
    let inputs = f.wallets[..2]
        .iter()
        .zip(&f.bytes[..2])
        .map(|(wallet, bytes)| PublicInput::new(*wallet, bytes.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let selection = Selection::new(f.pin, [0x5a; 32], &inputs)?;
    let job = selection
        .jobs()
        .find(|job| job.operation() == Operation::WrapPair)
        .ok_or("missing pair job")?
        .clone();
    Ok((f, selection, job, bytes))
}

// Retain a task or result until the parent kills this process. Readiness is
// published only after its coordinator handle has been dropped. No hook is
// added to the production verifier or to the proof's cryptographic checks.
fn hold<T>(path: &Path, phase: &str, held: T) -> ! {
    private_file(
        &path.join("ready"),
        format!("phase={phase} pid={}\n", std::process::id()).as_bytes(),
    );
    loop {
        std::thread::park();
        std::hint::black_box(&held);
    }
}

#[test]
#[ignore = "subprocess helper for the pinned CPU process-crash test"]
fn guarded_process_helper() -> Result<(), Error> {
    let path = PathBuf::from(std::env::var(CASE_PATH)?);
    let phase = std::env::var(CASE_PHASE)?;
    if phase != "task" && phase != "result" {
        return Err("unknown verifier process phase".into());
    }
    let (f, selection, job, bytes) = fixture()?;
    let store = ArtifactStore::create(&path.join("store"), store_limits())?;
    let mut owner = DurableDag::create(
        &path.join("journal"),
        journal_limits(),
        store,
        f.pin,
        [0x5a; 32],
        1,
        case_limits(),
    )?;
    selection.attach(&mut owner, [1; 32], 10_000, 0)?;
    let lease = owner.lease(job.id(), WorkerId(1), budget(), 1, 1000, 1)?;
    // No worker exists: the public pair proof predates this test.
    owner.worker_stopped(lease, 2)?;
    let task = owner.begin_guarded_verification(lease, 2)?;
    drop(owner);
    std::thread::spawn(move || {
        if phase == "task" {
            hold(&path, &phase, task);
        }
        let result = task.verify(&f.registry, bytes);
        assert!(result.error().is_none(), "{:?}", result.error());
        hold(&path, &phase, result);
    })
    .join()
    .map_err(|_| "guarded child thread failed before readiness")?;
    Err("held verifier unexpectedly returned".into())
}

struct ReapedChild(Child);

impl ReapedChild {
    fn wait_ready(&mut self, path: &Path, phase: &str) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let expected = format!("phase={phase} pid={}\n", self.0.id());
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Err(format!("verifier child exited before readiness: {status}").into());
            }
            match fs::read_to_string(path.join("ready")) {
                Ok(bytes) if bytes == expected => return Ok(()),
                // The create-new marker can be observed before its write.
                Ok(bytes) if expected.starts_with(&bytes) => (),
                Ok(_) => return Err("wrong verifier readiness identity/phase".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Err("verifier child readiness timed out".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn kill_and_reap(&mut self) -> Result<ExitStatus, Error> {
        self.0.kill()?;
        Ok(self.0.wait()?)
    }
}

impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn recover_case(temp: &Temp, f: &Fixture) -> Result<Recovery, Error> {
    let store = ArtifactStore::open(&temp.store(), store_limits())?;
    DurableDag::recover(
        &temp.journal(),
        journal_limits(),
        store,
        f.pin,
        &f.registry,
        [0x5a; 32],
        2,
        case_limits(),
    )
}

#[test]
#[ignore = "requires pinned public CPU fixtures and an existing pair proof"]
fn cpu_guarded_verifier_process_crash_requires_reap_and_reconciliation() -> Result<(), Error> {
    let (f, selection, job, bytes) = fixture()?;
    for phase in ["task", "result"] {
        let temp = Temp::new();
        let mut child = ReapedChild(
            Command::new(std::env::current_exe()?)
                .args([CHILD_TEST, "--exact", "--ignored", "--test-threads=1"])
                .env(CASE_PATH, &temp.path)
                .env(CASE_PHASE, phase)
                .stdin(Stdio::null())
                .spawn()?,
        );
        child.wait_ready(&temp.path, phase)?;
        // Only the child's verifier task/result now retains the journal lock.
        assert!(SnapshotLog::open(&temp.journal(), journal_limits()).is_err());
        assert!(recover_case(&temp, &f).is_err());
        let status = child.kill_and_reap()?;
        assert_eq!(status.signal(), Some(9)); // SIGKILL, not a cooperative drop.

        let recovery = recover_case(&temp, &f)?;
        assert_eq!(recovery.previous_candidates().len(), 1);
        assert_eq!(recovery.unresolved_attempts().len(), 1);
        let old = recovery.unresolved_attempts()[0].clone();
        assert_eq!(old.lease.job(), job.id());
        assert!(old.worker_stopped && old.verification_active);
        // Opening the journal is not permission to discard a verifier lease.
        assert!(recovery
            .resume(|_| Err("explicit reconciliation withheld".into()), || 100)
            .is_err());

        let mut owner = recover_case(&temp, &f)?.resume(
            |attempt| {
                assert_eq!(attempt.lease, old.lease);
                assert!(attempt.worker_stopped && attempt.verification_active);
                // This fixture has no external verifier. The exact child that
                // held the task/result was SIGKILLed and reaped above.
                assert_eq!(status.signal(), Some(9));
                Ok(())
            },
            || 100,
        )?;
        assert_eq!(owner.resource_use()?, Resources::default());
        assert!(owner.ready()?.is_empty());
        assert_ne!(owner.status(job.id())?, JobStatus::Completed);
        let ticket = VerifiedNode::verify(&job, &f.registry, &bytes)?;
        assert!(owner
            .finish_verification(old.lease, Some((ticket, bytes.clone())), 101)
            .is_err());

        selection.attach(&mut owner, [2; 32], 10_000, 102)?;
        let next = owner.lease(job.id(), WorkerId(2), budget(), 1, 1000, 102)?;
        assert_ne!(next, old.lease);
        owner.worker_stopped(next, 103)?;
        let task = owner.begin_guarded_verification(next, 103)?;
        let mut changed = bytes.clone();
        *changed.last_mut().ok_or("empty proof")? ^= 1;
        let rejected = task.verify(&f.registry, changed);
        assert!(rejected.error().is_some());
        assert_eq!(
            owner.finish_guarded_verification(rejected, 104)?,
            Completion::Rejected
        );
        assert_eq!(owner.resource_use()?, Resources::default());
        println!("guarded_process_crash=PASS phase={phase} signal=9 child_reaped=true prior_verification_active=true old_eligibility_revived=false stale_result_rejected=true mutation_rejected=true prover_process_launched=false production_ready=false");
    }
    Ok(())
}
