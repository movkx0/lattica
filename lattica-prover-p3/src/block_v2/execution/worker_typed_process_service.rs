//! Attach an inherited socket to an independently bounded systemd GPU worker.
//! The trusted launcher owns service limits, accounting and owner-exit cleanup.
//! Its proxy exit alone never authorizes workspace release.

use super::*;
use crate::block_v2::execution::os_worker;
use std::ffi::OsString;

pub(super) struct OwnedService {
    unit: String,
    live: os_worker::LiveProcess,
}

impl ProcessWorker {
    /// The launcher must pass stdin unchanged to the requested worker service,
    /// wait for its exit, and bind its lifetime to the coordinator service.
    /// The worker independently checks the assigned physical limits before READY.
    /// Service names are single-use; failed sessions retain their journal charge.
    pub fn start_supervised(
        &mut self,
        mut launcher: Command,
        unit: &str,
        worker_arguments: &[OsString],
    ) -> Result<(), Error> {
        os_worker::persistent_unit_name(unit)?;
        if self.poisoned || self.pid.is_some() || self.exited_cleanly {
            return Err("typed process cannot be restarted under the same reservation".into());
        }
        if worker_arguments.is_empty() {
            return Err("typed service worker arguments missing".into());
        }
        let (mut socket, child_socket) = UnixStream::pair()?;
        configure(&socket)?;
        self.poisoned = true;
        self.child = Some(
            launcher
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_socket)))
                .spawn()?,
        );
        // Release the parent's copy of the service's socket endpoint. A
        // launcher that exits before READY must be observed immediately.
        drop(launcher);
        send(&mut socket, HELLO, &self.spec)?;
        let ready = receive(&mut socket, READY, 36)?;
        if ready.len() != 36 || ready[4..] != self.execution_digest()? {
            return Err("typed service handshake identity".into());
        }
        let pid = u32::from_le_bytes(ready[..4].try_into().unwrap());
        let live = os_worker::observe_persistent(unit, self.config.executable, worker_arguments)?
            .ok_or("typed service worker is not currently observable")?;
        if live.identity().pid() != pid {
            return Err("typed service handshake PID differs from observed main process".into());
        }
        self.pid = Some(pid);
        self.service = Some(OwnedService {
            unit: unit.to_owned(),
            live,
        });
        self.socket = Some(socket);
        self.poisoned = false;
        Ok(())
    }

    pub fn service_identity(&self) -> Option<&os_worker::Identity> {
        self.service.as_ref().map(|service| service.live.identity())
    }

    /// Fence a failed job and drain its exact supervised process before releasing
    /// its job and workspace reservations. A socket error alone is insufficient.
    /// The returned counters cover completed responses, not interrupted work.
    pub fn stop_failed_supervised(
        &mut self,
        owner: &mut DurableDag,
        launches: &mut launch::LaunchStore,
        lease: Lease,
        now: impl Fn() -> u64,
    ) -> Result<CacheStats, Error> {
        owner.check_workspace_reservation(&self.reservation)?;
        let service = self
            .service
            .as_ref()
            .ok_or("failed worker has no supervised identity")?;
        if self.pending.as_ref().map(|(task, _)| task.lease()) != Some(lease) {
            return Err("failed worker lease differs from its pending job".into());
        }
        self.poisoned = true;
        let revoked = launches.revoke(lease)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        if !service.live.quiescent()? {
            os_worker::request_stop(service.live.identity(), &service.unit)?;
        }
        wait_quiescent(service, deadline)?;
        let _idle = launches
            .try_idle(&revoked)?
            .ok_or("failed worker launch remains active")?;
        loop {
            if self
                .child
                .as_mut()
                .ok_or("failed worker launcher missing")?
                .try_wait()?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("failed worker launcher did not exit".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        owner.reject_worker(lease, now())?;
        owner.worker_stopped(lease, now())?;
        drop(self.pending.take());
        self.socket = None;
        self.child = None;
        owner.release_workspace(&mut self.reservation, now())?;
        Ok(self.stats)
    }
}

pub(super) fn wait_quiescent(service: &OwnedService, deadline: Instant) -> Result<(), Error> {
    loop {
        if service.live.quiescent()? && os_worker::exited(service.live.identity(), &service.unit)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("typed service process/cgroup did not become quiescent".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
