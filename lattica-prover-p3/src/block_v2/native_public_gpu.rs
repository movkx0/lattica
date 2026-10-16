//! Fresh-process startup for public recursive workers. No wallet authority,
//! registry approval, proof transport or verifier activation is implied.

use super::{execution::gpu_admission::Admission, gpu_hash, gpu_startup, profile, wallet_worker};
use crate::proving::{Policy, Request};

pub(crate) fn initialize() -> Result<(), String> {
    Prepared::from_env()
        .and_then(Prepared::initialize)
        .inspect_err(|error| {
            eprintln!("public GPU worker startup rejected: {error}");
        })
}

pub(crate) struct Prepared {
    request: Request,
    admission: Admission,
}

impl Prepared {
    pub(crate) fn from_env() -> Result<Self, String> {
        if wallet_worker::is_assigned() || gpu_hash::is_enabled() {
            return Err("public GPU worker startup requires a fresh, non-wallet process".into());
        }
        let request = Request::from_env().map_err(|e| e.to_string())?;
        if request.policy != Policy::GpuRequired {
            return Err("public GPU worker startup requires gpu-required".into());
        }
        if cfg!(debug_assertions) {
            return Err(
                "public GPU worker startup requires a release build without CPU constraint audits"
                    .into(),
            );
        }
        let admission = Admission::from_env().map_err(|e| e.to_string())?;
        gpu_startup::preflight()?;
        Ok(Self { request, admission })
    }

    pub(crate) fn assignment(&self) -> &serde_json::Value {
        self.admission.assignment()
    }

    pub(crate) fn initialize(self) -> Result<(), String> {
        self.initialize_with(|_| Ok(())).map_err(|e| e.to_string())
    }

    /// Admit allocators and Rayon before bounded CPU preparation can start
    /// threads. The preparation result is the only state carried into device
    /// startup; a preparation failure never creates a GPU context.
    pub(crate) fn initialize_with<T>(
        self,
        prepare: impl FnOnce(&serde_json::Value) -> Result<T, super::recursive::Error>,
    ) -> Result<T, super::recursive::Error> {
        gpu_startup::select()?;
        self.admission.initialize_rayon()?;
        let value = prepare(self.admission.assignment())?;
        let mut created = gpu_startup::Startup::begin()?;
        if !gpu_hash::initialize_resident_from_env()? {
            return Err("public GPU worker startup requires resident commitments".into());
        }
        self.request
            .admit(&profile::recursive_request_capabilities())
            .map_err(|e| e.to_string())?;
        created.accept();
        Ok(value)
    }
}
