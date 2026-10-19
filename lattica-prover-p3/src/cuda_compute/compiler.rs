//! Bounded public-source compilation. No input witness or RNG state is accepted
//! by the prover's code generator. Native program cleanup precedes source drop.
use super::{cleanup, error, Result};
use cudarc::nvrtc::{result, sys};
use std::{
    ffi::{CStr, CString},
    sync::Mutex,
};

const MAX_SOURCE: usize = 2 << 20;
const MAX_IMAGE: usize = 8 << 20;
const MAX_LOG: usize = 64 << 10;
static COMPILER: Mutex<()> = Mutex::new(());

struct Program {
    raw: sys::nvrtcProgram,
    _source: CString,
}

impl Drop for Program {
    fn drop(&mut self) {
        cleanup(
            unsafe { result::destroy_program(self.raw).map_err(error) },
            "NVRTC program destroy",
        );
    }
}

/// A process-local identity for the immutable library instance used by cudarc.
/// The loader retains this exact instance for the life of the process. This is
/// deliberately unsuitable for disk/distributed caches: those need toolchain
/// binary hashes, including the NVRTC builtins, rather than a loader address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ToolchainIdentity {
    pub version: [i32; 2],
    pub library_instance: usize,
}

pub(super) fn identity() -> Result<ToolchainIdentity> {
    if !unsafe { sys::is_culib_present() } {
        return Err("NVRTC is unavailable; configure the pinned CUDA 12.9.1 library path".into());
    }
    let mut major = 0;
    let mut minor = 0;
    unsafe {
        sys::nvrtcVersion(&mut major, &mut minor)
            .result()
            .map_err(error)?;
    }
    if (major, minor) != (12, 9) {
        return Err("CUDA prover requires pinned NVRTC 12.9".into());
    }
    type Version = unsafe extern "C" fn(*mut i32, *mut i32) -> sys::nvrtcResult;
    let symbol = unsafe { sys::culib().get::<Version>(b"nvrtcVersion\0") }.map_err(error)?;
    Ok(ToolchainIdentity {
        version: [major, minor],
        library_instance: *symbol as usize,
    })
}

pub(super) fn options(capability: u32) -> [String; 4] {
    [
        format!("--gpu-architecture=compute_{capability}"),
        "--std=c++17".into(),
        "--generate-line-info".into(),
        "--modify-stack-limit=false".into(),
    ]
}

pub(super) fn compile(source: &str, capability: u32) -> Result<Vec<u8>> {
    compile_optional(source, capability)?
        .ok_or_else(|| "CUDA compiled image exceeds its allowance".into())
}

/// A valid specialization may exceed the fixed PTX envelope. That outcome is
/// distinct from compiler/driver errors and permits the existing GPU interpreter.
pub(super) fn compile_optional(source: &str, capability: u32) -> Result<Option<Vec<u8>>> {
    compile_with_limit(source, capability, MAX_IMAGE)
}

fn compile_with_limit(
    source: &str,
    capability: u32,
    image_limit: usize,
) -> Result<Option<Vec<u8>>> {
    if source.is_empty() || source.len() > MAX_SOURCE || source.contains('\0') {
        return Err("CUDA source is empty, oversized, or contains NUL".into());
    }
    let _guard = COMPILER.lock().map_err(|_| "CUDA compiler poisoned")?;
    identity()?;
    let mut count = 0;
    unsafe {
        sys::nvrtcGetNumSupportedArchs(&mut count)
            .result()
            .map_err(error)?;
    }
    if !(1..=64).contains(&count) {
        return Err("unexpected NVRTC target count".into());
    }
    let mut targets = vec![0; count as usize];
    unsafe {
        sys::nvrtcGetSupportedArchs(targets.as_mut_ptr())
            .result()
            .map_err(error)?;
    }
    if !targets.contains(&(capability as i32)) {
        return Err("NVRTC does not support the assigned GPU target".into());
    }
    let source = CString::new(source).map_err(error)?;
    let program = Program {
        raw: result::create_program(&source, Some(c"lattica.cu")).map_err(error)?,
        _source: source,
    };
    let options = options(capability);
    if let Err(status) = unsafe { result::compile_program(program.raw, &options) } {
        let mut length = 0;
        unsafe {
            sys::nvrtcGetProgramLogSize(program.raw, &mut length)
                .result()
                .map_err(error)?;
        }
        if length == 0 || length > MAX_LOG {
            return Err(format!(
                "NVRTC compilation failed: {status}; diagnostic size {length}"
            ));
        }
        let mut log = vec![0u8; length];
        unsafe {
            sys::nvrtcGetProgramLog(program.raw, log.as_mut_ptr().cast())
                .result()
                .map_err(error)?;
        }
        let log = CStr::from_bytes_until_nul(&log)
            .map_err(error)?
            .to_string_lossy();
        return Err(format!("NVRTC compilation failed: {status}: {log}"));
    }
    let mut length = 0;
    unsafe {
        sys::nvrtcGetPTXSize(program.raw, &mut length)
            .result()
            .map_err(error)?;
    }
    if length == 0 {
        return Err("NVRTC returned an empty compiled image".into());
    }
    if length > image_limit {
        return Ok(None);
    }
    let mut image = vec![0u8; length];
    unsafe {
        sys::nvrtcGetPTX(program.raw, image.as_mut_ptr().cast())
            .result()
            .map_err(error)?;
    }
    if image.last() != Some(&0) {
        return Err("NVRTC returned unterminated PTX".into());
    }
    Ok(Some(image))
}

#[cfg(test)]
mod tests {
    #[test]
    fn invalid_source_rejects_without_a_cuda_installation() {
        for source in ["", "a\0b"] {
            assert!(super::compile(source, 70).is_err());
        }
        assert!(super::compile(&"x".repeat(super::MAX_SOURCE + 1), 70).is_err());
    }

    #[test]
    #[ignore = "requires pinned NVRTC; no device execution"]
    fn oversized_specializations_are_distinct_from_compilation_errors() {
        let source = "extern \"C\" __global__ void bounded_image(unsigned long long* p) { p[threadIdx.x] = threadIdx.x; }";
        assert!(super::compile_with_limit(source, 70, 1).unwrap().is_none());
        assert!(super::compile_with_limit("invalid CUDA source", 70, 1).is_err());
        assert!(super::compile_with_limit(source, 70, super::MAX_IMAGE)
            .unwrap()
            .is_some());
    }
}
