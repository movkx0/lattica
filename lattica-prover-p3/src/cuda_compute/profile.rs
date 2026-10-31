//! Optional NVTX annotations. The launch assignment pins the helper library.
//! Only static operation labels are exposed; no witness, seeds or challenges.
use super::Result;
use crate::proving::Stage;
use std::{
    ffi::{CStr, CString},
    marker::PhantomData,
    rc::Rc,
    sync::OnceLock,
};

type Push = unsafe extern "C" fn(*const libc::c_char);
type Pop = unsafe extern "C" fn();
struct Api {
    // Deliberately process-lived: active ranges/function pointers cannot outlive it.
    _library: usize,
    push: Push,
    pop: Pop,
}
static API: OnceLock<Result<Option<Api>>> = OnceLock::new();

fn api() -> &'static Result<Option<Api>> {
    API.get_or_init(|| {
        let Some(path) = std::env::var_os("LATTICA_CUDA_PROFILE_LIBRARY") else {
            return Ok(None);
        };
        use std::os::unix::ffi::OsStrExt;
        if !std::path::Path::new(&path).is_absolute() {
            return Err("CUDA profiling library must be absolute".into());
        }
        let path = CString::new(path.as_bytes()).map_err(super::error)?;
        unsafe {
            let library = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if library.is_null() {
                return Err("CUDA profiling library could not be loaded".into());
            }
            let push = libc::dlsym(library, c"lattica_profile_push".as_ptr());
            let pop = libc::dlsym(library, c"lattica_profile_pop".as_ptr());
            if push.is_null() || pop.is_null() {
                libc::dlclose(library);
                return Err("CUDA profiling library lacks range symbols".into());
            }
            Ok(Some(Api {
                _library: library as usize,
                push: std::mem::transmute::<*mut libc::c_void, Push>(push),
                pop: std::mem::transmute::<*mut libc::c_void, Pop>(pop),
            }))
        }
    })
}

pub(super) fn initialize() -> Result<()> {
    api().as_ref().map(|_| ()).map_err(Clone::clone)
}

pub(super) fn enabled() -> bool {
    matches!(api(), Ok(Some(_)))
}

// NVTX push/pop ranges are thread-local. Never move a live range to another thread.
pub(super) struct Range(Option<&'static Api>, PhantomData<Rc<()>>);
pub(super) fn range(label: &CStr) -> Range {
    let active = api().as_ref().ok().and_then(Option::as_ref);
    if let Some(api) = active {
        unsafe { (api.push)(label.as_ptr()) };
    }
    Range(active, PhantomData)
}
impl Drop for Range {
    fn drop(&mut self) {
        if let Some(api) = self.0 {
            unsafe { (api.pop)() };
        }
    }
}

pub(super) fn stage(stage: Option<Stage>) -> Range {
    range(match stage {
        Some(Stage::PublicValues) => c"cuda.public_values",
        Some(Stage::WitnessTrace) => c"cuda.witness",
        Some(Stage::Preprocessing) => c"cuda.preprocessing",
        Some(Stage::Lookup) => c"cuda.lookup",
        Some(Stage::Transform) => c"cuda.transform",
        Some(Stage::Quotient) => c"cuda.quotient",
        Some(Stage::Randomness) => c"cuda.randomness",
        Some(Stage::Hiding) => c"cuda.hiding",
        Some(Stage::Commitment) => c"cuda.commitment",
        Some(Stage::Opening) => c"cuda.opening",
        Some(Stage::FriFold) => c"cuda.fri_fold",
        Some(Stage::FriQuery) => c"cuda.fri_query",
        Some(Stage::FinalPolynomial) => c"cuda.final_polynomial",
        Some(Stage::Scalar) => c"cuda.scalar",
        Some(Stage::Transcript) => c"cuda.transcript",
        Some(Stage::Grinding) => c"cuda.grinding",
        _ => c"cuda.unclassified",
    })
}
