use super::*;
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn host_transfer_census_is_pure_and_additive_to_all_original_owners() {
    let (bytes, requests) = measure(ShakeSourceDeviceCensus::host_transfer_wrapper_bytes);
    let bytes = bytes.unwrap();
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
    assert!(bytes > ERROR_SLOTS * (REPLY_BYTES + ERROR_FORMAT_BYTES));
    assert!(bytes > FENCES * size_of::<engine::QueueFence>());
    assert!(bytes < 1 << 20);
    assert!(add(usize::MAX, 1).is_err());
    assert!(mul(usize::MAX, 2).is_err());
}

#[test]
fn actual_transfer_and_fence_source_preserve_borrowed_sequential_ownership() {
    let storage = include_str!("../../../../../../retained_storage.rs");
    let offload = storage
        .split("pub(super) fn retain_completed_tree(")
        .nth(1)
        .unwrap()
        .split("fn upload_host_tree(")
        .next()
        .unwrap();
    let reload = storage
        .split("fn upload_host_tree(")
        .nth(1)
        .unwrap()
        .split("pub(super) fn open_retained_batch(")
        .next()
        .unwrap();
    for body in [offload, reload] {
        assert_eq!(body.matches("let fence = self.fence();").count(), 1);
        assert_eq!(body.matches("let mut event = Event::empty();").count(), 1);
        assert_eq!(body.matches(".enew(&mut event)").count(), 1);
        assert_eq!(body.matches("fence.finish()?").count(), 1);
        assert!(!body.contains(".enq_async(") && !body.contains(".ewait("));
        assert!(!body.contains(".block(false)") && !body.contains("EventList"));
        assert!(!body.contains("RwVec") && !body.contains("Vec<Event>"));
    }
    assert!(offload.contains(".read(&mut self.staging[0].map[..output.len()])"));
    assert!(reload.contains(".write(&self.staging[0].map[..words.len()])"));
    assert!(offload.find("fence.finish()?").unwrap() < offload.find("drop(device)").unwrap());
    assert!(offload.contains("host.words.capacity() != layout.elements"));
    let engine = include_str!("../../../../../../../engine.rs");
    let fence = engine
        .split("impl QueueFence {")
        .nth(1)
        .unwrap()
        .split("impl Drop for QueueFence")
        .next()
        .unwrap();
    assert!(fence.contains("let a = self.copy.finish();"));
    assert!(fence.contains("let b = self.compute.finish();"));
    assert!(fence.contains("a.and(b).map_err(|e| e.to_string())"));
    let drop_fence = engine
        .split("impl Drop for QueueFence {")
        .nth(1)
        .unwrap()
        .split("struct Engine {")
        .next()
        .unwrap();
    assert!(drop_fence.contains("fatal_cleanup(\"queue_drain\", error)"));
}

#[test]
fn real_opencl_error_and_profiling_owners_fit_additive_failure_slots() {
    // Exercise the public bounded-info failure and ocl wrapper conversion
    // without a driver. The private enqueue/finish ApiError formatter remains
    // covered by the pinned source census, not this public-API allocation test.
    for operation in [
        "clEnqueueReadBuffer",
        "clEnqueueWriteBuffer",
        "clFinish",
        "clWaitForEvents",
        "clGetEventProfilingInfo",
    ] {
        let (_, requests) = measure(|| {
            let original = String::from("host transfer failed");
            let copy: ocl::core::Error = ocl::core::bounded_info::Error::ApiFailure {
                operation,
                request: 0,
                status: ocl::core::Status::CL_OUT_OF_RESOURCES as i32,
            }
            .into();
            let compute: ocl::core::Error = ocl::core::bounded_info::Error::ApiFailure {
                operation: "clFinish",
                request: 0,
                status: ocl::core::Status::CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST as i32,
            }
            .into();
            let copy = ocl::Error::from(copy);
            let compute = ocl::Error::from(compute);
            let formatted = copy.to_string();
            let fatal = format!("queue_drain: {formatted}");
            std::hint::black_box((&original, &copy, &compute, &formatted, &fatal));
            assert!(formatted.capacity() < ERROR_FORMAT_BYTES);
            assert!(fatal.capacity() < ERROR_FORMAT_BYTES);
        });
        assert!(!requests.overflow && requests.bytes < ERROR_SLOTS * ERROR_FORMAT_BYTES);
    }
    // The real pinned decoding constructor consumes each eight-byte reply;
    // the resulting profiling scalar has no retained allocation.
    let (values, requests) = measure(|| {
        use ocl::enums::{ProfilingInfo, ProfilingInfoResult};
        let start =
            ProfilingInfoResult::from_bytes(ProfilingInfo::Start, 7u64.to_ne_bytes().to_vec())
                .unwrap();
        let end = ProfilingInfoResult::from_bytes(ProfilingInfo::End, 11u64.to_ne_bytes().to_vec())
            .unwrap();
        (start.time().unwrap(), end.time().unwrap())
    });
    assert_eq!(values, (7, 11));
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (2, 16, false)
    );
}
