"""Strict public-hash execution evidence shared by research guards and audits.

These checks validate reported evidence and agreement, not executable provenance
or cryptographic correctness. The enclosing guard must bind the reports to the
recorded build, source snapshot, selected device, and completed native work.
"""

PUBLIC_HASH_KERNELS = ("baseline", "sbox-pair-v1")
_FIELDS = frozenset(("kernel", "gpu_tuning_compiled", "nvidia_supported"))


def _kernel(value, source):
    if type(value) is not str or value not in PUBLIC_HASH_KERNELS:
        raise ValueError(f"{source}: invalid public hash kernel")
    return value


def validate_record(value, *, expected_kernel=None, source="public_hash"):
    """Return a fresh, validated copy of one completed-execution report.

    Missing reports are errors, including for a newly requested baseline. A
    baseline may use a gpu-tuning build or a portable non-NVIDIA device. The
    candidate requires both build support and actual NVIDIA capability. Flags
    must be JSON booleans; integers and truthy strings are never equivalent.
    """
    if expected_kernel is not None:
        _kernel(expected_kernel, "requested selection")
    if type(value) is not dict or set(value) != _FIELDS:
        raise ValueError(f"{source}: missing or unexpected public hash evidence fields")
    kernel = _kernel(value["kernel"], source)
    for field in ("gpu_tuning_compiled", "nvidia_supported"):
        if type(value[field]) is not bool:
            raise ValueError(f"{source}: {field} must be a boolean")
    if kernel == "sbox-pair-v1" and not (
        value["gpu_tuning_compiled"] and value["nvidia_supported"]
    ):
        raise ValueError(f"{source}: candidate lacks compiled GPU tuning or NVIDIA support")
    if expected_kernel is not None and kernel != expected_kernel:
        raise ValueError(f"{source}: effective public hash kernel differs from requested selection")
    return {field: value[field] for field in ("kernel", "gpu_tuning_compiled", "nvidia_supported")}


def require_requested(record, requested_kernel, environment_kernel):
    """Bind effective execution to both explicit plan and sanitized environment.

    A missing environment value is an error. The runner must write an explicit
    baseline as well as an explicit candidate; inherited process state does not
    select a kernel. This function reads no process environment itself.
    """
    requested = _kernel(requested_kernel, "requested selection")
    environment = _kernel(environment_kernel, "execution environment")
    if requested != environment:
        raise ValueError("execution environment: public hash kernel differs from requested selection")
    return validate_record(record, expected_kernel=requested)


def workflow_records(workflow, proving, verification, *, expected_kernel=None):
    """Require the summary and both GPU preprocessing lifetimes to agree.

    ``verification`` describes independent reconstruction and fresh GPU
    preprocessing. Its subsequent numerical proof verification remains CPU
    work; this helper never changes or infers that separate backend policy.
    The caller must pass all three reports. Absence never implies a baseline.
    """
    agreed = None
    for source, report in (
        ("workflow", workflow), ("proving", proving), ("verification", verification)
    ):
        if type(report) is not dict:
            raise ValueError(f"{source}: expected a workflow report object")
        evidence = validate_record(
            report.get("public_hash"), expected_kernel=expected_kernel,
            source=f"{source}.public_hash",
        )
        if agreed is None:
            agreed = evidence
        elif evidence != agreed:
            raise ValueError(f"{source}.public_hash: execution evidence differs across workflow reports")
    return agreed
