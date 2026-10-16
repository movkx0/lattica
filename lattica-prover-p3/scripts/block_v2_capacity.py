"""Explicit block profiles. Planned sizes are never admitted as supported sizes."""
import json
import subprocess
from pathlib import Path

DEFAULT_CAPACITY = 64
SUPPORTED_CAPACITIES = (64, 128)
PLANNED_CAPACITIES = (256, 512)
MAX_TRANSACTIONS = max(SUPPORTED_CAPACITIES)
MAX_DAG_NODES = 2 * MAX_TRANSACTIONS - 1

def validate(capacity):
    if type(capacity) is not int or capacity not in SUPPORTED_CAPACITIES:
        raise ValueError("supported block capacities are 64 and 128; 256/512 are planned")
    return capacity

def depth(capacity):
    return validate(capacity).bit_length() - 1

def select(count, capacity=None):
    if type(count) is not int:
        raise ValueError("transaction count must be an integer")
    capacity = validate(capacity if capacity is not None else (128 if count > 64 else 64))
    if type(count) is not int or not 1 <= count <= capacity:
        raise ValueError("transaction count exceeds the selected block profile")
    return capacity

def configured(config):
    capacity = config.get("block_capacity", DEFAULT_CAPACITY)
    validate(capacity)
    if "count" in config:
        select(config["count"], capacity)
    return capacity

def root_file(config=None, *, capacity=None):
    if capacity is None:
        capacity = configured(config or {})
    return f"node.{depth(capacity)}.0"

def require_binaries(capacity, *binaries):
    validate(capacity)
    for binary in binaries:
        command = [str(Path(binary).resolve(strict=True)), "capacity"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError("block profile requires CPU and GPU binaries with a capacity descriptor")
        receipt = json.loads(result.stdout)
        if (not isinstance(receipt, dict) or receipt.get("schema") != "lattica-block-capacity-v1"
                or type(receipt.get("max_transactions")) is not int
                or type(receipt.get("tree_depth")) is not int
                or receipt.get("max_transactions") != capacity
                or receipt.get("tree_depth") != depth(capacity)):
            raise ValueError("CPU/GPU executable block capacity does not match the requested profile")


def coordinator_shared_bytes(capacity, workers=1):
    validate(capacity)
    if type(workers) is not int or not 1 <= workers <= 16:
        raise ValueError("coordinator requires 1..16 workers")
    if capacity == 64:
        return 576 << 20
    return (687 + workers - 1) << 20
