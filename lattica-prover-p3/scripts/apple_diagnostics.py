"""Optional, bounded CPU stack samples triggered by public proof-start markers."""
import hashlib
import os


class StackSampler:
    def __init__(self, owned, worker, job, handles):
        self.owned, self.worker, self.job, self.handles = owned, worker, job, handles
        self.reader = (job / "worker.log").open("r")
        handles.append(self.reader)
        self.partial = ""
        self.starts = 0
        self.samples = []

    def poll(self):
        lines = (self.partial + self.reader.read()).split("\n")
        self.partial = lines.pop()
        for line in lines:
            if not line.startswith("proof_start "):
                continue
            self.starts += 1
            if self.starts not in (1, 7) or self.worker.poll() is not None:
                continue
            label = "wrapper" if self.starts == 1 else "root"
            path = self.job / f"cpu-sample-{label}.txt"
            log = (self.job / f"cpu-sample-{label}.log").open("w")
            self.handles.append(log)
            process = self.owned.spawn(["/usr/bin/sample", str(self.worker.pid), "5", "10", "-file", path],
                os.environ, log, role="sampler")
            self.samples.append((label, path, process))
            print("DIAGNOSTIC_SAMPLE_START", self.job.name, label, flush=True)

    def summary(self):
        result = []
        for label, path, process in self.samples:
            code = process.poll()
            passed = code == 0 and path.exists() and path.stat().st_size > 0
            row = {"phase": label, "status": "PASS" if passed else "FAILED", "exit_code": code,
                   "duration_seconds": 5, "interval_ms": 10, "path": str(path)}
            if passed:
                row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                print("DIAGNOSTIC_SAMPLE_FAILED", self.job.name, label, code, flush=True)
            result.append(row)
        for label in ("wrapper", "root"):
            if not any(row["phase"] == label for row in result):
                result.append({"phase": label, "status": "NOT_TRIGGERED"})
        return result
