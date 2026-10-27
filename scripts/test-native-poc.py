"""Mandatory native POC acceptance, separate from portable unit tests.

Set DK_LOADER_FIXTURE to runtime-reuse-oracle.py's composite loader-v4/out and
DK_NATIVE_INSPECT_FIXTURE to export-native-inspect-fixture.py's directory.
Then run: TASK_X_REMOTE_TASKFILES=1 task --yes test:native-poc
Both frozen fixtures must be present; no executable fixture is stored in Git.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_directory(name):
    value = os.environ.get(name)
    if not value or not Path(value).is_dir():
        raise SystemExit(f"{name} must name an existing pinned fixture directory")
    return Path(value)


def main():
    loader = required_directory("DK_LOADER_FIXTURE")
    native = required_directory("DK_NATIVE_INSPECT_FIXTURE")
    if sha256(loader / "ld-linux-x86-64.so.2") != "606bf05526f326f0f4cd42450ff6ee0a7c9ff9391d7f37f38473874e0897e53c":
        raise SystemExit("loader fixture pin mismatch")
    manifest_path = native / "manifest.json"
    if sha256(manifest_path) != "6cb2a3c62c0324fc91afa929b106cd3b65d863c70ca7473cecb5f2dd6008c9a8":
        raise SystemExit("native inspect fixture manifest pin mismatch")
    manifest = json.loads(manifest_path.read_text())
    for name, expected in manifest["files"].items():
        if sha256(native / name) != expected:
            raise SystemExit(f"native inspect fixture content mismatch: {name}")
    with tempfile.TemporaryDirectory(prefix="dk-native-poc-") as directory:
        report_path = Path(directory) / "ginkgo.json"
        subprocess.run([
            "task", "--yes", "test:unit", "paths=./pkg/sbom/nativegate", "parallel=1",
            "--", "--json-report=" + str(report_path),
        ], check=True)
        reports = json.loads(report_path.read_text())
        specs = [spec for report in reports for spec in report["SpecReports"]]
        if not reports or not specs or any(not report["SuiteSucceeded"] for report in reports):
            raise SystemExit("native POC suite did not succeed")
        if any(spec["State"] != "passed" for spec in specs):
            raise SystemExit("native POC acceptance requires all specs passed, with no skips")
        print(f"Native POC acceptance: {len(specs)} passed, zero skipped; fixture pins verified")


if __name__ == "__main__":
    main()
