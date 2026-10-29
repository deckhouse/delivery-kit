"""Mandatory native POC acceptance, separate from portable unit tests.

Set DK_LOADER_FIXTURE to runtime-pie-oracle.py's composite loader-v5/out and
DK_NATIVE_INSPECT_FIXTURE to export-native-inspect-fixture.py's directory, and
DK_GO_FIXTURE to the frozen pure-Go ELF/record directory, and
DK_GO_MODULES_FIXTURE to the frozen module/replacement/VCS ELF directory,
and DK_CROSS_CLI_FIXTURE to the frozen Mach-O/PE/Linux-ARM binaries and records.
DK_PM_BINARY must point to the frozen pm writer used for serial install/import verification.
Then run: TASK_X_REMOTE_TASKFILES=1 task --yes test:native-poc
All frozen inputs must be present; no executable fixture is stored in Git.
The rsync oracle also requires Docker and the locally available stapel image
pinned by pkg/stapel (the gate does not pull it implicitly).
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


GO_MODULE_PINS = {
    "go-module-versioned-elf": ("309bc007183399cca557943000b2e1e5f1a66557c829485235ea7dc4a166faa7", "eec2cd68a8fb4e8225d38d8a61f59bb8525183037adebec07489290615bed488"),
    "go-module-replaced-elf": ("fae4938464f5548ba6c58fff335390db4ff3317e65b4c01dfd2df9c3e9dbcfcc", "0711ad1f7a63f21449c657444d046708a857c0cee6c2f82994166cdb1550441b"),
    "go-module-local-replaced-elf": ("4206d48c818160e69401ce98f6b9e0a614f7db30233c01350eda0459207d90a7", "76c57e02b8499024eab49d19621b6b908bf67e1347be724cfd82f5ac9216f85f"),
    "go-module-vcs-tagged-elf": ("7e7c6cbf4c1d14f3ab058aad4a8fbd9a878ca9cb654ee521de5ae4e8aec50778", "0b690898633672e3fb2e5a5af511de5d237aee375cbc5affbd1328463c78b4bc"),
    "go-module-vcs-dirty-elf": ("24f2dd1c4679b57294eae480d62264995837f5f8f18261b43da16a37822d6564", "9d2c59b89d89b7c8ce12e53f0aa63ec3700494a966a278738733cf7d56ca4b6f"),
}


CROSS_CLI_PINS = {
    "go-darwin-amd64": ("afe276bc8515aecd23db43566d8cd611790cebfe42d2a5b797345544446c8335", "ee2417d1fb19f1a7533394183228581a272482e7cbc9e8b2751a5d8bacaee368"),
    "go-darwin-arm64": ("46435400faca319060974e9037ea06b85c8c92fb8e980806aecfd02f357c2d42", "f5e5bda2e340b9b406cfe59afe15795fff91184aaa6fd70bb59c9c6eecaff565"),
    "go-windows-amd64.exe": ("7ef28a2b2ed55e33052283d8c2480b3ec7aa7212ac97696143bc8ede73c35247", "dc90f9346dd07c840bf175792d7088768d84cc90e6d2ec572d4b45d44737da09"),
    "go-linux-arm": ("8846d60614cc49d8d15675c12df9e7ab9c13b68d00a88c5294289772fd7b7e5c", "25d2b37f532f780f60c54591cf8f040b49081496db5369db82b30a4f54b087ee"),
}


def main():
    loader = required_directory("DK_LOADER_FIXTURE")
    native = required_directory("DK_NATIVE_INSPECT_FIXTURE")
    go_fixture = required_directory("DK_GO_FIXTURE")
    go_modules = required_directory("DK_GO_MODULES_FIXTURE")
    cross_cli = required_directory("DK_CROSS_CLI_FIXTURE")
    for name, (binary_pin, record_pin) in CROSS_CLI_PINS.items():
        if sha256(cross_cli / name) != binary_pin or sha256(cross_cli / (name + ".sbom.json")) != record_pin:
            raise SystemExit(f"Cross CLI fixture pin mismatch: {name}")
    for name, (binary_pin, record_pin) in GO_MODULE_PINS.items():
        if sha256(go_modules / name) != binary_pin or sha256(go_modules / (name + ".sbom.json")) != record_pin:
            raise SystemExit(f"Go module fixture pin mismatch: {name}")
    pm_binary = os.environ.get("DK_PM_BINARY")
    if not pm_binary or not Path(pm_binary).is_file():
        raise SystemExit("DK_PM_BINARY must name the pinned pm writer executable")
    if sha256(Path(pm_binary)) != "d40ad4f58374fe296d367ef6b144d08fa49f2e51d81be650dd5eec92f4fe8ae1":
        raise SystemExit("pm writer binary pin mismatch")
    if sha256(go_fixture / "go-pure-elf") != "6633c6efe582b616f97743a113cbbbf98a8cf43f22851613e6c36dd6e906280e":
        raise SystemExit("pure-Go fixture pin mismatch")
    if sha256(go_fixture / "go-pure-elf.sbom.json") != "294d967f1256a93a69154829806ef3f7aa91190ea4625d55b6e7ba0f561b47e1":
        raise SystemExit("pure-Go record pin mismatch")
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
