#!/usr/bin/env bash

# Copyright 2026 Flant JSC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Partial stand: runs the increment 1 cases that need no instrumented base, builders or index, by hand with
# the same fixtures, and prints the gate's refusal (or the success) of each. For a stand that has only a
# Delivery Kit binary, the pm binary and the stock images below; the specs of increment1_test.go need the full one.
#
#   DK=/home/ubuntu/sbom-increment-1/dk-1/releases/<sha>/werf PM=/path/to/pm \
#   STAGE_REPO=127.0.0.1:35110/pm1-e2e STOCK_EMPTY=registry.werf.io/werf/scratch@sha256:… \
#   STOCK_BASE=busybox@sha256:… [ONLY=<regex>] OUT=/tmp/i1-partial test/e2e/sbom/_increment1/partial-run.sh
#
# Own WERF_HOME with auto host cleanup off (nothing of another job on the host is touched); one build
# at a time, nice 10. Needs go (to build the ELF) and docker.
set -uo pipefail
EXECUTED="" # names of the cases selected (ONLY) and run in THIS invocation: assertions and post-checks look only at them
bad=0 # RED / SETUP FAILED / unpinned / outside-the-gate results: a non-zero exit of the runner (ALLOW_UNPINNED=1 tolerates unpinned patterns)
: "${DK:?Delivery Kit werf binary}" "${PM:?pm binary}" "${STAGE_REPO:?stage repository prefix}" "${STOCK_EMPTY:?empty stock image by digest}" "${STOCK_BASE:?non-empty stock image by digest}" "${OUT:?output directory}"
fixtures=$(cd "$(dirname "$0")/../_fixtures/increment1" && pwd)
mkdir -p "$OUT/tmp"
# A private TMPDIR as well as a private WERF_HOME: werf deletes stale tmp dirs it does not hold a lock for, and
# the locks live in WERF_HOME, so another job's werf on a shared /tmp would delete this one's live ones.
export TMPDIR=$OUT/tmp
unset SSH_AUTH_SOCK SSH_AGENT_PID DOCKER_BUILDKIT
export WERF_HOME=${WERF_HOME:-$OUT/werf-home} WERF_DISABLE_AUTO_HOST_CLEANUP=1 WERF_LOG_COLOR_MODE=off WERF_LOG_TERMINAL_WIDTH=200
export WERF_BUILDAH_MODE=docker WERF_INSECURE_REGISTRY=1 WERF_SKIP_TLS_VERIFY_REGISTRY=1 WERF_EXTERNAL_REFS_SERVER_URL=http://127.0.0.1:9
export WERF_SBOM_PM_BINARY=$PM WERF_SBOM_PM_SHA256=$(sha256sum "$PM" | cut -d' ' -f1)
run() { # name fixture BASE BASE_NO_SBOM BASE_NO_SBOM_EMPTY; ONLY=<regex of case names> runs a part of the cases
  local name=$1 fx=$2 d=$OUT/$1
  [[ $1 =~ ${ONLY:-.} ]] || return 0
  EXECUTED="$EXECUTED $1"
  rm -rf "$d"; cp -R "$fixtures/$fx" "$d"
  find "$d" -name werf.yaml -exec sed -i "s|@BASE@|$3|g; s|@BASE_NO_SBOM@|$4|g; s|@BASE_NO_SBOM_EMPTY@|$5|g" {} +
  if [ "$fx" = elf-in-git ] || [ "$fx" = checked-elf ]; then
    mkdir -p "$d/gen" && printf 'package main\n\nfunc main() {}\n' > "$d/gen/main.go" && printf 'module prebuilt\n\ngo 1.22\n' > "$d/gen/go.mod"
    mkdir -p "$d/prebuilt"
    (cd "$d/gen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$d/prebuilt/tool" .) && rm -rf "$d/gen"
    [ -s "$d/prebuilt/tool" ] || { echo "== $name: SETUP FAILED: $d/prebuilt/tool was not built"; bad=1; return 0; }
  fi
  (cd "$d" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -qm i)
  (cd "$d" && WERF_REPO=$STAGE_REPO/$name timeout 420 nice -n 10 "$DK" build >"$OUT/$name.log" 2>&1; echo "exit=$?" >>"$OUT/$name.log")
  echo "== $name: $(tail -1 "$OUT/$name.log")  $(grep -m1 '^Error:' "$OUT/$name.log" | sed 's/sha256:[0-9a-f]\{64\}/sha256:…/g' | cut -c1-260)"
}
selected() { [[ " $EXECUTED " == *" $1 "* ]]; }
# expect NAME refuse|pass prints OK or RED: RED = the gate does the opposite of the spec (a red control on a gate that excludes /.werf/).
expect() {
  selected "$1" || return 0
  local got=pass; grep -q '^exit=0$' "$OUT/$1.log" || got=refuse
  # A build that failed in the recipe (e.g. a read-only service directory) is not a refusal by the gate.
  if [ "$got" = refuse ] && { grep -q 'container run failed' "$OUT/$1.log" || ! grep -q -E "${3:-verify image app:}" "$OUT/$1.log"; }; then got="failed-outside-the-gate"; fi
  if [ "$got" = "$2" ] && [ "${3:-}" = "." ] && [ "${ALLOW_UNPINNED:-0}" != 1 ]; then
    echo "   $1: expected $2, got $got: UNPINNED (any failure but a recipe failure; pin the gate's wording first)"; bad=1
  elif [ "$got" = "$2" ]; then echo "   $1: expected $2, got $got: OK"
  else echo "   $1: expected $2, got $got: RED"; bad=1; fi
}
run elf-in-git elf-in-git scratch x x
expect elf-in-git refuse 'verify image app: /app/tool: no-data: missing sbom metadata'
run git-file-edited git-file-edited scratch x x
expect git-file-edited refuse 'hash-mismatch: git original changed'
run base-without-sbom base-without-sbom x "$STOCK_BASE" x
expect base-without-sbom refuse 'must have an SBOM artifact attached'
run base-empty-without-sbom base-empty-without-sbom x x "$STOCK_EMPTY"
expect base-empty-without-sbom refuse 'must have an SBOM artifact attached'
run from-scratch from-scratch x x x
expect from-scratch pass
run cache-mounts cache-mounts x x x
expect cache-mounts pass
# The service path /.werf/: a file a recipe writes there that is not a werf service file must be refused (the gate
# must not exclude the whole directory); werf's own service paths (the ssh agent socket) must not make a build fail.
run service-path-written service-path-written scratch x x
expect service-path-written refuse
# A red control proves a bypass only if the file is really in the image: list the layers of the published image.
layers_check() { # name file-in-image
  selected "$1" || return 0
  grep -q '^exit=0$' "$OUT/$1.log" || return 0
  (cd "$OUT/$1" && WERF_REPO=$STAGE_REPO/$1 "$DK" build --save-build-report --build-report-path "$OUT/$1.report.json" >>"$OUT/$1.log" 2>&1) || { echo "   $1: layer check build FAILED"; bad=1; return 0; }
  python3 - "$OUT/$1.report.json" "$OUT/$1.layers" "$2" "$1" <<'PY'
import json, subprocess, sys, tarfile, io
report, listing, wanted, name = sys.argv[1:]
ref = json.load(open(report))["Images"]["app"]["DockerImageName"]
preexisting = subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0
subprocess.run(["docker", "pull", "-q", ref], check=True, capture_output=True)
saved = subprocess.run(["docker", "save", ref], check=True, capture_output=True).stdout
names = []
with tarfile.open(fileobj=io.BytesIO(saved)) as outer:
    manifest = json.load(outer.extractfile("manifest.json"))
    for layer in manifest[0]["Layers"]:
        with tarfile.open(fileobj=io.BytesIO(outer.extractfile(layer).read())) as inner:
            names += ["/" + (n[2:] if n.startswith("./") else n.lstrip("/")) for n in inner.getnames()]
open(listing, "w").write("\n".join(names) + "\n")
print("   %s: %s in the image layers: %s" % (name, wanted, "YES" if wanted in names else "NO"))
if not preexisting:  # never remove an image that was there before this run
    subprocess.run(["docker", "rmi", ref], capture_output=True)
sys.exit(0 if wanted in names else 1)  # a red control is valid only if the file really is in the image
PY
  [ $? -eq 0 ] || { echo "   $1: layer check FAILED (the control file is not in the image or docker/report failed)"; bad=1; }
}
layers_check service-path-written /.werf/user/payload.txt
run service-path-dir-scripts service-path-dir-scripts scratch x x
expect service-path-dir-scripts refuse
layers_check service-path-dir-scripts /.werf/scripts/payload.txt
# /.werf/stapel is a build-time mount: a file written there is NOT in the published image (checked on 70dddd223), so it
# proves nothing about the gate and has no case here.
agent_dir=$(mktemp -d "$OUT/agent.XXXXXX"); eval "$(ssh-agent -a "$agent_dir/sock" -s)" >/dev/null
SSH_AUTH_SOCK=$agent_dir/sock run service-path-ssh-agent service-path-ssh-agent scratch x x
kill "$SSH_AGENT_PID" 2>/dev/null; rm -rf "$agent_dir"
expect service-path-ssh-agent pass
# The mounted cache contents must be in neither the published image nor its SBOM (spec of the cache-mounts fixture). Only a NON-EMPTY file under
# /go-cache/ or /tmp-cache/ counts as a leak (as in the Ginkgo spec): an empty file or directory there would not be flagged.
if selected cache-mounts && grep -q '^exit=0$' "$OUT/cache-mounts.log" 2>/dev/null; then
  (cd "$OUT/cache-mounts" && WERF_REPO=$STAGE_REPO/cache-mounts "$DK" build --save-build-report --build-report-path "$OUT/cache-mounts.report.json" >>"$OUT/cache-mounts.log" 2>&1 &&
    WERF_REPO=$STAGE_REPO/cache-mounts "$DK" sbom get app >"$OUT/cache-mounts.sbom.json" 2>>"$OUT/cache-mounts.log") || { echo "   cache-mounts: report/sbom commands FAILED"; bad=1; }
  python3 - "$OUT/cache-mounts.report.json" "$OUT/cache-mounts.sbom.json" "$OUT/cache-mounts.layers" <<'PY'
import json, subprocess, sys, tarfile, io
report, sbom, listing = sys.argv[1:]
ref = json.load(open(report))["Images"]["app"]["DockerImageName"]
preexisting = subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0
subprocess.run(["docker", "pull", "-q", ref], check=True, capture_output=True)
saved = subprocess.run(["docker", "save", ref], check=True, capture_output=True).stdout
names = []
with tarfile.open(fileobj=io.BytesIO(saved)) as outer:
    manifest = json.load(outer.extractfile("manifest.json"))
    leaked = []
    for layer in manifest[0]["Layers"]:
        with tarfile.open(fileobj=io.BytesIO(outer.extractfile(layer).read())) as inner:
            for member in inner.getmembers():
                name = "/" + (member.name[2:] if member.name.startswith("./") else member.name.lstrip("/"))
                names.append(name)
                # only a non-empty file under a mount directory is a leak (the mount points themselves are empty directories)
                if member.size > 0 and (name.startswith("/go-cache/") or name.startswith("/tmp-cache/")):
                    leaked.append(name)
open(listing, "w").write("\n".join(names) + "\n")
bom = json.load(open(sbom))
in_bom = [c["name"] for c in bom.get("components", []) if c.get("name", "").startswith(("/go-cache/", "/tmp-cache/"))]
output_present = "/app/output" in names
print("   cache-mounts: non-empty files under the mounts: %s; SBOM components under the mounts: %s; /app/output in image: %s" % (
    leaked or "none", in_bom or "none", output_present))
if not preexisting:  # never remove an image that was there before this run
    subprocess.run(["docker", "rmi", ref], capture_output=True)
sys.exit(1 if leaked or in_bom or not output_present else 0)
PY
  [ $? -eq 0 ] || { echo "   cache-mounts: cache contents leaked or the check FAILED"; bad=1; }
fi
# The spec's assertions for the passing build: the SBOM carries the verification marker and the git file as a file component.
if selected from-scratch && grep -q '^exit=0$' "$OUT/from-scratch.log" 2>/dev/null; then
  (cd "$OUT/from-scratch" && WERF_REPO=$STAGE_REPO/from-scratch "$DK" sbom get app >"$OUT/from-scratch.sbom.json" 2>"$OUT/from-scratch.sbom.err") || { echo "   from-scratch: sbom get FAILED"; bad=1; }
  python3 - "$OUT/from-scratch.sbom.json" <<'PY'
import json, sys
bom = json.load(open(sys.argv[1]))
props = [(p["name"], p["value"]) for p in bom.get("metadata", {}).get("properties", [])]
files = [c for c in bom.get("components", []) if c.get("name") == "/app/config.txt"]
ok = ("dk:verification", "instrumented-v1") in props and bool(files)
print("   from-scratch SBOM: dk:verification=instrumented-v1 %s; /app/config.txt component %s" % (
    "present" if ("dk:verification", "instrumented-v1") in props else "MISSING", "present" if files else "MISSING"))
sys.exit(0 if ok else 1)
PY
  [ $? -eq 0 ] || { echo "   from-scratch: SBOM assertions FAILED"; bad=1; }
fi

# Checked build-environment images (WERF_SBOM_CHECKED_IMAGES=gen): for the Delivery Kit with the checked producer. Prepared before
# the binary exists, not run yet; the refusal wording of the cases that must be refused is NOT pinned (pattern "." = any failure except a recipe failure
# (container run failed); fix the patterns after the first run). Spec of the cases: checked-final/checked-from refused by the configuration;
# checked-text exported as generated text is accepted; a modified git file (hash-mismatch), an ELF without a record, non-text data and
# a #!-script with an ELF payload are refused; a #!-script with a BEL is text and accepted.
export CHECKED_PATTERN='.'
checked() { # name expected(refuse|pass) pattern-or-sbom-path
  WERF_SBOM_CHECKED_IMAGES=gen run "$1" "$1" scratch x x
  if [ "$2" = pass ]; then
    expect "$1" pass
    # An accepted export must show up in the SBOM; a gate that silently drops the file would still exit 0.
    if selected "$1" && grep -q '^exit=0$' "$OUT/$1.log" 2>/dev/null; then
      if (cd "$OUT/$1" && WERF_SBOM_CHECKED_IMAGES=gen WERF_REPO=$STAGE_REPO/$1 "$DK" sbom get app >"$OUT/$1.sbom.json" 2>"$OUT/$1.sbom.err"); then
        if grep -q -F "$3" "$OUT/$1.sbom.json" 2>/dev/null; then echo "   $1: $3 in the SBOM: OK"; else echo "   $1: $3 in the SBOM: RED (absent)"; bad=1; fi
      else
        echo "   $1: sbom get FAILED (exit status)"; bad=1
      fi
    fi
  else
    # refusal of any kind except a recipe failure (container run failed) and a missing log; the gate's own wording is pinned after the first run
    expect "$1" refuse "${3:-.}"
  fi
}
checked checked-final refuse
checked checked-from refuse
checked checked-text pass /app/config.h
checked checked-git-modified refuse 'hash-mismatch'
checked checked-elf refuse
checked checked-binary refuse
# V1 on COMMITTED executable git scripts (variant A: only non-executable text can be generated): a git original with a BEL is text
checked checked-script-bel pass /app/run.sh
checked checked-script-elf refuse
# variant A boundary: an EXECUTABLE file generated by the checked stage is not generated text
checked checked-generated-exec refuse
[ -n "$EXECUTED" ] || { echo "no case matches ONLY=${ONLY:-.}: nothing was run"; bad=1; }
exit "$bad"
