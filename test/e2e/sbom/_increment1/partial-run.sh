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
  rm -rf "$d"; cp -R "$fixtures/$fx" "$d"
  find "$d" -name werf.yaml -exec sed -i "s|@BASE@|$3|g; s|@BASE_NO_SBOM@|$4|g; s|@BASE_NO_SBOM_EMPTY@|$5|g" {} +
  if [ "$fx" = elf-in-git ]; then
    mkdir -p "$d/gen" && printf 'package main\n\nfunc main() {}\n' > "$d/gen/main.go" && printf 'module prebuilt\n\ngo 1.22\n' > "$d/gen/go.mod"
    (cd "$d/gen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$d/prebuilt/tool" .) && rm -rf "$d/gen"
  fi
  (cd "$d" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -qm i)
  (cd "$d" && WERF_REPO=$STAGE_REPO/$name timeout 420 nice -n 10 "$DK" build >"$OUT/$name.log" 2>&1; echo "exit=$?" >>"$OUT/$name.log")
  echo "== $name: $(tail -1 "$OUT/$name.log")  $(grep -m1 '^Error:' "$OUT/$name.log" | sed 's/sha256:[0-9a-f]\{64\}/sha256:…/g' | cut -c1-260)"
}
run elf-in-git elf-in-git scratch x x
run git-file-edited git-file-edited scratch x x
run base-without-sbom base-without-sbom x "$STOCK_BASE" x
run base-empty-without-sbom base-empty-without-sbom x x "$STOCK_EMPTY"
run from-scratch from-scratch x x x
run cache-mounts cache-mounts x x x
# The service path /.werf/: a file a recipe writes there that is not a werf service file must be refused (the gate
# must not exclude the whole directory); werf's own service paths (the ssh agent socket) must not make a build fail.
# expect NAME refuse|pass prints OK or RED: RED = the gate does the opposite of the spec (a red control on a gate that excludes /.werf/).
expect() {
  [ -f "$OUT/$1.log" ] || return 0
  local got=pass; grep -q '^exit=0$' "$OUT/$1.log" || got=refuse
  if [ "$got" = "$2" ]; then echo "   $1: expected $2, got $got: OK"; else echo "   $1: expected $2, got $got: RED"; fi
}
run service-path-written service-path-written scratch x x
expect service-path-written refuse
# A red control proves a bypass only if the file is really in the image: list the layers of the published image.
if grep -q '^exit=0$' "$OUT/service-path-written.log"; then
  (cd "$OUT/service-path-written" && WERF_REPO=$STAGE_REPO/service-path-written "$DK" build --save-build-report --build-report-path "$OUT/service-path-written.report.json" >>"$OUT/service-path-written.log" 2>&1)
  python3 - "$OUT/service-path-written.report.json" "$OUT/service-path-written.layers" <<'PY'
import json, subprocess, sys, tarfile, io
report, listing = sys.argv[1:]
ref = json.load(open(report))["Images"]["app"]["DockerImageName"]
subprocess.run(["docker", "pull", "-q", ref], check=True, capture_output=True)
saved = subprocess.run(["docker", "save", ref], check=True, capture_output=True).stdout
names = []
with tarfile.open(fileobj=io.BytesIO(saved)) as outer:
    manifest = json.load(outer.extractfile("manifest.json"))
    for layer in manifest[0]["Layers"]:
        with tarfile.open(fileobj=io.BytesIO(outer.extractfile(layer).read())) as inner:
            names += ["/" + (n[2:] if n.startswith("./") else n.lstrip("/")) for n in inner.getnames()]
open(listing, "w").write("\n".join(names) + "\n")
print("   service-path-written: /.werf/user/payload.txt in the image layers: %s" % ("YES" if "/.werf/user/payload.txt" in names else "NO"))
subprocess.run(["docker", "rmi", ref], capture_output=True)
PY
fi
agent_dir=$(mktemp -d "$OUT/agent.XXXXXX"); eval "$(ssh-agent -a "$agent_dir/sock" -s)" >/dev/null
SSH_AUTH_SOCK=$agent_dir/sock run service-path-ssh-agent service-path-ssh-agent scratch x x
kill "$SSH_AGENT_PID" 2>/dev/null; rm -rf "$agent_dir"
expect service-path-ssh-agent pass
# The mounted cache contents must be in neither the published image nor its SBOM (spec of the cache-mounts fixture).
if grep -q '^exit=0$' "$OUT/cache-mounts.log"; then
  (cd "$OUT/cache-mounts" && WERF_REPO=$STAGE_REPO/cache-mounts "$DK" build --save-build-report --build-report-path "$OUT/cache-mounts.report.json" >>"$OUT/cache-mounts.log" 2>&1 &&
    WERF_REPO=$STAGE_REPO/cache-mounts "$DK" sbom get app >"$OUT/cache-mounts.sbom.json" 2>>"$OUT/cache-mounts.log")
  python3 - "$OUT/cache-mounts.report.json" "$OUT/cache-mounts.sbom.json" "$OUT/cache-mounts.layers" <<'PY'
import json, subprocess, sys, tarfile, io
report, sbom, listing = sys.argv[1:]
ref = json.load(open(report))["Images"]["app"]["DockerImageName"]
subprocess.run(["docker", "pull", "-q", ref], check=True, capture_output=True)
saved = subprocess.run(["docker", "save", ref], check=True, capture_output=True).stdout
names = []
with tarfile.open(fileobj=io.BytesIO(saved)) as outer:
    manifest = json.load(outer.extractfile("manifest.json"))
    for layer in manifest[0]["Layers"]:
        with tarfile.open(fileobj=io.BytesIO(outer.extractfile(layer).read())) as inner:
            names += ["/" + (n[2:] if n.startswith("./") else n.lstrip("/")) for n in inner.getnames()]
open(listing, "w").write("\n".join(names) + "\n")
leaked = [n for n in names if n.startswith(("/go-cache", "/tmp-cache"))]
bom = json.load(open(sbom))
in_bom = [c["name"] for c in bom.get("components", []) if c.get("name", "").startswith(("/go-cache/", "/tmp-cache/"))]
print("   cache-mounts: image paths under the mounts: %s; SBOM components under the mounts: %s; /app/output in image: %s" % (
    leaked or "none", in_bom or "none", "/app/output" in names))
subprocess.run(["docker", "rmi", ref], capture_output=True)
PY
fi
# The spec's assertions for the passing build: the SBOM carries the verification marker and the git file as a file component.
if grep -q '^exit=0$' "$OUT/from-scratch.log"; then
  (cd "$OUT/from-scratch" && WERF_REPO=$STAGE_REPO/from-scratch "$DK" sbom get app >"$OUT/from-scratch.sbom.json" 2>"$OUT/from-scratch.sbom.err")
  python3 - "$OUT/from-scratch.sbom.json" <<'PY'
import json, sys
bom = json.load(open(sys.argv[1]))
props = [(p["name"], p["value"]) for p in bom.get("metadata", {}).get("properties", [])]
files = [c for c in bom.get("components", []) if c.get("name") == "/app/config.txt"]
print("   from-scratch SBOM: dk:verification=instrumented-v1 %s; /app/config.txt component %s" % (
    "present" if ("dk:verification", "instrumented-v1") in props else "MISSING", "present" if files else "MISSING"))
PY
fi
