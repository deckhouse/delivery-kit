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
#   STOCK_BASE=busybox@sha256:… OUT=/tmp/i1-partial test/e2e/sbom/_increment1/partial-run.sh
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
run() { # name fixture BASE BASE_NO_SBOM BASE_NO_SBOM_EMPTY
  local name=$1 fx=$2 d=$OUT/$1
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
