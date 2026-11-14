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

# Produces the instrumented linux/arm64 binary the foreign-arch case needs (WERF_TEST_I1_ARM64_BINARY): a Go hello
# cross-compiled in the strict builder, where the patched Go writes the composition record of the target
# (profile go, platform linux/arm64; the linker patch accepts linux/amd64 and linux/arm64). Run on the build host,
# under its lock, once the builder is published.
#
#   WERF=<delivery kit werf> REPO=<stage repo> GOLANG=<builder/golang-alt-1.27 repo@sha256:…> PM=<pm binary> \
#   OUT=/path/hello-arm64 test/e2e/sbom/_increment1/arm64-binary.sh
#
# Exit 0 only if the binary exists, is an ELF for aarch64, and `pm info --build-info` reads a present record for it
# whose platform is linux/arm64. If the patched Go writes no record for arm64, this is the place it shows: tell BI-1.
set -euo pipefail
: "${WERF:?}" "${REPO:?}" "${GOLANG:?}" "${PM:?}" "${OUT:?}"
work=$(mktemp -d)
trap 'rm -rf "$work"; docker rm -f arm64-binary-extract >/dev/null 2>&1 || true' EXIT
cd "$work"
git init -q . && git config user.email t@t && git config user.name t
printf 'module hello\n\ngo 1.22\n' > go.mod
printf 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hello") }\n' > main.go
cat > werf.yaml <<YAML
project: arm64-binary
configVersion: 1
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
---
image: hello
from: ${GOLANG}
git:
- add: /
  to: /src
  includePaths: [go.mod, main.go]
packages:
- type: go-mod
  workdir: /src
shell:
  install:
  - mkdir -p /out
  - cd /src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -o /out/hello-arm64 .
YAML
git add -A && git commit -qm hello
"$WERF" build --repo "$REPO" --insecure-registry --platform linux/amd64 --save-build-report --build-report-path report.json >build.log 2>&1 \
  || { echo "FAIL the cross build failed:"; tail -40 build.log; exit 1; }
image=$(python3 -c 'import json;r=json.load(open("report.json"))["Images"]["hello"];print(r["DockerRepo"]+"@"+r["DockerImageDigest"])')
docker pull -q "$image" >/dev/null
docker create --name arm64-binary-extract "$image" >/dev/null
docker cp arm64-binary-extract:/out/hello-arm64 "$OUT"
file "$OUT" | grep -q "ELF 64-bit.*ARM aarch64" || { echo "FAIL $OUT is not an aarch64 ELF: $(file "$OUT")"; exit 1; }
info=$("$PM" info --build-info --json "$OUT") || { echo "FAIL no present record in the arm64 binary:"; echo "$info"; exit 1; }
echo "$info" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
files = doc.get("files") or []
if not files or files[0].get("status") != "present":
    sys.exit("FAIL the record of the arm64 binary is not present: %s" % json.dumps(files)[:300])
platform = files[0]["sbom"]["profile"]["platform"]
if platform != "linux/arm64":
    sys.exit("FAIL the record states platform %s, want linux/arm64" % platform)
print("ok: record present, profile %s on %s" % (files[0]["sbom"]["profile"]["id"], platform))'
