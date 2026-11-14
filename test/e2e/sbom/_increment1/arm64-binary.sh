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
# cross-compiled in the builder, where the patched Go writes the composition record of the target (profile go,
# platform linux/arm64; the linker patch accepts linux/amd64 and linux/arm64). Run on the build host, under its
# lock, once the builder is published.
#
# The build runs with plain `docker run` and a bind mount, not through werf: an image with build.sbom.enable would be
# refused by the strict gate for holding a foreign-platform ELF, which is the very case this binary is for.
#
#   GOLANG=<builder/golang-alt-1.27 repo@sha256:…> PM=<pm binary> OUT=/path/hello-arm64 \
#   test/e2e/sbom/_increment1/arm64-binary.sh
#
# Exit 0 only if the binary exists, is an ELF for aarch64, and `pm info --build-info` reads a present record for it
# whose platform is linux/arm64. If the patched Go writes no record for arm64, this is the place it shows: tell BI-1.
# The script does not supply SBOM_BUILD_CONTEXT (the helper context a patched Go may need outside a werf stage): a failure
# on that account is a finding for DK-1/BI-1, not proof that arm64 records are impossible.
# Not run end to end yet (no builder at the time of writing). The pulled builder image is removed by tag at the end
# only if this script pulled it.
set -euo pipefail
: "${GOLANG:?}" "${PM:?}" "${OUT:?}"
work=$(mktemp -d)
pulled=
trap 'rm -rf "$work"; [ -z "$pulled" ] || docker rmi "$GOLANG" >/dev/null 2>&1 || true' EXIT
docker image inspect "$GOLANG" >/dev/null 2>&1 || { docker pull -q "$GOLANG" >/dev/null; pulled=1; }
mkdir "$work/src" "$work/out"
printf 'module hello\n\ngo 1.22\n' > "$work/src/go.mod"
printf 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hello") }\n' > "$work/src/main.go"
# The builder may define an ENTRYPOINT and its PATH only in the image config: bypass the entrypoint and take PATH from it.
path=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$GOLANG" | sed -n 's/^PATH=//p')
[ -n "$path" ] || { echo "FAIL the builder image has no PATH in its config"; exit 1; }
docker run --rm --platform linux/amd64 --entrypoint /bin/sh -v "$work/src:/src:ro" -v "$work/out:/out" -w /src \
  -e "PATH=$path" -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=arm64 -e GOCACHE=/tmp/gocache "$GOLANG" \
  -c 'go version && go env GOROOT && go build -buildvcs=false -o /out/hello-arm64 .' >"$work/build.log" 2>&1 \
  || { echo "FAIL the cross build failed:"; tail -40 "$work/build.log"; exit 1; }
cat "$work/build.log"
cp "$work/out/hello-arm64" "$OUT"
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
