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

# Renders the configuration of every increment 1 fixture with placeholder values, with the
# Delivery Kit binary that will run the stand. No image is built and no registry is read.
#
#   WERF=/path/to/delivery-kit/werf test/e2e/sbom/_increment1/render.sh
set -euo pipefail
: "${WERF:?path to the Delivery Kit werf binary}"
fixtures=$(cd "$(dirname "$0")/../_fixtures/increment1" && pwd)
ref=registry.example.invalid/placeholder@sha256:$(printf '0%.0s' $(seq 64))
status=0
for fixture in "$fixtures"/*/; do
  name=$(basename "$fixture")
  work=$(mktemp -d)
  cp -R "$fixture". "$work"/
  find "$work" -name werf.yaml -exec sed -i.bak \
    -e "s|@BASE@|$ref|g" -e "s|@BASE_NO_SBOM@|$ref|g" -e "s|@BUILDER_NATIVE@|$ref|g" -e "s|@BUILDER_GO@|$ref|g" \
    -e "s|@PM_PACKAGE@|tzdata|g" -e "s|@PM_PACKAGE_FILE@|/usr/share/zoneinfo/UTC|g" -e "s|@OTHER_INDEX@|$ref|g" {} +
  find "$work" -name '*.bak' -delete
  (cd "$work" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -qm render &&
    "$WERF" config render --env dev >"$work/render.out" 2>&1) && echo "ok   $name ($(grep -c '^image:' "$work/render.out") images)" || {
    echo "FAIL $name:"; tail -5 "$work/render.out"; status=1; }
  rm -rf "$work"
done
exit $status
