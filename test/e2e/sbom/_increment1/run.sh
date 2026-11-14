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

# Runs the increment 1 specs (test/e2e/sbom/increment1_test.go) with a Delivery Kit binary against
# an instrumented stand. Take the stand variables from the BI-1 state file (bi-1.md) and the
# binary from scripts built by dk-build.sh. Run it on the Linux build host, under its lock.
#
#   WERF_TEST_BINARY_PATH=/home/ubuntu/sbom-increment-1/dk-1/releases/<sha>/werf \
#   WERF_TEST_K8S_DOCKER_REGISTRY=127.0.0.1:35110 \
#   WERF_TEST_I1_PM_BINARY=/home/ubuntu/sbom-increment-1/pm-1/linux-amd64/pm \
#   WERF_TEST_I1_TRUSTED_INDEXES='127.0.0.1:35110/sbom-incr1/index@sha256:...' \
#   WERF_TEST_I1_BASE=... WERF_TEST_I1_BUILDER_NATIVE=... WERF_TEST_I1_BUILDER_GO=... \
#   WERF_TEST_I1_BASE_NO_SBOM=... WERF_TEST_I1_PM_PACKAGE=tzdata \
#   WERF_TEST_I1_PM_PACKAGE_FILE=/usr/share/zoneinfo/UTC WERF_TEST_I1_OTHER_INDEX=... \
#     test/e2e/sbom/_increment1/run.sh
set -euo pipefail
: "${WERF_TEST_BINARY_PATH:?path to the Delivery Kit werf binary}"
for key in PM_BINARY PM_SHA256 TRUSTED_INDEXES BASE BASE_NO_SBOM BUILDER_NATIVE BUILDER_GO PM_PACKAGE PM_PACKAGE_FILE OTHER_INDEX; do
  variable="WERF_TEST_I1_$key"
  if [ -z "$(printenv "$variable")" ]; then
    printf "missing %s\n" "$variable" >&2
    exit 2
  fi
done
: "${WERF_TEST_K8S_DOCKER_REGISTRY:?registry required by the e2e suite}"
cd "$(git rev-parse --show-toplevel)"
WERF="$WERF_TEST_BINARY_PATH" test/e2e/sbom/_increment1/render.sh
export TASK_X_REMOTE_TASKFILES=1
exec task --yes test:e2e paths="./test/e2e/sbom" labelFilter="increment1" parallel=1
