#!/usr/bin/env bash

set -euo pipefail
set +m

profile_dir="${RUNNER_TEMP:?RUNNER_TEMP must be set}/test-profile/${GITHUB_JOB:-local}"
mkdir -p "$profile_dir"
sampler_pids=()
test_pid=""
tee_pid=""
test_process_group=false

snapshot() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  for source in /proc/stat /proc/meminfo /proc/diskstats /proc/net/dev /proc/pressure/cpu /proc/pressure/io /proc/pressure/memory /proc/self/cgroup; do
    if [[ -r "$source" ]]; then
      printf '\n%s\n' "$source"
      cat "$source"
    fi
  done
  df -h "$PWD" "$profile_dir"
}

finish() {
  local exit_code=$?
  trap - EXIT
  trap '' INT TERM
  if [[ -n "$test_pid" ]]; then
    if "$test_process_group"; then
      kill -TERM -- "-$test_pid" 2>/dev/null || kill -TERM "$test_pid" 2>/dev/null || true
      sleep 5
      kill -KILL -- "-$test_pid" 2>/dev/null || true
    else
      kill -TERM "$test_pid" 2>/dev/null || true
    fi
    wait "$test_pid" 2>/dev/null || true
  fi
  exec 3>&-
  if [[ -n "$tee_pid" ]]; then
    kill "$tee_pid" 2>/dev/null || true
    wait "$tee_pid" 2>/dev/null || true
  fi
  for sampler_pid in "${sampler_pids[@]}"; do
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
  done
  snapshot > "$profile_dir/host-after.txt" 2>&1 || true
  printf '%s\n' "$exit_code" > "$profile_dir/exit-code.txt" || true
  exit "$exit_code"
}

trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

{
  printf 'started_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'checkout_sha=%s\n' "$(git rev-parse HEAD)"
  printf 'event_sha=%s\n' "${GITHUB_SHA:-}"
  printf 'run_id=%s\nrun_attempt=%s\njob=%s\nrunner=%s\n' "${GITHUB_RUN_ID:-}" "${GITHUB_RUN_ATTEMPT:-}" "${GITHUB_JOB:-local}" "${RUNNER_NAME:-}"
  printf 'gomaxprocs=%s\ngoflags=%s\n' "${GOMAXPROCS:-}" "${GOFLAGS:-}"
  uname -a
  if command -v lscpu >/dev/null; then lscpu; fi
  if command -v ginkgo >/dev/null; then ginkgo version; fi
} > "$profile_dir/metadata.txt" 2>&1
snapshot > "$profile_dir/host-before.txt" 2>&1 || true

start_sampler() {
  local name=$1
  shift
  if command -v "$1" >/dev/null; then
    "$@" > "$profile_dir/$name.txt" 2>&1 &
    sampler_pids+=("$!")
  else
    printf 'unavailable: %s\n' "$1" > "$profile_dir/$name.txt"
    printf 'WARNING: optional profiler tool %s is unavailable\n' "$1" >&2
  fi
}

start_sampler vmstat vmstat -w -t 10
start_sampler diskstats vmstat -d -t 10
start_sampler iostat iostat -x -z -t 10
start_sampler pidstat pidstat -h -d -r -u -p ALL 10

timing_command=()
if [[ "$(uname -s)" == Linux ]]; then
  command -v setsid >/dev/null
  timing_command=(setsid)
  test_process_group=true
  if [[ -x /usr/bin/time ]]; then
    timing_command+=(/usr/bin/time -v -o "$profile_dir/command-time.txt")
  fi
fi

exec 3> >(tee "$profile_dir/test.log")
tee_pid=$!
"${timing_command[@]}" "$@" --json-report=report.json --keep-separate-reports --output-dir="$profile_dir" --show-node-events -v >&3 2>&1 &
test_pid=$!
set +e
wait "$test_pid"
test_exit_code=$?
test_pid=""
exec 3>&-
wait "$tee_pid"
tee_exit_code=$?
tee_pid=""
set -e
if [[ "$tee_exit_code" != 0 ]]; then
  printf 'WARNING: could not save complete test output\n' >&2
fi
exit "$test_exit_code"