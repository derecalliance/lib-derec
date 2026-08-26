#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Runs the on-device React Native smoke app on an iOS simulator and an Android
# emulator, and exits non-zero unless both report `DEREC_SMOKE_RESULT: PASS`.
#
# Absence of the sentinel is a failure, not a skip: a build that never launches,
# a JSI host object that never installs, and a scenario that hangs all look the
# same from outside, and all three must fail the run.

set -euo pipefail

# `${BASH_SOURCE[0]}` rather than `$0`, so the paths are still right when this
# file is sourced to reuse `run_ios` / `run_android` on their own — under
# `bash -c 'source ...'`, `$0` is the shell, and every path below would resolve
# outside the repository.
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$APP_DIR/../.." && pwd)"
LOG_DIR="$ROOT_DIR/target"
METRO_LOG="$LOG_DIR/rn-smoke-metro.log"
RESULT_LOG="$LOG_DIR/rn-smoke-result.log"
METRO_PORT="${DEREC_SMOKE_METRO_PORT:-8081}"
REPORT_PORT="${DEREC_SMOKE_REPORT_PORT:-8099}"
PASS_SENTINEL="DEREC_SMOKE_RESULT: PASS"
FAIL_SENTINEL="DEREC_SMOKE_RESULT: FAIL"

if [[ ! -d "$APP_DIR" ]]; then
  echo "Smoke app not found at $APP_DIR" >&2
  exit 1
fi

# Generous enough for a cold native build plus the full scenario sweep. The
# teardown scenarios deliberately park a worker for up to the binding's 30 s
# store timeout, so a tight budget would report a hang that is not one.
DEADLINE_SECS="${DEREC_SMOKE_TIMEOUT_SECS:-300}"

# Pinning a device name rots: the installed Xcode ships whichever simulators it
# ships, and a name that is not present makes `run-ios` fail in a way that reads
# like a build error. Default to the first available iPhone instead.
default_ios_simulator() {
  xcrun simctl list devices available 2>/dev/null \
    | sed -n 's/^ *\(iPhone [^(]*\) (.*/\1/p' \
    | sed 's/ *$//' \
    | head -1
}
IOS_SIMULATOR="${DEREC_SMOKE_IOS_SIMULATOR:-$(default_ios_simulator)}"

mkdir -p "$LOG_DIR"

METRO_PID=""
COLLECTOR_PID=""

# Collects the result the app POSTs.
#
# React Native routes `console.log` to the debugger rather than to Metro's
# stdout, so a run can pass or fail with nothing reaching any log this script
# can read. An HTTP POST is observable from the host, and identically on both
# platforms.
start_collector() {
  stop_collector
  : > "$RESULT_LOG"
  node -e '
    const fs = require("fs");
    const [file, port] = process.argv.slice(1);
    require("http").createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        fs.appendFileSync(file, body + "\n");
        res.end("ok");
      });
    }).listen(Number(port));
  ' "$RESULT_LOG" "$REPORT_PORT" &
  COLLECTOR_PID=$!
}

stop_collector() {
  if [[ -n "$COLLECTOR_PID" ]] && kill -0 "$COLLECTOR_PID" 2>/dev/null; then
    kill "$COLLECTOR_PID" 2>/dev/null || true
    wait "$COLLECTOR_PID" 2>/dev/null || true
  fi
  COLLECTOR_PID=""
}

# Metro is started here rather than left to `run-ios` / `run-android`, which
# spawn it as a child and take it down with them — killing the packager the
# moment the launch command returns.
start_metro() {
  stop_metro
  : > "$METRO_LOG"
  ( cd "$APP_DIR" && npx react-native start --port "$METRO_PORT" --reset-cache ) \
    >> "$METRO_LOG" 2>&1 &
  METRO_PID=$!

  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if curl -s "http://localhost:${METRO_PORT}/status" 2>/dev/null \
         | grep -q "packager-status:running"; then
      echo "Metro ready on port ${METRO_PORT}"
      return 0
    fi
    if ! kill -0 "$METRO_PID" 2>/dev/null; then
      echo "Metro exited during startup; see $METRO_LOG" >&2
      return 1
    fi
    sleep 2
  done
  echo "Metro did not become ready within 120s; see $METRO_LOG" >&2
  return 1
}

stop_metro() {
  if [[ -n "$METRO_PID" ]] && kill -0 "$METRO_PID" 2>/dev/null; then
    kill "$METRO_PID" 2>/dev/null || true
    wait "$METRO_PID" 2>/dev/null || true
  fi
  METRO_PID=""
  # `run-ios` may have left its own packager behind on a previous run.
  local stray
  stray="$(lsof -ti:"$METRO_PORT" 2>/dev/null || true)"
  if [[ -n "$stray" ]]; then
    kill $stray 2>/dev/null || true
  fi
}

cleanup() {
  stop_metro
  stop_collector
}
trap cleanup EXIT

# Waits for the app to report.
#
# The match is scoped to `$2`, the reporting platform, because both platforms
# write to the same collector log: an unscoped match let the second platform
# read the first one's result and pass without ever having run.
await_sentinel() {
  local label="$1"
  local platform="$2"
  local pass="$PASS_SENTINEL [$platform]"
  local fail="$FAIL_SENTINEL [$platform]"
  local deadline=$((SECONDS + DEADLINE_SECS))
  while (( SECONDS < deadline )); do
    if grep -qsF "$pass" "$RESULT_LOG" "$METRO_LOG"; then
      echo "$label reported PASS"
      return 0
    fi
    if grep -qsF "$fail" "$RESULT_LOG" "$METRO_LOG"; then
      grep -hsF "$fail" "$RESULT_LOG" "$METRO_LOG" >&2
      return 1
    fi
    sleep 5
  done
  echo "$label produced no result within ${DEADLINE_SECS}s; see $RESULT_LOG and $METRO_LOG" >&2
  return 1
}

run_ios() {
  if [[ -z "$IOS_SIMULATOR" ]]; then
    echo "No iOS simulator available; install one via Xcode or set DEREC_SMOKE_IOS_SIMULATOR." >&2
    return 1
  fi
  echo "── iOS simulator (${IOS_SIMULATOR}) ────────────────────────"
  local build_log="$LOG_DIR/rn-smoke-ios.log"

  # `--no-packager`: Metro is already running, and a second one on the same
  # port would leave the app connected to whichever won the race.
  if ! ( cd "$APP_DIR" && npx react-native run-ios \
           --simulator "$IOS_SIMULATOR" --no-packager ) > "$build_log" 2>&1; then
    echo "iOS build/launch failed; see $build_log" >&2
    # xcodebuild echoes its whole environment on failure, every line prefixed
    # `error`, so the compiler diagnostics have to be picked out of it.
    grep -E "^error [a-z]" "$build_log" | grep -vE "^error export" | head -20 >&2 || true
    return 1
  fi
  await_sentinel "iOS" "ios"
}

run_android() {
  echo "── Android emulator ────────────────────────────────────────"
  local build_log="$LOG_DIR/rn-smoke-android.log"

  if ! adb get-state >/dev/null 2>&1; then
    echo "No Android device or emulator attached; start one and retry." >&2
    return 1
  fi

  if ! ( cd "$APP_DIR" && npx react-native run-android --no-packager ) \
         > "$build_log" 2>&1; then
    echo "Android build/launch failed; see $build_log" >&2
    grep -iE "error:|FAILURE:|Caused by" "$build_log" | head -20 >&2 || true
    return 1
  fi
  await_sentinel "Android" "android"
}

main() {
  local status=0
  start_collector
  start_metro || return 1

  run_ios || { echo "iOS smoke test FAILED" >&2; status=1; }
  run_android || { echo "Android smoke test FAILED" >&2; status=1; }

  if (( status == 0 )); then
    echo "Both platforms reported $PASS_SENTINEL"
  fi
  return $status
}

# Guards direct execution so this file can also be `source`d — to reuse
# `run_ios` or `run_android` alone, or to check a helper — without launching a
# simulator as a side effect.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
