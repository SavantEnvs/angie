#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own Perl suite (tests/*.t, nginx-tests style) against the NORMAL build
# objs/test/angie that mayhem/build.sh produced. The selection covers the code the fuzz
# targets reach: rewrite/script, variables, access log, map, SSI, metric, proxy, gRPC,
# PROXY protocol, mail (IMAP/POP3/SMTP) and the stream prereads (MQTT/RDP/TLS).
BIN="$SRC/objs/test/angie"
[ -x "$BIN" ] || { echo "test.sh: $BIN missing — mayhem/build.sh must build it" >&2; emit_ctrf prove 0 1 0; exit 1; }
TESTS="rewrite.t rewrite_unescape.t rewrite_set.t rewrite_if.t http_variables.t access_log.t
 map.t ssi.t ssi_if.t http_metric.t proxy.t grpc.t proxy_protocol.t proxy_protocol2.t
 mail_imap.t mail_pop3.t mail_smtp.t stream_mqtt_preread.t stream_rdp_preread.t
 stream_ssl_preread.t h2.t h2_headers.t"
sel=""
for t in $TESTS; do [ -f "tests/$t" ] && sel="$sel $t"; done
out=$(cd tests && TEST_ANGIE_BINARY="$BIN" prove -j"$MAYHEM_JOBS" $sel 2>&1)
echo "$out"
total=$(printf '%s\n' "$out" | sed -n 's/.*Tests=\([0-9]*\).*/\1/p' | tail -1)
failed=$(printf '%s\n' "$out" | sed -n 's/.*Failed \([0-9]*\)\/[0-9]* subtests.*/\1/p' | awk '{s+=$1} END {print s+0}')
skipped=$(printf '%s\n' "$out" | grep -c ' skipped: ' || true)
: "${total:=0}"
if ! printf '%s\n' "$out" | grep -q '^Result: PASS'; then
  [ "$failed" -gt 0 ] || failed=1
fi
[ "$total" -gt 0 ] || failed=$(( failed > 0 ? failed : 1 ))
passed=$(( total - failed )); [ "$passed" -ge 0 ] || passed=0
emit_ctrf prove "$passed" "$failed" "$skipped"
