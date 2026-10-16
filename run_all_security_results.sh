#!/usr/bin/env bash
set -uo pipefail

# Security-Labs unified validation/metrics runner.
# Safe default: offline tests/demos only. It does NOT launch live attacks or scan hosts.
# Usage:
#   bash run_all_results.sh
# Optional:
#   SECURITY_LABS_PYTHON=python3 bash run_all_results.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR"
if [[ ! -d "$ROOT/sigma-suricata-detection-rules" ]]; then
  if command -v git >/dev/null 2>&1; then
    ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$SCRIPT_DIR")"
  fi
fi

required_dirs=(
  sigma-suricata-detection-rules
  network-intrusion-detection-suricata
  realtime-threat-detection-elk
  enterprise-vulnerability-scanner
  secure-code-review
)
for d in "${required_dirs[@]}"; do
  if [[ ! -d "$ROOT/$d" ]]; then
    echo "ERROR: $ROOT does not look like the Security-Labs repository (missing $d)." >&2
    exit 1
  fi
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$ROOT/outputs/all-results/$STAMP"
SUMMARY="$ROOT/docs/RESULTS-LATEST.md"
mkdir -p "$RUN_DIR" "$(dirname "$SUMMARY")"

BASE_PY="${SECURITY_LABS_PYTHON:-python3}"
VENV="${SECURITY_LABS_RESULTS_VENV:-$HOME/.cache/security-labs-results-venv}"
PY="$VENV/bin/python"

pass=0
fail=0
skip=0

CV_DETECTION="NOT MEASURED"
CV_FP="NOT MEASURED"
CV_TIME="NOT MEASURED"
CV_CVES="NOT MEASURED"

md_escape() {
  printf '%s' "$1" | sed 's/|/\\|/g; s/[[:cntrl:]]/ /g'
}

row() {
  local project="$1" check="$2" result="$3" evidence="$4"
  printf '| %s | %s | %s | `%s` |\n' \
    "$(md_escape "$project")" "$(md_escape "$check")" "$(md_escape "$result")" "$(md_escape "$evidence")" >> "$SUMMARY"
}

status_line() {
  local label="$1" state="$2" detail="$3"
  printf '%-36s %-7s %s\n' "$label" "$state" "$detail"
}

run_logged() {
  # run_logged LABEL LOGFILE command...
  local label="$1" logfile="$2"
  shift 2
  mkdir -p "$(dirname "$logfile")"
  "$@" >"$logfile" 2>&1
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    status_line "$label" "PASS" "$logfile"
    pass=$((pass+1))
  else
    status_line "$label" "FAIL" "rc=$rc; $logfile"
    fail=$((fail+1))
  fi
  return $rc
}

unittest_count() {
  local f="$1"
  grep -Eo 'Ran [0-9]+ tests?' "$f" | tail -1 | grep -Eo '[0-9]+' || true
}

setup_python() {
  echo "[setup] Preparing reusable Python environment: $VENV"
  if ! command -v "$BASE_PY" >/dev/null 2>&1; then
    echo "ERROR: $BASE_PY not found." >&2
    return 1
  fi
  if [[ ! -x "$PY" ]]; then
    "$BASE_PY" -m venv "$VENV" || return 1
  fi

  # Install only what these three Python projects need. First run may use internet.
  "$PY" -m pip install --disable-pip-version-check -q \
    -r "$ROOT/sigma-suricata-detection-rules/requirements.txt" \
    -e "$ROOT/realtime-threat-detection-elk" \
    -e "$ROOT/enterprise-vulnerability-scanner" \
    >"$RUN_DIR/python-install.log" 2>&1 || return 1

  "$PY" - <<'PY' >/dev/null 2>&1
import yaml, flask, defusedxml, waitress, threatwatch, netsentry
PY
}

GIT_COMMIT="unknown"
if command -v git >/dev/null 2>&1; then
  GIT_COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

cat > "$SUMMARY" <<EOF_MD
# Security Labs — Latest Repeatable Results

- Run (UTC): $STAMP
- Repository commit: $GIT_COMMIT
- Host: $(uname -srmo 2>/dev/null || uname -a)
- Python requested: $BASE_PY
- Raw run directory: \`outputs/all-results/$STAMP/\`

> **Metric boundary:** synthetic/demo results are labeled as such. Live and owner-measured lab results are scoped laboratory evidence and should not be interpreted as production detection efficacy, confirmed exploitability, or organization-wide analyst productivity.

| Project | Check / metric | Result | Raw evidence |
| --- | --- | --- | --- |
EOF_MD

echo "============================================================"
echo " Security-Labs unified results"
echo " Root: $ROOT"
echo " Run : $STAMP"
echo "============================================================"

PY_READY=1
if setup_python; then
  status_line "Python environment" "PASS" "$PY"
  pass=$((pass+1))
else
  PY_READY=0
  status_line "Python environment" "FAIL" "$RUN_DIR/python-install.log"
  fail=$((fail+1))
fi

# ---------------------------------------------------------------------------
# 1) Sigma + Suricata detection rules
# ---------------------------------------------------------------------------
SIGMA="$ROOT/sigma-suricata-detection-rules"
echo
echo "[1/5] Sigma + Suricata detection rules"

if [[ $PY_READY -eq 1 ]]; then
  SIGMA_TEST_LOG="$RUN_DIR/sigma-unittest.log"
  (cd "$SIGMA" && "$PY" -m unittest discover -s tests -v) >"$SIGMA_TEST_LOG" 2>&1
  rc=$?
  n="$(unittest_count "$SIGMA_TEST_LOG")"
  if [[ $rc -eq 0 ]]; then
    status_line "Sigma unit tests" "PASS" "${n:-?} tests"
    row "Sigma/Suricata rules" "Unit tests" "${n:-?} tests passed" "outputs/all-results/$STAMP/sigma-unittest.log"
    pass=$((pass+1))
  else
    status_line "Sigma unit tests" "FAIL" "rc=$rc"
    row "Sigma/Suricata rules" "Unit tests" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/sigma-unittest.log"
    fail=$((fail+1))
  fi

  SIGMA_METRICS="$RUN_DIR/sigma-metrics.json"
  (cd "$SIGMA" && "$PY" tools/evaluate_sigma.py --output "$SIGMA_METRICS") >"$RUN_DIR/sigma-evaluator.log" 2>&1
  rc=$?
  if [[ $rc -eq 0 && -s "$SIGMA_METRICS" ]]; then
    readarray -t sm < <("$PY" - "$SIGMA_METRICS" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
b=x['baseline']; t=x['tuned']
att=t['TP']+t['FN']; ben=t['FP']+t['TN']
print(f"{t['TP']}/{att} attacks detected; recall={t['recall']}%")
print(f"FP={t['FP']}/{ben}; precision={t['precision']}%; FPR={t['fpr']}%")
r=x.get('false_positive_reduction_pct')
print("N/A" if r is None else f"{r}% (baseline FP {b['FP']} -> tuned FP {t['FP']})")
print(f"{x['rules']} rules / {x['events']} labeled synthetic events")
PY
)
    status_line "Sigma synthetic recall" "PASS" "${sm[0]}"
    status_line "Sigma synthetic FP tuning" "PASS" "${sm[2]}"
    CV_DETECTION="Synthetic Sigma fixture: ${sm[0]}"
    CV_FP="Synthetic Sigma fixture: ${sm[2]}"
    row "Sigma/Suricata rules" "Synthetic fixture detection" "${sm[0]}; ${sm[1]}" "outputs/all-results/$STAMP/sigma-metrics.json"
    row "Sigma/Suricata rules" "Synthetic FP reduction" "${sm[2]} — fixture-only" "outputs/all-results/$STAMP/sigma-metrics.json"
    pass=$((pass+1))
  else
    status_line "Sigma synthetic evaluator" "FAIL" "rc=$rc"
    row "Sigma/Suricata rules" "Synthetic evaluator" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/sigma-evaluator.log"
    fail=$((fail+1))
  fi
else
  row "Sigma/Suricata rules" "Python validation" "SKIPPED — Python environment unavailable" "outputs/all-results/$STAMP/python-install.log"
  skip=$((skip+1))
fi

# Existing actual Suricata replay evidence, if owner has already run it.
SURICATA_METRICS="$SIGMA/outputs/suricata_metrics.json"
if [[ -f "$SURICATA_METRICS" && $PY_READY -eq 1 ]]; then
  suri="$($PY - "$SURICATA_METRICS" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); m=x.get('metrics',{})
a=(m.get('TP') or 0)+(m.get('FN') or 0); b=(m.get('FP') or 0)+(m.get('TN') or 0)
print(f"actual offline replay: {m.get('TP')}/{a} attack cases detected; recall={m.get('recall')}%; FP={m.get('FP')}/{b}; FPR={m.get('fpr')}%")
PY
)"
  status_line "Suricata retained replay" "PASS" "$suri"
  CV_DETECTION="$suri"
  row "Sigma/Suricata rules" "Actual Suricata replay (retained)" "$suri" "sigma-suricata-detection-rules/outputs/suricata_metrics.json"
else
  status_line "Suricata actual replay" "SKIP" "no retained outputs/suricata_metrics.json"
  row "Sigma/Suricata rules" "Actual Suricata replay" "NOT MEASURED in this run" "sigma-suricata-detection-rules/docs/VALIDATION.md"
  skip=$((skip+1))
fi

# ---------------------------------------------------------------------------
# 2) Standalone Network IDS
# ---------------------------------------------------------------------------
NIDS="$ROOT/network-intrusion-detection-suricata"
echo
echo "[2/5] Standalone Network IDS"

NIDS_LOG="$RUN_DIR/network-ids-syntax.log"
(cd "$NIDS" && bash -n src/monitor_alerts.sh src/response.sh) >"$NIDS_LOG" 2>&1
rc=$?
if [[ $rc -eq 0 ]]; then
  status_line "NIDS shell syntax" "PASS" "2 scripts"
  row "Network IDS" "Shell syntax" "2 scripts passed bash -n" "outputs/all-results/$STAMP/network-ids-syntax.log"
  pass=$((pass+1))
else
  status_line "NIDS shell syntax" "FAIL" "rc=$rc"
  row "Network IDS" "Shell syntax" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/network-ids-syntax.log"
  fail=$((fail+1))
fi

NIDS_SIDS="$(grep -oE 'sid:[0-9]+' "$NIDS/rules/local.rules" | cut -d: -f2 | sort -nu | paste -sd, -)"
NIDS_SID_COUNT="$(grep -oE 'sid:[0-9]+' "$NIDS/rules/local.rules" | cut -d: -f2 | sort -nu | wc -l | tr -d ' ')"
status_line "NIDS rule inventory" "PASS" "$NIDS_SID_COUNT SIDs: $NIDS_SIDS"
row "Network IDS" "Rule inventory" "$NIDS_SID_COUNT custom SIDs: $NIDS_SIDS" "network-intrusion-detection-suricata/rules/local.rules"
pass=$((pass+1))

NIDS_EVE="$NIDS/outputs/live/eve.json"
NIDS_GT="$NIDS/outputs/live/ground_truth.csv"
NIDS_METRICS="$NIDS/outputs/live/live_metrics.json"
NIDS_EVALUATOR="$NIDS/tools/evaluate_live.py"

if [[ -f "$NIDS_EVE" && -f "$NIDS_GT" && -f "$NIDS_EVALUATOR" && $PY_READY -eq 1 ]]; then

  nids_live="$(
    "$PY" "$NIDS_EVALUATOR"       "$NIDS_EVE"       "$NIDS_GT"       "$NIDS_METRICS"
  )"
  rc=$?

  if [[ $rc -eq 0 ]]; then

    status_line "NIDS live detection rate" "PASS" "$nids_live"

    row       "Network IDS"       "Live VM-to-VM detection rate"       "$nids_live"       "network-intrusion-detection-suricata/outputs/live/live_metrics.json"

    CV_DETECTION="Live lab NIDS: $nids_live"

    pass=$((pass+1))

  else

    status_line       "NIDS live detection rate"       "FAIL"       "metric evaluator rc=$rc"

    row       "Network IDS"       "Live VM-to-VM detection rate"       "FAILED to evaluate retained live evidence"       "network-intrusion-detection-suricata/outputs/live/"

    fail=$((fail+1))

  fi

else

  status_line     "NIDS live detection rate"     "SKIP"     "no retained live EVE + ground truth"

  row     "Network IDS"     "Detection rate / FPR"     "NOT MEASURED — needs owner-run labeled sessions"     "network-intrusion-detection-suricata/docs/VALIDATION.md"

  skip=$((skip+1))

fi

# ---------------------------------------------------------------------------
# 3) ThreatWatch / ELK analyst tooling
# ---------------------------------------------------------------------------
TW="$ROOT/realtime-threat-detection-elk"
echo
echo "[3/5] ThreatWatch / ELK triage"

if [[ $PY_READY -eq 1 ]]; then
  TW_TEST_LOG="$RUN_DIR/threatwatch-unittest.log"
  (cd "$TW" && "$PY" -m unittest discover -s tests -v) >"$TW_TEST_LOG" 2>&1
  rc=$?
  n="$(unittest_count "$TW_TEST_LOG")"
  if [[ $rc -eq 0 ]]; then
    status_line "ThreatWatch unit tests" "PASS" "${n:-?} tests"
    row "ELK threat triage" "Unit tests" "${n:-?} tests passed" "outputs/all-results/$STAMP/threatwatch-unittest.log"
    pass=$((pass+1))
  else
    status_line "ThreatWatch unit tests" "FAIL" "rc=$rc"
    row "ELK threat triage" "Unit tests" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/threatwatch-unittest.log"
    fail=$((fail+1))
  fi

  TW_DATA="$RUN_DIR/threatwatch-demo-data"
  TW_REPORT="$RUN_DIR/threatwatch-demo-report"
  (cd "$TW" && "$PY" -m threatwatch demo --data-dir "$TW_DATA" --report-dir "$TW_REPORT") >"$RUN_DIR/threatwatch-demo.log" 2>&1
  rc=$?
  if [[ $rc -eq 0 && -f "$TW_REPORT/demo-incidents.json" ]]; then
    tw="$($PY - "$TW_REPORT/demo-incidents.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))['summary']
print(f"{s['alerts']} synthetic alerts -> {s['incidents']} incidents; P1={s['priorities'].get('P1',0)}; beacon leads={s['beacon_leads']}")
PY
)"
    status_line "ThreatWatch synthetic demo" "PASS" "$tw"
    row "ELK threat triage" "Synthetic offline demo" "$tw" "outputs/all-results/$STAMP/threatwatch-demo-report/demo-incidents.json"
    pass=$((pass+1))
  else
    status_line "ThreatWatch synthetic demo" "FAIL" "rc=$rc"
    row "ELK threat triage" "Synthetic offline demo" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/threatwatch-demo.log"
    fail=$((fail+1))
  fi

  # Owner lifecycle data: only use non-template CSVs.
  LIFECYCLE=""
  while IFS= read -r f; do
    LIFECYCLE="$f"; break
  done < <(find "$TW" -type f -name '*lifecycle*.csv' ! -path '*/docs/templates/*' ! -path '*/.venv/*' 2>/dev/null | sort)

  if [[ -n "$LIFECYCLE" ]]; then
    "$PY" - "$LIFECYCLE" >"$RUN_DIR/investigation-time.txt" <<'PY'
from pathlib import Path
import sys
from threatwatch.metrics import load_records,summarize,compare
p=Path(sys.argv[1]); s=summarize(load_records(p))
print('file:', p)
for k,v in s.items(): print(k, v)
keys=list(s)
if len(keys)==2:
    c=compare(s,keys[0],keys[1])
    print('comparison:', keys[0], '->', keys[1], c)
else:
    print('comparison: N/A (need exactly two comparable cohorts)')
PY
    rc=$?
    if [[ $rc -eq 0 ]]; then
      inv_short="$(tail -1 "$RUN_DIR/investigation-time.txt")"
      status_line "Investigation-time metrics" "PASS" "$inv_short"
      CV_TIME="$inv_short"
      row "ELK threat triage" "Investigation/triage time" "$inv_short" "outputs/all-results/$STAMP/investigation-time.txt"
      pass=$((pass+1))
    else
      status_line "Investigation-time metrics" "FAIL" "invalid lifecycle CSV"
      row "ELK threat triage" "Investigation/triage time" "FAILED — invalid lifecycle data" "outputs/all-results/$STAMP/investigation-time.txt"
      fail=$((fail+1))
    fi
  else
    status_line "Investigation-time metrics" "SKIP" "no owner lifecycle CSV"
    row "ELK threat triage" "Investigation/triage time improvement" "NOT MEASURED — add owner lifecycle CSV" "realtime-threat-detection-elk/docs/METRICS.md"
    skip=$((skip+1))
  fi
else
  row "ELK threat triage" "Python validation" "SKIPPED — Python environment unavailable" "outputs/all-results/$STAMP/python-install.log"
  skip=$((skip+1))
fi

# ---------------------------------------------------------------------------
# 4) NetSentry vulnerability scanner
# ---------------------------------------------------------------------------
NS="$ROOT/enterprise-vulnerability-scanner"
echo
echo "[4/5] NetSentry vulnerability scanner"

if [[ $PY_READY -eq 1 ]]; then
  NS_TEST_LOG="$RUN_DIR/netsentry-unittest.log"
  (cd "$NS" && "$PY" -m unittest discover -s tests -v) >"$NS_TEST_LOG" 2>&1
  rc=$?
  n="$(unittest_count "$NS_TEST_LOG")"
  if [[ $rc -eq 0 ]]; then
    status_line "NetSentry unit tests" "PASS" "${n:-?} tests"
    row "Vulnerability scanner" "Unit tests" "${n:-?} tests passed" "outputs/all-results/$STAMP/netsentry-unittest.log"
    pass=$((pass+1))
  else
    status_line "NetSentry unit tests" "FAIL" "rc=$rc"
    row "Vulnerability scanner" "Unit tests" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/netsentry-unittest.log"
    fail=$((fail+1))
  fi

  NS_DB="$RUN_DIR/netsentry-demo.sqlite3"
  NS_JSON="$RUN_DIR/netsentry-demo-report.json"
  (cd "$NS" && "$PY" -m netsentry demo --db "$NS_DB" && "$PY" -m netsentry export --db "$NS_DB" --output "$NS_JSON") >"$RUN_DIR/netsentry-demo.log" 2>&1
  rc=$?
  if [[ $rc -eq 0 && -s "$NS_JSON" ]]; then
    nsdemo="$($PY - "$NS_JSON" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); s=x['summary']
print(f"DEMO: {s['hosts']} hosts, {s['open_services']} services, {s['unique_cves']} unique synthetic CVE candidates, {s['cve_instances']} endpoint instances")
PY
)"
    status_line "NetSentry synthetic demo" "PASS" "$nsdemo"
    row "Vulnerability scanner" "Synthetic demo" "$nsdemo" "outputs/all-results/$STAMP/netsentry-demo-report.json"
    pass=$((pass+1))
  else
    status_line "NetSentry synthetic demo" "FAIL" "rc=$rc"
    row "Vulnerability scanner" "Synthetic demo" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/netsentry-demo.log"
    fail=$((fail+1))
  fi

  # Prefer latest owner non-demo NetSentry JSON report if one exists.
  LIVE_REPORT="$($PY - "$NS" "$RUN_DIR" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); rundir=Path(sys.argv[2]).resolve(); found=[]
for p in root.rglob('*.json'):
    try:
        if rundir in p.resolve().parents: continue
        x=json.loads(p.read_text(encoding='utf-8'))
    except Exception: continue
    if isinstance(x,dict) and x.get('demo') is False and isinstance(x.get('summary'),dict):
        found.append((p.stat().st_mtime,p))
print(found[-1][1] if found else '')
PY
)"
  if [[ -n "$LIVE_REPORT" && -f "$LIVE_REPORT" ]]; then

    live_cve="$($PY - "$LIVE_REPORT" <<'PYMETRIC'
import json
import sys

path = sys.argv[1]

with open(path, encoding="utf-8") as f:
    report = json.load(f)

summary = report.get("summary", {})
coverage = report.get("coverage", {})

unique_cves = summary.get("unique_cves", 0)
instances = summary.get("cve_instances", 0)
checked = coverage.get("checked_services", "?")
eligible = coverage.get("eligible_services", "?")
source = report.get("source", "unknown")
demo = report.get("demo", True)

if source != "Live Nmap":
    raise SystemExit(f"unexpected source: {source}")

if demo:
    raise SystemExit("report is marked as demo")

print(
    f"{unique_cves} unique CVE candidates; "
    f"{instances} candidate instances; "
    f"checked {checked}/{eligible} eligible services"
)
PYMETRIC
)"
    rc=$?

    if [[ $rc -eq 0 ]]; then

      status_line \
        "NetSentry live CVE candidates" \
        "PASS" \
        "$live_cve"

      CV_CVES="$live_cve"

      row \
        "Vulnerability scanner" \
        "Retained live Nmap/NVD assessment" \
        "$live_cve — candidates, not confirmed exploitable vulnerabilities" \
        "${LIVE_REPORT#$ROOT/}"

      pass=$((pass+1))

    else

      status_line \
        "NetSentry live CVE candidates" \
        "FAIL" \
        "retained report validation failed"

      row \
        "Vulnerability scanner" \
        "Retained live Nmap/NVD assessment" \
        "FAILED to validate retained live report" \
        "${LIVE_REPORT#$ROOT/}"

      fail=$((fail+1))

    fi

  else

    status_line \
      "NetSentry live CVE candidates" \
      "SKIP" \
      "no owner non-demo report"

    row \
      "Vulnerability scanner" \
      "Live CVE candidate count" \
      "NOT MEASURED — no retained non-demo assessment" \
      "enterprise-vulnerability-scanner/docs/VALIDATION.md"

    skip=$((skip+1))

  fi

  # Count CVE IDs embedded in retained XML (e.g. Nmap vulners output), if present.
  XML_CVE_FILE=""
  XML_CVE_COUNT=0
  while IFS= read -r x; do
    c="$(grep -oE 'CVE-[0-9]{4}-[0-9]+' "$x" 2>/dev/null | sort -u | wc -l | tr -d ' ')"
    if [[ ${c:-0} -gt $XML_CVE_COUNT ]]; then XML_CVE_COUNT=$c; XML_CVE_FILE="$x"; fi
  done < <(find "$NS/outputs" -type f -name '*.xml' 2>/dev/null | sort)
  if [[ $XML_CVE_COUNT -gt 0 ]]; then
    status_line "Nmap XML CVE IDs" "PASS" "$XML_CVE_COUNT unique potential CVE IDs"
    CV_CVES="$XML_CVE_COUNT unique potential CVE IDs from retained Nmap XML"
    row "Vulnerability scanner" "Nmap XML CVE IDs" "$XML_CVE_COUNT unique potential CVE IDs — version-match candidates" "${XML_CVE_FILE#$ROOT/}"
  fi
else
  row "Vulnerability scanner" "Python validation" "SKIPPED — Python environment unavailable" "outputs/all-results/$STAMP/python-install.log"
  skip=$((skip+1))
fi

# ---------------------------------------------------------------------------
# 5) Secure code review (Rust)
# ---------------------------------------------------------------------------
SCR="$ROOT/secure-code-review"
echo
echo "[5/5] Secure code review"

if command -v cargo >/dev/null 2>&1; then
  cargo --version >"$RUN_DIR/cargo-version.txt" 2>&1

  for app in vulnerable-app secure-app; do
    log="$RUN_DIR/cargo-check-$app.log"
    (cd "$SCR" && cargo check --locked --manifest-path "src/$app/Cargo.toml") >"$log" 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
      status_line "cargo check $app" "PASS" "locked build check"
      row "Secure code review" "cargo check $app" "PASS" "outputs/all-results/$STAMP/cargo-check-$app.log"
      pass=$((pass+1))
    else
      status_line "cargo check $app" "FAIL" "rc=$rc"
      row "Secure code review" "cargo check $app" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/cargo-check-$app.log"
      fail=$((fail+1))
    fi
  done

  if cargo clippy --version >/dev/null 2>&1; then
    for app in vulnerable-app secure-app; do
      log="$RUN_DIR/cargo-clippy-$app.log"
      (cd "$SCR" && cargo clippy --locked --manifest-path "src/$app/Cargo.toml") >"$log" 2>&1
      rc=$?
      if [[ $rc -eq 0 ]]; then
        status_line "cargo clippy $app" "PASS" ""
        row "Secure code review" "cargo clippy $app" "PASS" "outputs/all-results/$STAMP/cargo-clippy-$app.log"
        pass=$((pass+1))
      else
        status_line "cargo clippy $app" "FAIL" "rc=$rc"
        row "Secure code review" "cargo clippy $app" "FAILED (rc=$rc)" "outputs/all-results/$STAMP/cargo-clippy-$app.log"
        fail=$((fail+1))
      fi
    done
  else
    status_line "cargo clippy" "SKIP" "component unavailable"
    row "Secure code review" "Clippy" "SKIPPED — component unavailable" "secure-code-review/docs/VALIDATION.md"
    skip=$((skip+1))
  fi
else
  status_line "Rust runtime validation" "SKIP" "cargo not installed"
  row "Secure code review" "Build/lint runtime validation" "NOT RUN — cargo unavailable" "secure-code-review/docs/VALIDATION.md"
  skip=$((skip+1))
fi

# Source-supported checks (do not claim runtime exploitation/remediation).
VULN_SQL="$(grep -cE 'format!.*SELECT|format!.*WHERE|format!.*username' "$SCR/src/vulnerable-app/src/main.rs" 2>/dev/null || true)"
SEC_PARAMS="$(grep -cE 'params!|query_row\(' "$SCR/src/secure-app/src/main.rs" 2>/dev/null || true)"
status_line "Secure-code source comparison" "INFO" "vulnerable SQL format hits=${VULN_SQL:-0}; secure parameter/query hits=${SEC_PARAMS:-0}"
row "Secure code review" "Source comparison" "Static source comparison retained; runtime endpoint regression still separate" "secure-code-review/docs/security-review.md"

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
cat >> "$SUMMARY" <<EOF_MD

## Run totals

- PASS checks: $pass
- FAIL checks: $fail
- SKIP / not-yet-measured checks: $skip

## Metrics snapshot

| Metric | Current result |
| --- | --- |
| Detection rate | $CV_DETECTION |
| False-positive reduction | $CV_FP |
| Investigation-time improvement | $CV_TIME |
| Potential/retained CVE count | $CV_CVES |

## CV-safe interpretation

Use only measurements above that match the evidence type. In particular:

- Sigma percentages from the bundled 38-event corpus are **synthetic fixture metrics**, not operational held-out performance.
- A CVE ID from Nmap/NVD is a **candidate/potential CVE** until applicability is confirmed.
- Investigation-time comparison is supported by the retained 5-case before-playbook and 5-case with-playbook lifecycle records. Because this small replay produced second-scale timings, the observed median-close change should be treated as a lab workflow measurement, not a general analyst-productivity claim.
- Standalone IDS detection rate is supported by the retained labeled live VM-to-VM session (4/4 controlled attack cases detected). Live false-positive rate is not yet measured because the retained live cohort contains no benign cases.

Raw outputs are kept under the ignored run directory shown at the top. Review and sanitize small evidence before committing it to \`docs/\` or \`sample-data/\`.
EOF_MD

echo
echo "============================================================"
echo " FINAL"
echo " PASS=$pass  FAIL=$fail  SKIP=$skip"
echo " Summary: $SUMMARY"
echo " Raw    : $RUN_DIR"
echo "============================================================"
echo
cat "$SUMMARY"

# A failing validation makes the script non-zero; unmeasured/skipped items do not.
if [[ $fail -gt 0 ]]; then
  exit 1
fi
exit 0
