#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
usage() { echo 'Usage: run.sh PROJECT_DIRECTORY [recon|scan|all] [RUN_DIRECTORY for scan]'; }
[[ $# -ge 1 && $# -le 3 ]] || { usage; exit 2; }
project=$(realpath -- "$1")
phase=${2:-all}
[[ "$phase" =~ ^(recon|scan|all)$ ]] || { usage; exit 2; }
for cmd in python3 flock timeout; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }; done
[[ -d "$project" ]] || exit 2
exec 9>"$project/.run.lock"
flock -n 9 || { echo 'Another run holds this project lock.' >&2; exit 2; }
export RPS=${RPS:-1} WORKERS=${WORKERS:-1} DEPTH=${DEPTH:-3}
export CRAWL_SECONDS=${CRAWL_SECONDS:-300} STAGE_SECONDS=${STAGE_SECONDS:-7200}
export PASSIVE=${PASSIVE:-0}
# Explicit profile controls the minimum interval; standalone defaults to bounty.
SCAN_PROFILE=${SCAN_PROFILE:-bounty}
[[ "$SCAN_PROFILE" == fast || "$SCAN_PROFILE" == bounty ]] || { echo 'Invalid SCAN_PROFILE' >&2; exit 2; }
export SCAN_PROFILE
SCAN_DELAY_MS=$(python3 -c 'import os, math, sys; low=0.1 if os.environ["SCAN_PROFILE"]=="fast" else 1; v=float(os.environ.get("SCAN_REQUEST_INTERVAL", str(low))); (math.isfinite(v) and low <= v <= 60) or sys.exit("Invalid request interval"); print(math.ceil(v*1000))') || exit 2
if ((SCAN_DELAY_MS < 1000)); then SCAN_CRAWL_DELAY=0; else SCAN_CRAWL_DELAY=$(((SCAN_DELAY_MS + 999) / 1000)); fi
RPS=$((1000 / SCAN_DELAY_MS))
((RPS >= 1)) || RPS=1
[[ "$WORKERS" == 1 ]] || { echo 'WORKERS must be 1.' >&2; exit 2; }
for name in RPS WORKERS DEPTH CRAWL_SECONDS STAGE_SECONDS; do
  [[ ${!name} =~ ^[1-9][0-9]*$ ]] || { echo "Invalid $name" >&2; exit 2; }
done
[[ "$PASSIVE" =~ ^[01]$ ]] || exit 2
if [[ "$phase" == scan ]]; then
  [[ $# == 3 ]] || { usage; exit 2; }
  run=$(realpath -- "$3")
  [[ -d "$run/input" && -f "$run/recon.complete" ]] || { echo 'Recon is missing or incomplete.' >&2; exit 2; }
  [[ ! -e "$run/scan.started" ]] || { echo 'Scan already started here; create a fresh recon run.' >&2; exit 2; }
else
  mkdir -p -- "$project/runs"
  run=$(mktemp -d "$project/runs/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
  mkdir -p "$run/input"
  cp -- "$project/origins.txt" "$run/input/origins.txt"
  for f in seeds.txt urls.txt exclude.txt; do
    if [[ -f "$project/$f" ]]; then cp -- "$project/$f" "$run/input/$f"; else : >"$run/input/$f"; fi
  done
fi
printf 'Run: %s\n' "$run"
trap 'rc=$?; if ((rc)); then printf "Failed (exit %s); inspect logs in %s\n" "$rc" "$run" >&2; fi' EXIT
python3 "$base/glue.py" prepare "$run"
scope=$(cat "$run/scope.regex")
if [[ -f "$project/single-scope.regex" ]]; then scope=$(cat "$project/single-scope.regex"); fi
exclude=$(cat "$run/exclude.regex")
if [[ "$phase" != scan ]]; then
  command -v katana >/dev/null || { echo 'Missing katana' >&2; exit 2; }
  katana -version >"$run/katana.version" 2>&1
  [[ $(cat "$run/katana.version") =~ 1\.8\.0([^0-9]|$) ]] || { echo 'This wrapper requires Katana 1.8.0.' >&2; exit 2; }
  : >"$run/passive.txt"
  : >"$run/gau.toml"
  printf '{}\n' >"$run/katana.yaml"
  if [[ "$PASSIVE" == 1 ]]; then
    command -v gau >/dev/null || { echo 'Missing gau' >&2; exit 2; }
    while IFS= read -r host; do
      timeout "$STAGE_SECONDS" gau "$host" --config "$run/gau.toml" --providers wayback,commoncrawl --threads 1 --timeout 15 --retries 1 \
        >>"$run/passive.txt" 2>>"$run/gau.log"
    done <"$run/hosts.txt"
  fi
  # Filter archive/supplied URLs BEFORE any active crawl, including seeds.
  cat "$run/seeds.txt" "$run/input/urls.txt" "$run/passive.txt" >"$run/pre-crawl.txt"
  python3 "$base/glue.py" filter "$run" "$run/pre-crawl.txt" "$run/crawl-input.txt"
  [[ -s "$run/crawl-input.txt" ]] || { echo 'No allowed seeds.' >&2; exit 2; }
  # Standard HTTP mode: no headless subresource requests outside crawler scope.
  timeout "$STAGE_SECONDS" katana -list "$run/crawl-input.txt" -config "$run/katana.yaml" -silent -duc \
    -jc -d "$DEPTH" -ct "${CRAWL_SECONDS}s" -c 1 -p 1 -rl "$RPS" -rd "$SCAN_CRAWL_DELAY" \
    -timeout 10 -retry 1 -dr -cs "$scope" -cos "$exclude" \
    >"$run/katana.txt" 2>"$run/katana.log"
  cat "$run/crawl-input.txt" "$run/katana.txt" >"$run/discovered.txt"
  python3 "$base/glue.py" filter "$run" "$run/discovered.txt" "$run/allowed.txt"
  python3 "$base/glue.py" split "$run"
  touch "$run/recon.complete"
fi
if [[ "$phase" == recon ]]; then
  echo 'Recon finished. Review reflected.txt, dom.txt, inputs.tsv and rejected.jsonl.'
  echo "Then: $0 '$project' scan '$run'"
  exit 0
fi
command -v dalfox >/dev/null || { echo 'Missing Dalfox 3.2.4' >&2; exit 2; }
dalfox --version >"$run/dalfox.version"
[[ $(cat "$run/dalfox.version") =~ 3\.2\.4([^0-9]|$) ]] || { echo 'This wrapper requires Dalfox 3.2.4; validate other versions before changing the pin.' >&2; exit 2; }
# Prevent user-level Dalfox config from silently enabling other scan modes.
printf '{}\n' >"$run/dalfox.config.json"
touch "$run/scan.started"
common=(--config "${XSS_SESSION_CONFIG:-$run/dalfox.config.json}" --no-color --include-url "$scope" --exclude-url "$exclude"
  --workers "$WORKERS" --max-concurrent-targets 1
  --rate-limit "$RPS" --delay "$SCAN_DELAY_MS" --timeout 10 --retries 0 --waf-bypass off --skip-waf-probe
  --insecure=false --dedup-urls exact --include-request --format json)
if [[ -n "${XSS_COOKIE_REQUEST:-}" ]]; then
  common+=(--cookie-from-raw "$XSS_COOKIE_REQUEST")
fi
if [[ -n "${AUTH_SUCCESS_REGEX:-}" ]]; then
  common+=(--session-check "$AUTH_SUCCESS_REGEX")
fi
if [[ -n "${AUTH_CHECK_URL:-}" ]]; then
  common+=(--session-check-url "$AUTH_CHECK_URL")
fi
status=0
for mode in reflected dom; do
  [[ -s "$run/$mode.txt" ]] || { printf '{"meta":{"incomplete":false,"target_summary":[]},"findings":[]}\n' >"$run/$mode.json"; continue; }
  if [[ "$mode" == reflected ]]; then
    engine=(--skip-mining-dict --skip-reflection-header --skip-reflection-cookie --skip-reflection-path --skip-ast-analysis)
  else
    # Independent JS source/sink analysis: no reflection prerequisite, no XSS injection loop.
    engine=(--skip-discovery --skip-mining --skip-xss-scanning --analyze-external-js)
  fi
  rc=0
  target_count=$(wc -l <"$run/$mode.txt")
  timeout "$STAGE_SECONDS" dalfox scan "$run/$mode.txt" -i file "${common[@]}" "${engine[@]}" \
    --max-targets-per-host "$target_count" -o "$run/$mode.json" >"$run/$mode.stdout.log" 2>"$run/$mode.stderr.log" || rc=$?
  printf '%s\n' "$rc" >"$run/$mode.exit"
  if ((rc > 1)); then status=3; fi
done
python3 "$base/glue.py" report "$run" || status=3
if ((status == 0)); then touch "$run/scan.complete"; else touch "$run/scan.incomplete"; fi
cat "$run/summary.txt"
exit "$status"
