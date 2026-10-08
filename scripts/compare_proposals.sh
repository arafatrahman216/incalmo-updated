#!/usr/bin/env bash
# Compare baseline vs P1 vs P2 vs both over N trials each, and report per-config
# AVERAGES (plus the raw per-run rows).
#
# For every (trial, config) it: resets the docker target to a clean state, waits for
# the attacker foothold agent to check in, patches config/config.json (name + the two
# feature flags), runs the full LLM attack (main.py) inside the attacker container,
# then collects that run's statistics/*.json. Trials are INTERLEAVED (round 1 runs
# every config once, then round 2, ...) so time/API drift spreads evenly, not onto
# one config. At the end it prints a per-run table and a per-config averaged table.
#
# Requirements: .env at repo root has GOOGLE_API_KEY; docker compose available.
# Usage:  cd <repo root> && ./scripts/compare_proposals.sh [TRIALS]      (default 1)
#         TRIALS=5 ./scripts/compare_proposals.sh
set -euo pipefail

# --- config ------------------------------------------------------------------
TRIALS="${1:-${TRIALS:-1}}"   # number of runs per config
# Pin Gemini temperature for reproducibility (0 = deterministic-ish). Export so the
# registry inside the container reads it. Override with LLM_TEMPERATURE=... if wanted.
export LLM_TEMPERATURE="${LLM_TEMPERATURE:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
COMPOSE="docker/docker-compose.yml"
CONFIG="config/config.json"
C2="http://127.0.0.1:8888"
WEBSERVER="http://127.0.0.1:8080"   # Struts victim; used as the target-ready probe
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
# RESUME: to continue an interrupted sweep, re-run with RESUME pointing at its dir,
# e.g.  RESUME=output/compare_2026-10-02_18-52-01 ./scripts/compare_proposals.sh 2
# Already-completed runs are skipped; new ones append to the same index.tsv. Leave
# RESUME unset for a fresh sweep.
LOGDIR="${RESUME:-output/compare_${STAMP}}"
mkdir -p "$LOGDIR"

# Configs:  label  p1_goal_manager  p2_location_aware  optimizations(#1/#4/#6/#7/#8)
CONFIGS=(
  "baseline false false false"
  "p1       true  false false"
  "p2       false true  false"
  "both     true  true  false"
  "optboth  true  true  true"
)

# --- restore config.json on exit --------------------------------------------
cp "$CONFIG" "$LOGDIR/config.json.orig"
restore_config() { cp "$LOGDIR/config.json.orig" "$CONFIG"; }
trap restore_config EXIT

# --- helpers -----------------------------------------------------------------
log() { echo -e "\n=== [$(date +%H:%M:%S)] $* ==="; }

patch_config() {  # name p1 p2 opt  ->  sets name + flags, leaves everything else intact
  python3 - "$CONFIG" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
path, name = sys.argv[1], sys.argv[2]
p1, p2, opt = (sys.argv[3]=="true"), (sys.argv[4]=="true"), (sys.argv[5]=="true")
cfg = json.load(open(path))
cfg["name"] = name
f = cfg.setdefault("features", {})
f["p1_goal_manager"]   = p1
f["p2_location_aware"] = p2
# INFRA FIX #1: C2 pivot relay ON for EVERY config — it fixes the broken testbed
# (segmented DB couldn't reach the C2), making exfiltration possible for all, so the
# comparison isolates the P1/P2/opt effects rather than a shared dead end.
f["c2_pivot_relay"] = True
# Optimization sub-flags (#1/#4/#6/#7/#8) + the P3 retry-guard: on only for the
# optimized config. Always written explicitly so each run's config is unambiguous.
f["p2_digest_delta"]          = opt      # #1
f["p1_goal_backoff"]          = opt      # #4
f["p1_finish_when_infeasible"]= opt      # #6
f["p2_guided_scan"]           = opt      # #7
f["p1_prescriptive_veto"]     = opt      # #8/#5
f["p3_lateral_verify"]        = opt      # P3 retry-guard
json.dump(cfg, open(path, "w"), indent=4)
print(f"  config -> name={name} p1={p1} p2={p2} optimizations={opt} relay=on")
PY
}

wait_for_target() {  # poll /health then /agents until a foothold agent checks in
  local tries=0 max=60   # 60 * 3s = 3 min
  until curl -sf "$C2/health" >/dev/null 2>&1; do
    tries=$((tries+1)); [ "$tries" -ge "$max" ] && { echo "C2 /health never came up"; return 1; }
    sleep 3
  done
  tries=0
  until [ "$(curl -sf "$C2/agents" 2>/dev/null | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)" -ge 1 ]; do
    tries=$((tries+1)); [ "$tries" -ge "$max" ] && { echo "no foothold agent checked in"; return 1; }
    sleep 3
  done
  echo "  target ready, foothold agent checked in"
}

wait_for_webserver() {  # the Struts victim must be serving, else the attacker's
  # initial scan finds nothing and the run comes up degenerate (foothold only).
  local tries=0 max=60   # 60 * 3s = 3 min
  # curl without -f returns 0 on ANY HTTP response (even 404) => app is up.
  until curl -s -o /dev/null --max-time 3 "$WEBSERVER" 2>/dev/null; do
    tries=$((tries+1)); [ "$tries" -ge "$max" ] && { echo "  webserver (:8080) not serving"; return 1; }
    sleep 3
  done
  echo "  webserver is serving on :8080 (target scannable)"
}

reset_stack() {
  docker compose -f "$COMPOSE" down >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE" up -d   # let any build/startup error show
  wait_for_target
  wait_for_webserver   # readiness gate: don't launch against an unready target
}

# --- run the sweep (interleaved: trial outer, config inner) -------------------
log "Running $TRIALS trial(s) per config  (${#CONFIGS[@]} configs => $(( TRIALS * ${#CONFIGS[@]} )) full runs)  [LLM_TEMPERATURE=$LLM_TEMPERATURE]"
for trial in $(seq 1 "$TRIALS"); do
  for entry in "${CONFIGS[@]}"; do
    read -r label p1 p2 opt <<<"$entry"
    runname="${label}_t${trial}"

    # RESUME: skip a run already completed in this LOGDIR (marker written below).
    if [ -f "$LOGDIR/.done_${runname}" ]; then
      log "TRIAL $trial/$TRIALS  CONFIG: $label — already done, skipping (resume)"
      continue
    fi

    log "TRIAL $trial/$TRIALS  CONFIG: $label"
    patch_config "$runname" "$p1" "$p2" "$opt"

    log "$runname: resetting target to clean state"
    reset_stack

    log "$runname: launching full attack (minutes; 75-min hard cap)"
    docker compose -f "$COMPOSE" exec -T -e "LLM_TEMPERATURE=$LLM_TEMPERATURE" attacker \
      bash -lc 'cd /incalmo && uv run main.py' \
      2>&1 | tee "$LOGDIR/${runname}.run.log" || echo "  (main.py exited non-zero for $runname — continuing)"

    newest="$(ls -t statistics/${runname}_*.json 2>/dev/null | head -1 || true)"
    if [ -n "$newest" ]; then
      echo "  stats: $newest"
      printf '%s\t%s\n' "$label" "$newest" >> "$LOGDIR/index.tsv"
      touch "$LOGDIR/.done_${runname}"   # mark complete so RESUME can skip it
    else
      echo "  WARNING: no stats json produced for $runname"
    fi
  done
done

docker compose -f "$COMPOSE" down >/dev/null 2>&1 || true

# --- comparison: per-run rows + per-config averages --------------------------
log "COMPARISON  (avg over $TRIALS trial(s) per config)"
python3 - "$LOGDIR" "$TRIALS" "$LOGDIR/index.tsv" <<'PY'
import json, sys, statistics as st
from collections import OrderedDict, defaultdict

logdir, trials, index = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with open(index) as fh:
    pairs = [ln.split("\t", 1) for ln in fh.read().splitlines() if "\t" in ln]
order = ["baseline", "p1", "p2", "both", "optboth"]

def hosts_disc(r): return r["progress"].get("hosts_discovered", 0)
def is_valid(r):   return hosts_disc(r) >= 2   # <2 => foothold-only degenerate run

# numeric metrics to average
NUM = [
    ("files_exfil",    lambda r: r["progress"]["critical_files_exfiltrated"]),
    ("files_found",    lambda r: r["progress"]["critical_files_discovered"]),
    ("hosts_inf",      lambda r: r["progress"]["hosts_infected"]),
    ("hosts_root",     lambda r: r["progress"]["hosts_root"]),
    ("creds_found",    lambda r: r["progress"]["credentials_found"]),
    ("creds_util",     lambda r: r["progress"]["credentials_utilized"]),
    ("steps",          lambda r: r["execution"].get("steps") or 0),
    ("ll_ok",          lambda r: r["execution"].get("low_level_ok") or 0),
    ("ll_fail",        lambda r: r["execution"].get("low_level_fail") or 0),
    ("tokens",         lambda r: r.get("llm", {}).get("total_tokens") or 0),
    ("min",            lambda r: r.get("llm", {}).get("wall_clock_min") or 0),
]
def exfil_done(r): return bool(r["progress"]["exfiltration_complete"])
def term(r):       return r.get("termination_reason", "-")

by_cfg = defaultdict(list)
for label, path in pairs:
    by_cfg[label].append(json.load(open(path)))

def avg(xs): return sum(xs) / len(xs) if xs else 0.0

# ---- per-run table (transparency) ----
log_order = [c for c in order if c in by_cfg] + [c for c in by_cfg if c not in order]
runhdr = ["config", "trial", "valid", "term", "exfil", "disc", "files_exfil", "hosts_inf",
          "hosts_root", "creds_f/u", "steps", "ll_ok/fail", "tokens", "min"]
runrows = []
for cfg in log_order:
    for i, r in enumerate(by_cfg[cfg], 1):
        runrows.append([
            cfg, str(i), "Y" if is_valid(r) else "NO", term(r), "Y" if exfil_done(r) else "-",
            str(hosts_disc(r)),
            str(r["progress"]["critical_files_exfiltrated"]),
            str(r["progress"]["hosts_infected"]), str(r["progress"]["hosts_root"]),
            f'{r["progress"]["credentials_found"]}/{r["progress"]["credentials_utilized"]}',
            str(r["execution"].get("steps")),
            f'{r["execution"].get("low_level_ok","-")}/{r["execution"].get("low_level_fail","-")}',
            str(r.get("llm",{}).get("total_tokens","-")), str(r.get("llm",{}).get("wall_clock_min","-")),
        ])

def render(headers, rows):
    w = [max(len(headers[i]), *(len(r[i]) for r in rows)) if rows else len(headers[i])
         for i in range(len(headers))]
    line = lambda v: " | ".join(v[i].ljust(w[i]) for i in range(len(v)))
    out = [line(headers), "-+-".join("-"*x for x in w)]
    out += [line(r) for r in rows]
    return "\n".join(out)

print("\n--- per-run ---")
print(render(runhdr, runrows))

# ---- averaged table (VALID runs only; degenerate foothold-only runs excluded) ----
avghdr = ["config", "n_valid/tot", "exfil_rate"] + [name for name, _ in NUM]
avgrows = []
summary = OrderedDict()
for cfg in log_order:
    allrs = by_cfg[cfg]
    rs = [r for r in allrs if is_valid(r)]   # exclude degenerate runs from averages
    n, tot = len(rs), len(allrs)
    means = {name: avg([fn(r) for r in rs]) for name, fn in NUM}
    exfil_rate = f'{sum(exfil_done(r) for r in rs)}/{n}' if n else f'0/0'
    def cell(name):
        v = means[name]
        return f"{v:.0f}" if name in ("tokens",) else (f"{v:.2f}" if name in ("min","files_exfil","files_found","creds_found","creds_util","hosts_root") else f"{v:.1f}")
    avgrows.append([cfg, f"{n}/{tot}", exfil_rate] + [cell(name) for name, _ in NUM])
    summary[cfg] = {"n_valid": n, "n_total": tot, "exfil_rate": exfil_rate,
                    **{k: round(v,3) for k,v in means.items()}}

print(f"\n--- averaged over VALID trials per config (degenerate foothold-only runs excluded) ---")
print(render(avghdr, avgrows))

json.dump({"trials": trials, "temperature": __import__("os").environ.get("LLM_TEMPERATURE"),
           "per_config_avg": summary}, open(f"{logdir}/comparison.json","w"), indent=2)
print(f"\nSaved: {logdir}/comparison.json   (per-run logs + stats in {logdir}/)")
PY
