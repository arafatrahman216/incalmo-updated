"""Per-run statistics collector (ALWAYS ON — measurement infrastructure, not a
proposal feature). At the end of every run it writes one JSON summary to the
`statistics/` folder so baseline and proposal runs can be compared later
(hosts infected, data exfiltrated, steps, LLM cost, which feature flags were on).

It only READS the finished run's state + output logs and writes a file; it is
wrapped by the caller in try/except so it can never affect a run's outcome.
"""

import json
import os
from datetime import datetime

STATS_DIR = "statistics"


class StatisticsService:
    @staticmethod
    def _read_jsonl(path: str) -> list:
        rows = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            rows.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
        return rows

    @staticmethod
    def collect(strategy, termination_reason: str = "unknown") -> dict:
        env = strategy.environment_state_service
        config = strategy.config
        network = env.network

        all_hosts = network.get_all_unique_hosts()
        infected_hosts = env.get_hosts_with_agents()

        # Root / elevated footprint
        root_hosts = 0
        for h in infected_hosts:
            if any(getattr(a, "privilege", "") == "Elevated" for a in h.agents):
                root_hosts += 1

        # Critical data discovered vs exfiltrated
        discovered_files = set()
        for h in network.get_all_hosts():
            for _user, files in h.critical_data_files.items():
                for f in files:
                    discovered_files.add(f)
        exfiltrated_files = set()
        for e in getattr(env, "exfiltrated_data", []) or []:
            f = getattr(e, "file", None)
            if f:
                exfiltrated_files.add(f)
        taken = discovered_files & exfiltrated_files
        exfiltration_complete = len(discovered_files) > 0 and taken == discovered_files

        # Credentials
        creds_found = 0
        creds_utilized = 0
        for h in network.get_all_hosts():
            for c in h.ssh_config:
                creds_found += 1
                if getattr(c, "utilized", False):
                    creds_utilized += 1

        # Output-dir derived stats (LLM + actions)
        log_dir = getattr(strategy.logging_service, "logger_dir_path", None)
        operation_id = os.path.basename(log_dir) if log_dir else config.name

        llm_calls = llm_in = llm_out = 0
        wall_clock_min = None
        if log_dir:
            toks = StatisticsService._read_jsonl(
                os.path.join(log_dir, "token_usage.json")
            )
            llm_calls = len(toks)
            llm_in = sum(t.get("input_tokens", 0) for t in toks)
            llm_out = sum(t.get("output_tokens", 0) for t in toks)
            if toks:
                try:
                    t0 = datetime.fromisoformat(toks[0]["timestamp"])
                    t1 = datetime.fromisoformat(toks[-1]["timestamp"])
                    wall_clock_min = round((t1 - t0).total_seconds() / 60.0, 2)
                except Exception:
                    pass

        actions = hl = ll = ll_ok = ll_fail = 0
        if log_dir:
            acts = StatisticsService._read_jsonl(os.path.join(log_dir, "actions.json"))
            actions = len(acts)
            for a in acts:
                if a.get("type") == "HighLevelAction":
                    hl += 1
                elif a.get("type") == "LowLevelAction":
                    ll += 1
                    if (a.get("stderr") or "").strip() == "":
                        ll_ok += 1
                    else:
                        ll_fail += 1

        strat = config.strategy
        strategy_summary = {
            "planning_llm": getattr(strat, "planning_llm", None),
            "execution_llm": getattr(strat, "execution_llm", None),
            "abstraction": getattr(strat, "abstraction", None),
            "name": getattr(strat, "name", None),
        }

        return {
            "operation_id": operation_id,
            "timestamp": datetime.now().isoformat(),
            "termination_reason": termination_reason,
            "config": {
                "name": config.name,
                "environment": config.environment,
                "strategy": strategy_summary,
                "features": config.features.model_dump()
                if hasattr(config, "features")
                else {},
            },
            "progress": {
                "hosts_discovered": len(all_hosts),
                "hosts_infected": len(infected_hosts),
                "hosts_root": root_hosts,
                "subnets_discovered": [s.ip_mask for s in network.subnets],
                "critical_files_discovered": len(discovered_files),
                "critical_files_exfiltrated": len(taken),
                "exfiltration_complete": exfiltration_complete,
                "credentials_found": creds_found,
                "credentials_utilized": creds_utilized,
            },
            "execution": {
                "steps": getattr(strategy, "cur_step", None),
                "max_steps": getattr(strategy, "total_steps", None),
                "p1_finish_rejections": getattr(strategy, "finish_rejections", 0),
                "actions_total": actions,
                "high_level_actions": hl,
                "low_level_actions": ll,
                "low_level_ok": ll_ok,
                "low_level_fail": ll_fail,
            },
            "llm": {
                "calls": llm_calls,
                "input_tokens": llm_in,
                "output_tokens": llm_out,
                "total_tokens": llm_in + llm_out,
                "wall_clock_min": wall_clock_min,
            },
        }

    @staticmethod
    def write_run_statistics(strategy, termination_reason: str = "unknown") -> str:
        stats = StatisticsService.collect(strategy, termination_reason)
        os.makedirs(STATS_DIR, exist_ok=True)
        out_path = os.path.join(STATS_DIR, f"{stats['operation_id']}.json")
        with open(out_path, "w") as f:
            json.dump(stats, f, indent=2)
        return out_path
