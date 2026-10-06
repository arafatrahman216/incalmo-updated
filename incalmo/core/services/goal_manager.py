"""Proposal 1 — Goal-and-Progress Manager.

A DETERMINISTIC coverage oracle that decides whether a run has actually achieved
its objectives, so an LLM `<finished>` becomes a *request* the oracle may veto.
This fixes "premature termination": the planner emitting `<finished>` while
reachable hosts / known-but-untaken data / unused credentials still remain.

Design notes (see incalmo/proposal/P1_IMPLEMENTATION_PLAN.txt and the decisions
log):
  - No ground-truth goal list exists (data is discovered at runtime), so the
    oracle reasons over the attacker's CURRENT knowledge only.
  - F1: a host is only a "compromise" goal if there is a REAL vector to it (a CVE
    on an open port, or a held credential). Raw open ports alone, subnet gateways
    (.1) and blacklisted IPs are NOT goals — this removes router/noise
    false-positives observed in live runs.
  - F3: the safety valve measures "stuck", not "total attempts" — the rejection
    counter resets whenever the run makes real progress (a new host infected or a
    file exfiltrated).

Pure logic over EnvironmentStateService + AttackGraphService — no LLM, no C2, no
Docker — so it is unit-testable against hand-crafted graph fixtures. Decoupled:
used only when config.features.p1_goal_manager is True; automatically becomes
vantage-aware when P2 is enabled (no change here).
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional


@dataclass
class RemainingGoal:
    kind: str  # "compromise" | "exfiltrate" | "unused_cred"
    detail: str
    target_ip: Optional[str] = None
    username: Optional[str] = None  # set for "unused_cred" (prescriptive veto, #8)


class GoalManager:
    def __init__(
        self,
        environment_state_service,
        attack_graph_service,
        features,
        blacklist_ips: Optional[list] = None,
    ):
        self.env = environment_state_service
        self.attack_graph = attack_graph_service
        self.features = features
        self.blacklist_ips = blacklist_ips or []

        # Safety-valve state (F3).
        self._rejections = 0
        self._last_progress = None

        # Per-goal backoff state (#4): (kind, ip) -> number of finish-requests at
        # which this goal was still open. A goal whose count exceeds
        # p1_goal_max_attempts is "retired" (treated as infeasible).
        self._goal_attempts = {}

    # ---- helpers ------------------------------------------------------------
    @property
    def rejections(self) -> int:
        return self._rejections

    def _is_gateway(self, ip: str) -> bool:
        # Heuristic: the .1 of a /24 is the gateway/router in these environments,
        # not an attack target.
        return ip.split(".")[-1] == "1"

    def _is_blacklisted(self, ip: str) -> bool:
        for cidr in self.blacklist_ips:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                    return True
            except Exception:
                continue
        return False

    def _has_real_vector(self, target) -> bool:
        """F1: a host is a real compromise goal only if there's a CVE on an open
        port, or some host holds a credential to it."""
        for port in target.open_ports.values():
            if getattr(port, "CVE", None):
                return True
        for host in self.env.network.get_all_hosts():
            for cred in host.ssh_config:
                if cred.host_ip in target.ip_addresses:
                    return True
        return False

    def _exfiltrated_files(self) -> set:
        files = set()
        for e in getattr(self.env, "exfiltrated_data", []) or []:
            f = getattr(e, "file", None)
            if f:
                files.add(f)
        return files

    def _target_reachable(self, target_host) -> bool:
        """Soft P2 integration: when a ReachabilityModel is attached to the attack
        graph, a target only counts as a goal if some infected host can actually
        reach it. When P2 is off (no model) this always returns True, so P1 behaves
        standalone. This is what retires the unreachable-DB goal (F2) under P1+P2."""
        rm = getattr(self.attack_graph, "reachability", None)
        if rm is None or target_host is None:
            return True
        for h in self.env.get_hosts_with_agents():
            if rm.can_reach_host(h, target_host, self.env.network) is True:
                return True
        return False

    def _progress_metric(self) -> tuple:
        """A monotonic measure of real progress: (#infected hosts, #exfiltrated)."""
        return (
            len(self.env.get_hosts_with_agents()),
            len(self._exfiltrated_files()),
        )

    # ---- oracle -------------------------------------------------------------
    def remaining_goals(self) -> list:
        """Still-open objectives given current knowledge. Empty => may finish."""
        goals: list[RemainingGoal] = []
        seen = set()

        def add(kind: str, detail: str, ip, username=None):
            key = (kind, ip)
            if key not in seen:
                seen.add(key)
                goals.append(RemainingGoal(kind, detail, ip, username))

        infected_hosts = self.env.get_hosts_with_agents()

        # (a) A reachable uninfected host that has a real attack vector (F1).
        for host in infected_hosts:
            try:
                paths = self.attack_graph.get_possible_targets_from_host(host)
            except Exception:
                paths = []
            src = host.hostname or (host.ip_addresses[0] if host.ip_addresses else "?")
            for path in paths:
                target = path.target_host
                if target.infected or not target.has_an_ip_address():
                    continue
                ip = target.get_ip_address()
                if self._is_gateway(ip) or self._is_blacklisted(ip):
                    continue
                if not self._has_real_vector(target):
                    continue
                add(
                    "compromise",
                    f"host {ip} is reachable from {src} but not yet compromised",
                    ip,
                )

        # (b) Discovered critical data not yet exfiltrated.
        if self.features.p1_require_exfiltration:
            taken = self._exfiltrated_files()
            for host in self.env.network.get_all_hosts():
                ip = host.ip_addresses[0] if host.ip_addresses else None
                if ip and (self._is_gateway(ip) or self._is_blacklisted(ip)):
                    continue
                if not host.infected and not self._target_reachable(host):
                    continue
                for user, files in host.critical_data_files.items():
                    for f in files:
                        if f not in taken:
                            add(
                                "exfiltrate",
                                f"critical file {f} on {ip} (user {user}) not exfiltrated",
                                ip,
                            )

        # (c) A held credential to a host we have not compromised (and that is a
        #     real target, not a gateway/blacklisted IP).
        for host in self.env.network.get_all_hosts():
            for cred in host.ssh_config:
                if getattr(cred, "utilized", False):
                    continue
                if self._is_gateway(cred.host_ip) or self._is_blacklisted(cred.host_ip):
                    continue
                target = self.env.network.find_host_by_ip(cred.host_ip)
                if target is None or not target.infected:
                    if not self._target_reachable(target):
                        continue
                    add(
                        "unused_cred",
                        f"unused credential {cred.username}@{cred.host_ip} to an uncompromised host",
                        cred.host_ip,
                        username=cred.username,
                    )

        return goals

    def _is_retired(self, goal) -> bool:
        """#4: a goal surfaced-but-unresolved more than p1_goal_max_attempts times
        is retired (treated as infeasible). No-op unless p1_goal_backoff is on."""
        if not self.features.p1_goal_backoff:
            return False
        key = (goal.kind, goal.target_ip)
        return self._goal_attempts.get(key, 0) > self.features.p1_goal_max_attempts

    def actionable_goals(self) -> list:
        """Open goals the planner can still usefully pursue: remaining_goals minus
        any retired by backoff. Equals remaining_goals() when backoff is off."""
        return [g for g in self.remaining_goals() if not self._is_retired(g)]

    def is_satisfied(self) -> bool:
        """GENUINE satisfaction: nothing open at all (independent of backoff). Used
        for 'satisfied vs stuck' reporting; the finish decision lives in
        evaluate_finish_request, which also considers backoff/infeasibility."""
        return len(self.remaining_goals()) == 0

    def _prescribe(self, g) -> str:
        """#5/#8: action-oriented phrasing of a single goal for the veto message."""
        if g.kind == "unused_cred":
            who = f"{g.username}@{g.target_ip}" if g.username else g.target_ip
            return f"USE the captured credential {who} to authenticate and compromise {g.target_ip}."
        if g.kind == "exfiltrate":
            return f"EXFILTRATE the critical data on {g.target_ip} ({g.detail})."
        if g.kind == "compromise":
            return f"COMPROMISE {g.target_ip}: scan it, then exploit a known CVE or use a held credential."
        return g.detail

    def describe_remaining(self, goals=None) -> str:
        goals = self.actionable_goals() if goals is None else goals
        if not goals:
            return "All known objectives are satisfied."
        prescriptive = getattr(self.features, "p1_prescriptive_veto", False)
        lines = ["You requested to finish, but these objectives are still OPEN:"]
        for g in goals:
            if prescriptive:
                lines.append(f"  - {self._prescribe(g)}")
            else:
                lines.append(f"  - [{g.kind}] {g.detail}")
        lines.append(
            "Continue pursuing these objectives, or justify infeasibility with concrete evidence."
        )
        return "\n".join(lines)

    def evaluate_finish_request(self):
        """Decide whether to honor an LLM <finished>. Returns (allow, message).

        - allow=True, message=None  -> finish the run.
        - allow=False, message=str  -> veto; `message` is injected back to the
          planner describing what remains.

        F3: the rejection counter resets whenever real progress has been made
        since the previous finish request, so a productive run is never cut off;
        the valve only fires when the run is genuinely stuck.
        """
        raw_open = self.remaining_goals()

        if not raw_open:
            return True, None  # genuinely satisfied — nothing open at all

        # #4: record one "surfacing" for every still-open goal. A goal that stays
        # open across finish-requests climbs toward its per-goal cap and is then
        # retired (treated as infeasible) so the planner stops chasing it.
        if self.features.p1_goal_backoff:
            for g in raw_open:
                key = (g.kind, g.target_ip)
                self._goal_attempts[key] = self._goal_attempts.get(key, 0) + 1

        actionable = [g for g in raw_open if not self._is_retired(g)]

        # #6: only retired/infeasible goals remain — optionally finish now instead
        # of flailing until the global rejection cap.
        if not actionable and self.features.p1_finish_when_infeasible:
            return True, None

        progress = self._progress_metric()
        if self._last_progress is not None and progress > self._last_progress:
            self._rejections = 0
        self._last_progress = progress

        if self._rejections >= self.features.p1_max_finish_rejections:
            return True, None  # safety valve: genuinely stuck

        self._rejections += 1
        # Nag about actionable goals when any remain; otherwise fall back to the
        # full open set so the veto message is never empty.
        return False, self.describe_remaining(actionable or raw_open)
