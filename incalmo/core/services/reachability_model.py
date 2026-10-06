"""Proposal 2 — Location-Aware Attack Graph: the reachability model.

Reachability is VANTAGE-CONDITIONED and derived empirically from scans: a scan from
vantage host V against subnet S that returns hosts proves V can reach S; returning
nothing is evidence V cannot (or S is empty). Same-subnet membership is always
reachable (computed from IP addresses, no scan needed).

Policy (locked decision D1) is CONSERVATIVE: unknown reachability is treated as
NOT reachable by the attack graph (callers require can_reach_host(...) is True).

Pure data + lookups — no LLM/C2/Docker — so it is unit-testable with fixtures.
Used only when config.features.p2_location_aware is True (otherwise the attack
graph keeps its global behavior). Kept separate so P5 can later add TTL/confidence
decay without touching the graph.
"""

from datetime import datetime
import ipaddress


def _host_key(host) -> tuple:
    return tuple(sorted(getattr(host, "ip_addresses", []) or []))


class ReachabilityModel:
    def __init__(self, blacklist_ips=None, delta=False, guided=False):
        # key(vantage) -> { subnet_mask: {"status": "reachable"|"unreachable",
        #                                  "confidence": float,
        #                                  "first_seen": iso, "last_seen": iso} }
        self._reach = {}
        self.blacklist_ips = blacklist_ips or []
        # #1 delta digest / #7 guided scan — both default off (current P2 behavior).
        self.delta = delta
        self.guided = guided
        # Signature of the last digest emitted, for #1 (emit only on change).
        self._last_sig = None

    # ---- recording ----------------------------------------------------------
    def record_scan(self, vantage_host, subnet_mask: str, hosts_found: bool):
        key = _host_key(vantage_host)
        now = datetime.now().isoformat()
        status = "reachable" if hosts_found else "unreachable"
        bucket = self._reach.setdefault(key, {})
        rec = bucket.get(subnet_mask)
        if rec is None:
            bucket[subnet_mask] = {
                "status": status,
                "confidence": 1.0,
                "first_seen": now,
                "last_seen": now,
            }
        else:
            # A positive observation always wins and refreshes; a negative one only
            # updates if we had no positive yet.
            if status == "reachable" or rec["status"] != "reachable":
                rec["status"] = status
            rec["last_seen"] = now

    # ---- helpers ------------------------------------------------------------
    @staticmethod
    def _subnets_of(host, network) -> list:
        masks = []
        for subnet in network.subnets:
            if subnet.any_ips_in_subnet(host.ip_addresses):
                masks.append(subnet.ip_mask)
        return masks

    @staticmethod
    def _share_subnet(host_a, host_b, network) -> bool:
        for subnet in network.subnets:
            if subnet.any_ips_in_subnet(host_a.ip_addresses) and subnet.any_ips_in_subnet(
                host_b.ip_addresses
            ):
                return True
        return False

    # ---- queries ------------------------------------------------------------
    def can_reach_subnet(self, attack_host, subnet_mask: str):
        """True / False / None(unknown) for one subnet from attack_host."""
        rec = self._reach.get(_host_key(attack_host), {}).get(subnet_mask)
        if rec is None:
            return None
        return rec["status"] == "reachable"

    def can_reach_host(self, attack_host, target_host, network):
        """True / False / None. Same-subnet => True. Otherwise True if any of the
        target's subnets is observed reachable from attack_host; False if all known
        records say unreachable; None if nothing is known."""
        if attack_host is target_host:
            return True
        if self._share_subnet(attack_host, target_host, network):
            return True

        statuses = []
        for mask in self._subnets_of(target_host, network):
            statuses.append(self.can_reach_subnet(attack_host, mask))

        if any(s is True for s in statuses):
            return True
        if statuses and all(s is False for s in statuses):
            return False
        return None

    # ---- prompt / stats -----------------------------------------------------
    def _vantage_view(self, environment_state_service):
        """For each owned vantage: (name, reachable, unreachable, unscanned) sets."""
        env = environment_state_service
        network = env.network
        all_masks = [s.ip_mask for s in network.subnets]
        view = []
        for host in env.get_hosts_with_agents():
            own = set(self._subnets_of(host, network))
            reachable, unreachable, unknown = set(own), set(), set()
            for mask in all_masks:
                if mask in own:
                    continue
                st = self.can_reach_subnet(host, mask)
                if st is True:
                    reachable.add(mask)
                elif st is False:
                    unreachable.add(mask)
                else:
                    unknown.add(mask)
            name = host.hostname or (host.ip_addresses[0] if host.ip_addresses else "?")
            view.append((name, reachable, unreachable, unknown))
        return view

    def to_summary(self, environment_state_service) -> str:
        """Per-owned-vantage reachability digest for the planner prompt.

        #1 (delta): when self.delta is on, emit the digest only when the reachability
        picture changed since the last emission; otherwise return "" (the planner
        already has the unchanged picture from a previous step), saving per-step
        tokens. #7 (guided): when self.guided is on, append explicit scan suggestions
        for unscanned subnets to actively direct recon.
        """
        view = self._vantage_view(environment_state_service)

        # #1: suppress unchanged digests.
        sig = tuple(
            (name, tuple(sorted(r)), tuple(sorted(u)), tuple(sorted(k)))
            for name, r, u, k in view
        )
        if self.delta and self._last_sig is not None and sig == self._last_sig:
            return ""
        changed = self.delta and self._last_sig is not None and sig != self._last_sig
        self._last_sig = sig

        header = (
            "\nReachability UPDATE (location-aware) — changed since last step:"
            if changed
            else "\nReachability (location-aware) — from each host you control:"
        )
        lines = [header]
        for name, reachable, unreachable, unknown in view:
            lines.append(
                f"  - {name}: reachable={sorted(reachable)} "
                f"unreachable={sorted(unreachable)} unscanned={sorted(unknown)}"
            )
        lines.append(
            "To attack a host in an unscanned subnet, first Scan that subnet from a "
            "vantage that can reach it; unreachable subnets need a new stepping-stone."
        )

        # #7: concrete, action-oriented recon suggestions.
        if self.guided:
            suggestions = [
                f"  - SCAN {mask} from {name}"
                for name, _r, _u, unknown in view
                for mask in sorted(unknown)
            ]
            if suggestions:
                lines.append("Suggested recon (do these to expand reach):")
                lines.extend(suggestions)

        return "\n".join(lines)
