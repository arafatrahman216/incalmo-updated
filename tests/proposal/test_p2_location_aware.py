"""Proposal 2 — Location-Aware Attack Graph: deterministic tests over hand-crafted
graph fixtures (no LLM / no C2 / no Docker). See
incalmo/proposal/P2_IMPLEMENTATION_PLAN.txt section 7.
"""

from incalmo.proposal.fixtures.loader import load_fixture
from incalmo.core.services.goal_manager import GoalManager
from incalmo.core.models.network import Host
from incalmo.core.models.network.open_port import OpenPort
from config.attacker_config import Features


def _web_db(env):
    return (
        env.network.find_host_by_ip("192.168.200.20"),
        env.network.find_host_by_ip("192.168.201.100"),
    )


def test_unreachable_blocks_attack_edges():
    env, ag = load_fixture("p2_unreachable")
    web, db = _web_db(env)
    assert ag.get_possible_attack_paths(web, db) == []


def test_reachable_allows_attack_edges():
    env, ag = load_fixture("p2_reachable")
    web, db = _web_db(env)
    assert len(ag.get_possible_attack_paths(web, db)) > 0


def test_p1_ignores_unreachable_goal_when_p2_on():
    """F2: with the DB proven unreachable, P1's oracle must not list it (via
    compromise, exfiltrate, or unused_cred)."""
    env, ag = load_fixture("p2_unreachable")
    gm = GoalManager(
        env, ag, Features(p1_goal_manager=True, p2_location_aware=True)
    )
    ips = {g.target_ip for g in gm.remaining_goals()}
    assert "192.168.201.100" not in ips


def test_p1_lists_reachable_goal_when_p2_on():
    env, ag = load_fixture("p2_reachable")
    gm = GoalManager(
        env, ag, Features(p1_goal_manager=True, p2_location_aware=True)
    )
    ips = {g.target_ip for g in gm.remaining_goals()}
    assert "192.168.201.100" in ips


def test_p2_off_is_global_baseline():
    """No reachability block => model None => global edges (regression guard)."""
    env, ag = load_fixture("equifax_midrun")
    assert ag.reachability is None
    web, db = _web_db(env)
    assert len(ag.get_possible_attack_paths(web, db)) > 0


def test_same_subnet_always_reachable_without_scan():
    """A peer in the attacker's own subnet is reachable even with no scan record."""
    env, ag = load_fixture("p2_unreachable")  # has a reachability model attached
    peer = Host(ip_addresses=["192.168.200.77"])
    peer.open_ports[8080] = OpenPort(port=8080, service="http", CVE=["CVE-2021-1"])
    env.network.add_host(peer)
    web = env.network.find_host_by_ip("192.168.200.20")
    assert len(ag.get_possible_attack_paths(web, peer)) > 0


# ---- Optimizations #1 (delta digest), #7 (guided scan) ----------------------

from incalmo.core.models.network import Subnet


def test_digest_delta_suppresses_unchanged_summary():
    """#1: with delta on, an unchanged reachability picture emits nothing the 2nd time."""
    env, ag = load_fixture("p2_reachable")
    model = ag.reachability
    model.delta = True
    first = model.to_summary(env)
    assert first.strip() != ""          # first emission is the full digest
    assert model.to_summary(env) == ""  # nothing changed -> no tokens spent


def test_digest_delta_reemits_on_change():
    """#1: a new scan observation changes the picture -> the digest re-emits (as UPDATE)."""
    env, ag = load_fixture("p2_unreachable")  # web->201/24 recorded unreachable
    model = ag.reachability
    model.delta = True
    model.to_summary(env)  # prime the signature
    web = env.network.find_host_by_ip("192.168.200.20")
    model.record_scan(web, "192.168.201.0/24", True)  # positive now wins -> flips
    out = model.to_summary(env)
    assert out.strip() != "" and "UPDATE" in out


def test_delta_off_always_emits():
    """Regression: with delta off, the digest is emitted every call (current behavior)."""
    env, ag = load_fixture("p2_reachable")
    model = ag.reachability  # delta defaults off
    assert model.to_summary(env).strip() != ""
    assert model.to_summary(env).strip() != ""


def test_guided_scan_suggests_scanning_unscanned_subnets():
    """#7: an unscanned subnet from an owned vantage yields an explicit SCAN suggestion."""
    env, ag = load_fixture("p2_reachable")
    env.network.subnets.append(Subnet("192.168.202.0/24"))  # never scanned
    model = ag.reachability
    model.guided = True
    out = model.to_summary(env)
    assert "Suggested recon" in out
    assert "SCAN 192.168.202.0/24 from web" in out


def test_guided_off_has_no_suggestions():
    env, ag = load_fixture("p2_reachable")
    env.network.subnets.append(Subnet("192.168.202.0/24"))
    model = ag.reachability  # guided defaults off
    assert "Suggested recon" not in model.to_summary(env)
