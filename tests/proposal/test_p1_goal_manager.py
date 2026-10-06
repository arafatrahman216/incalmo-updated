"""Proposal 1 — Goal-and-Progress Manager: deterministic tests over hand-crafted
graph fixtures (no LLM / no C2 / no Docker). See
incalmo/proposal/P1_IMPLEMENTATION_PLAN.txt section 6.
"""

from incalmo.core.services.goal_manager import GoalManager
from incalmo.proposal.fixtures.loader import load_fixture
from config.attacker_config import Features
from incalmo.models.agent import Agent


def _gm(fixture: str, **feat) -> GoalManager:
    env, attack_graph = load_fixture(fixture)
    features = Features(p1_goal_manager=True, **feat)
    return GoalManager(env, attack_graph, features)


def test_midrun_blocks_finish():
    """DB reachable + holds data + unused cred -> must NOT be satisfied."""
    gm = _gm("equifax_midrun")
    assert gm.is_satisfied() is False
    goals = gm.remaining_goals()
    kinds = {g.kind for g in goals}
    assert "compromise" in kinds
    assert "exfiltrate" in kinds
    assert "unused_cred" in kinds
    assert "192.168.201.100" in {g.target_ip for g in goals}


def test_done_allows_finish():
    """Both hosts owned, cred used, data exfiltrated -> satisfied."""
    gm = _gm("equifax_done")
    assert gm.remaining_goals() == []
    assert gm.is_satisfied() is True


def test_require_exfiltration_toggle():
    """The p1_require_exfiltration knob controls whether untaken data is a goal."""
    env, attack_graph = load_fixture("equifax_done")
    env.exfiltrated_data = []  # DB file now 'discovered but untaken'

    strict = GoalManager(
        env, attack_graph, Features(p1_goal_manager=True, p1_require_exfiltration=True)
    )
    assert any(g.kind == "exfiltrate" for g in strict.remaining_goals())

    relaxed = GoalManager(
        env, attack_graph, Features(p1_goal_manager=True, p1_require_exfiltration=False)
    )
    assert all(g.kind != "exfiltrate" for g in relaxed.remaining_goals())


def test_describe_remaining_lists_open_goals():
    gm = _gm("equifax_midrun")
    text = gm.describe_remaining()
    assert "OPEN" in text
    assert "192.168.201.100" in text


def test_f1_gateway_and_vectorless_hosts_are_not_goals():
    """F1: a .1 gateway and an open-ports-only host (no CVE, no cred) must NOT be
    compromise goals -> oracle is satisfied."""
    gm = _gm("gateway_noise")
    assert gm.remaining_goals() == []
    assert gm.is_satisfied() is True


def test_f1_blacklisted_ip_is_not_a_goal():
    """A host inside config.blacklist_ips is never a compromise/cred goal."""
    env, attack_graph = load_fixture("equifax_midrun")
    # Blacklist the DB subnet -> the only real goals (DB compromise + cred) drop out.
    gm = GoalManager(
        env, attack_graph, Features(p1_goal_manager=True),
        blacklist_ips=["192.168.201.0/24"],
    )
    ips = {g.target_ip for g in gm.remaining_goals()}
    assert "192.168.201.100" not in ips


def test_f3_valve_resets_on_progress():
    """F3: the rejection counter resets when real progress is made (new infection)."""
    env, attack_graph = load_fixture("f3_progress")
    gm = GoalManager(env, attack_graph, Features(p1_goal_manager=True))

    allow1, _ = gm.evaluate_finish_request()
    allow2, _ = gm.evaluate_finish_request()
    assert allow1 is False and allow2 is False
    assert gm.rejections == 2

    # Simulate real progress: infect the 'app' host.
    app = env.network.find_host_by_ip("192.168.200.30")
    app.add_agent(
        Agent(paw="pawAPP", username="root", privilege="Elevated", pid=2,
              host_ip_addrs=["192.168.200.30"], hostname="app")
    )

    # Still unsatisfied (DB remains), but the counter should have reset then +1.
    allow3, _ = gm.evaluate_finish_request()
    assert allow3 is False
    assert gm.rejections == 1


def test_f3_safety_valve_allows_finish_when_stuck():
    """With no progress, the valve eventually allows finish (bounded rejections)."""
    env, attack_graph = load_fixture("equifax_midrun")
    gm = GoalManager(
        env, attack_graph, Features(p1_goal_manager=True, p1_max_finish_rejections=3)
    )
    results = [gm.evaluate_finish_request()[0] for _ in range(4)]
    assert results == [False, False, False, True]


def test_features_default_is_baseline():
    """A config with no features block = all proposals OFF = baseline Incalmo."""
    f = Features()
    assert f.p1_goal_manager is False
    assert f.p2_location_aware is False
    assert f.p5_structured_memory is False
    assert f.p3_verifier is False
    assert f.p4_beam_search is False
    assert f.p6_dag_scheduler is False


# ---- Optimizations #4 (per-goal backoff), #6 (finish-when-infeasible),
#      #5/#8 (prescriptive veto) ----------------------------------------------

def test_backoff_plus_finish_when_infeasible_ends_stalled_run():
    """#4 + #6: once every open goal has been surfaced-but-unresolved past its
    per-goal cap, the run is allowed to finish instead of flailing to the global cap."""
    gm = _gm(
        "equifax_midrun",
        p1_goal_backoff=True,
        p1_goal_max_attempts=2,
        p1_finish_when_infeasible=True,
        p1_max_finish_rejections=99,  # prove the EARLY finish isn't the global valve
    )
    assert gm.evaluate_finish_request()[0] is False  # surfacing 1 -> veto
    assert gm.evaluate_finish_request()[0] is False  # surfacing 2 -> veto
    allow, msg = gm.evaluate_finish_request()         # 3rd: all goals retired
    assert allow is True and msg is None


def test_backoff_without_finish_flag_still_respects_global_cap():
    """#4 alone (no #6) must NOT finish early; it keeps vetoing until the global
    rejection cap fires — backoff only trims the veto message, not the stop rule."""
    gm = _gm(
        "equifax_midrun",
        p1_goal_backoff=True,
        p1_goal_max_attempts=2,
        p1_finish_when_infeasible=False,
        p1_max_finish_rejections=4,
    )
    allows = [gm.evaluate_finish_request()[0] for _ in range(4)]
    assert allows == [False, False, False, False]
    assert gm.evaluate_finish_request()[0] is True  # 5th: global safety valve


def test_backoff_off_is_unchanged_behavior():
    """Regression: with backoff off, goals are never retired (current P1 behavior)."""
    gm = _gm("equifax_midrun")  # p1 on, all opt flags off
    for _ in range(10):
        gm.evaluate_finish_request()
    assert gm.actionable_goals() == gm.remaining_goals()


def test_prescriptive_veto_names_the_credential_action():
    """#5/#8: prescriptive phrasing turns the unused-credential goal into an explicit
    'USE credential user@host' instruction (drives credential utilization)."""
    gm = _gm("equifax_midrun", p1_prescriptive_veto=True)
    text = gm.describe_remaining()
    assert "USE the captured credential" in text
    assert "database@192.168.201.100" in text
    # and the goal actually carries the username for the message
    creds = [g for g in gm.remaining_goals() if g.kind == "unused_cred"]
    assert creds and creds[0].username == "database"


def test_prescriptive_veto_off_keeps_descriptive_text():
    gm = _gm("equifax_midrun")
    text = gm.describe_remaining()
    assert "[unused_cred]" in text
    assert "USE the captured credential" not in text
