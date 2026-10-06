from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
from dataclasses import field


# Enum of environments
class Environment(Enum):
    EQUIFAX_SMALL = "equifax_small"
    EQUIFAX_MEDIUM = "equifax_medium"
    EQUIFAX_LARGE = "equifax_large"
    ICS = "ics"
    RING = "ring"
    ENTERPRISE_A = "enterprise_a"
    ENTERPRISE_B = "enterprise_b"


class AbstractionLevel(str, Enum):
    INCALMO = "incalmo"
    SHELL = "shell"
    LOW_LEVEL_ACTIONS = "low_level_actions"
    NO_SERVICES = "no_services"
    AGENT_SCAN = "agent_scan"
    AGENT_LATERAL_MOVE = "agent_lateral_move"
    AGENT_PRIVILEGE_ESCALATION = "agent_privilege_escalation"
    AGENT_EXFILTRATE_DATA = "agent_exfiltrate_data"
    AGENT_FIND_INFORMATION = "agent_find_information"
    AGENT_ALL = "agent_all"


class LLMStrategyConfig(BaseModel):
    planning_llm: str
    execution_llm: str
    abstraction: AbstractionLevel


class StateMachineStrategy(BaseModel):
    name: str
    script_path: Optional[str] = None


def convert_to_environment(env: str) -> Environment:
    try:
        return Environment(env)
    except ValueError:
        raise ValueError(f"'{env}' is not a valid environment")


def convert_to_abstraction_level(level: str) -> AbstractionLevel:
    try:
        return AbstractionLevel(level)
    except ValueError:
        raise ValueError(f"'{level}' is not a valid level of abstraction")


class Features(BaseModel):
    """Toggles for the proposal improvements. All default False, so a config.json
    without a "features" block behaves EXACTLY like baseline Incalmo. Each flag is
    independent and decoupled — any combination may be enabled.
    See incalmo/proposal/PROPOSAL_AND_DECISIONS.txt."""

    # Group A — world model
    p1_goal_manager: bool = False
    p2_location_aware: bool = False
    p5_structured_memory: bool = False
    # Glue
    p3_verifier: bool = False
    # Group B — planning/execution control
    p4_beam_search: bool = False
    p6_dag_scheduler: bool = False

    # ---- P1 knobs ----
    # Bound on how many times the Goal Manager may veto an LLM <finished> before
    # it gives up and lets the run end (prevents an infinite rejection loop when a
    # goal the oracle believes is reachable is actually unreachable — a case P2 fixes).
    p1_max_finish_rejections: int = 5
    # If True, a run is not "done" while discovered critical data remains un-exfiltrated.
    p1_require_exfiltration: bool = True

    # ---- P1 optimization knobs (all default False => current P1 behavior) ----
    # #4 Per-goal backoff: retire an individual goal from the open set after it has
    # been surfaced-but-unresolved this many finish-requests, so the planner stops
    # being pushed toward a goal it keeps failing (cuts wasted steps/tokens). When
    # combined with #6, the run may then finish as soon as only retired/infeasible
    # goals remain, instead of flailing until p1_max_finish_rejections.
    p1_goal_backoff: bool = False
    p1_goal_max_attempts: int = 2
    # #6 Finish-when-infeasible: if no ACTIONABLE goal remains (all retired by
    # backoff or filtered as unreachable/vectorless), honor <finished> immediately
    # without consuming the global rejection budget.
    p1_finish_when_infeasible: bool = False
    # #5/#8 Prescriptive veto: phrase the veto as the concrete next action per goal
    # (e.g. "USE credential bob@10.0.0.5 to compromise 10.0.0.5"), which drives
    # credential *utilization*, not just discovery.
    p1_prescriptive_veto: bool = False

    # ---- P2 optimization knobs (all default False => current P2 behavior) ----
    # #1 Delta digest: emit the reachability summary into the prompt only when the
    # reachability picture changed since the last step (huge per-step token saving,
    # since reachability rarely changes). Unchanged steps contribute nothing.
    p2_digest_delta: bool = False
    # #7 Guided scan: append explicit "SCAN <subnet> from <vantage>" recon
    # suggestions for unscanned subnets, turning P2 from purely restrictive into an
    # active recon director (more hosts discovered => more creds, fewer idle steps).
    p2_guided_scan: bool = False

    # ---- Execution fixes (all default False => current behavior) ----
    # FIX #1 C2 pivot relay: when a lateral move targets a host on a subnet the C2
    # cannot reach directly, start a tiny ncat relay ON THE PIVOT (the compromised
    # host running the move, which CAN reach both the target and the C2) and point
    # the new implant's -server at the pivot. Without this, a pivoted implant beacons
    # to an unreachable C2 (observed `C2:000`), never checks in, and the host is
    # never actually compromised — blocking exfiltration for EVERY config. Fully
    # self-contained: off => the lateral-move command is byte-for-byte unchanged.
    c2_pivot_relay: bool = False
    c2_relay_port: int = 8889
    # FIX #3 Lateral verify / retry guard (a minimal P3 verifier): after a lateral
    # move, if the target did not actually check in, record the failure; once a
    # (source->target) move has failed this many times, the attack graph stops
    # offering that edge, killing the wasted "Text file busy" retry loop. Off => the
    # edge is always offered (current behavior).
    p3_lateral_verify: bool = False
    p3_lateral_fail_threshold: int = 2


class AttackerConfig(BaseModel):
    name: str
    id: Optional[str] = None
    strategy: LLMStrategyConfig | StateMachineStrategy
    environment: str
    c2c_server: str
    # Proposal feature flags; defaults to all-off (baseline Incalmo).
    features: Features = Field(default_factory=Features)
    # Victim-reachable C2 URL for target-side payload downloads (ExploitStruts, ssh/nc agent-spawn).
    # Usually equals c2c_server, but under the harness's c2_on_kali mode c2c_server is a 127.0.0.1
    # ssh -L tunnel reachable only by the strategy on beluga, while victims must fetch the implant
    # from Kali's in-tenant IP. ConfigService fills this from c2c_server when unset.
    agent_c2c_server: Optional[str] = None
    blacklist_ips: list[str] = field(default_factory=list)

    class Config:
        # Enums are serialized as their values
        use_enum_values = True
