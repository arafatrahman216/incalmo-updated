"""Load a hand-crafted environment/attack-graph fixture (JSON) into live
EnvironmentStateService + AttackGraphService objects — with NO LLM, NO C2, and NO
Docker — for deterministic manual testing of the proposal features.

See incalmo/proposal/P1_IMPLEMENTATION_PLAN.txt (section 5) for the JSON schema.
"""

import json
import os

from config.attacker_config import AttackerConfig, StateMachineStrategy
from incalmo.core.services.environment_state_service import EnvironmentStateService
from incalmo.core.services.attack_graph_service import AttackGraphService
from incalmo.core.models.network import Network, Subnet, Host
from incalmo.core.models.network.open_port import OpenPort
from incalmo.core.models.network.credential import SSHCredential
from incalmo.core.models.events import ExfiltratedData
from incalmo.models.agent import Agent

FIXTURE_DIR = os.path.dirname(__file__)


class _StubC2:
    """Minimal stand-in for C2ApiClient — the state service only calls these."""

    def get_agents(self):
        return []

    def get_agent(self, paw):
        return None


def _minimal_config() -> AttackerConfig:
    return AttackerConfig(
        name="fixture",
        strategy=StateMachineStrategy(name="fixture"),
        environment="equifax_large",
        c2c_server="http://localhost:8888",
    )


def _build_network(data: dict) -> Network:
    network = Network([Subnet(mask) for mask in data.get("subnets", [])])

    for hj in data.get("hosts", []):
        host = Host(ip_addresses=[hj["ip"]], hostname=hj.get("hostname"))

        for port_str, pj in hj.get("open_ports", {}).items():
            port = int(port_str)
            host.open_ports[port] = OpenPort(
                port=port, service=pj.get("service", ""), CVE=list(pj.get("cve", []))
            )

        host.critical_data_files = {
            user: list(files)
            for user, files in hj.get("critical_data_files", {}).items()
        }

        for cj in hj.get("ssh_config", []):
            cred = SSHCredential(
                hostname=cj.get("hostname", ""),
                host_ip=cj["host_ip"],
                username=cj["username"],
                port=str(cj.get("port", "22")),
                agent_discovered=None,
            )
            cred.utilized = bool(cj.get("utilized", False))
            host.ssh_config.append(cred)

        if hj.get("infected"):
            paws = hj.get("agents") or [f"paw_{hj['ip']}"]
            for paw in paws:
                host.add_agent(
                    Agent(
                        paw=paw,
                        username=hj.get("username", "root"),
                        privilege=hj.get("privilege", "Elevated"),
                        pid=1,
                        host_ip_addrs=[hj["ip"]],
                        hostname=hj.get("hostname") or hj["ip"],
                    )
                )

        network.add_host(host)

    return network


def load_fixture(path: str):
    """Return (environment_state_service, attack_graph_service) for a fixture.

    `path` may be a bare fixture name (e.g. "equifax_midrun") or a full path.
    """
    if not os.path.isabs(path) and not path.endswith(".json"):
        path = os.path.join(FIXTURE_DIR, f"{path}.json")

    with open(path) as f:
        data = json.load(f)

    env = EnvironmentStateService(_StubC2(), _minimal_config())
    env.network = _build_network(data)
    env.exfiltrated_data = [
        ExfiltratedData(file=f, hash="fixturehash")
        for f in data.get("exfiltrated", [])
    ]

    attack_graph = AttackGraphService(env)

    # Proposal 2: if the fixture asserts reachability, attach + seed a model.
    # Schema: "reachability": {"<vantage_ip>": {"<subnet_mask>": true|false}}
    reach_block = data.get("reachability")
    if reach_block is not None:
        from incalmo.core.services.reachability_model import ReachabilityModel

        model = ReachabilityModel()
        for vantage_ip, subnets in reach_block.items():
            vantage = env.network.find_host_by_ip(vantage_ip)
            if vantage is None:
                continue
            for subnet_mask, reachable in subnets.items():
                model.record_scan(vantage, subnet_mask, bool(reachable))
        attack_graph.reachability = model

    return env, attack_graph
