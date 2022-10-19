import pytest
import shutil
import rich
from pathlib import Path
from ...utils.common import STDLib


# Example of a Linux Atomic Test Harness which executes a `wget` command-line.
@pytest.mark.linux
class TestRemoteSystemDiscovery:
    @pytest.mark.parametrize(
        "recon_methods",
        [
            ["ip", "neigh", "show"],
            ["arp"],
            ["ip", "route"],
            ["cat", "/etc/hosts"],
            ["ping", "-c", "1", "127.0.0.1"],
        ],
        ids=[
            "ip neigh show",
            "arp",
            "ip route",
            "cat /etc/hosts",
            "ping -c 1 127.0.0.1",
        ],
    )
    def test_remote_system_discovery(self, recon_methods: list[str]):
        """
        Run various network recon commands.
        """

        # Make sure the executable is present on the system
        full_path: str | Path | None = shutil.which(recon_methods[0])
        if full_path is None:
            pytest.skip(f"Skipping test because '{recon_methods[0]}' is not present")
        recon_methods[0] = str(full_path)

        # Execute the command-line and get the result
        execution_result = STDLib.default_commandline_executer(recon_methods)

        assert execution_result is not None
        assert execution_result.return_code == 0
        execution_result.attack_id = "T1018"
        print()
        rich.print_json(execution_result.to_json(indent=4, sort_keys=True))
