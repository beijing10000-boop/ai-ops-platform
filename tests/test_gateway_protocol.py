import os
import subprocess
from pathlib import Path
import pytest

GATEWAY = Path(__file__).parents[1] / "gateway/aiops-diagnostic-gateway"


@pytest.mark.parametrize(
    "protocol_request",
    [
        "id",
        "scp -t /tmp/file",
        "internal-sftp",
        "aiops-v1 restart 30",
        "aiops-v1 cpu 30 extra",
        "aiops-v1 logs 30 nginx;touch /tmp/aiops-should-never-exist",
        "aiops-v1 logs 30 $(id)",
        "aiops-v1 logs 30 --help",
        "aiops-v1 cpu 30\nid",
        "aiops-v1 cpu 999999999999",
        "aiops-v1 cpu -1",
        "aiops-v1 cpu 30.0",
        "aiops-v1 memory 0",
    ],
)
def test_actual_gateway_process_rejects_unsafe_protocol(protocol_request):
    completed = subprocess.run(
        ["/bin/sh", str(GATEWAY)],
        env={**os.environ, "SSH_ORIGINAL_COMMAND": protocol_request},
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert completed.returncode == 64 and "AIOPS_GATEWAY_V1" not in completed.stdout


def test_actual_gateway_connection_action_runs_without_python():
    completed = subprocess.run(
        ["/bin/sh", str(GATEWAY)],
        env={**os.environ, "SSH_ORIGINAL_COMMAND": "aiops-v1 connection 30"},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0
    assert completed.stdout.startswith("AIOPS_GATEWAY_V1\nAIOPS_SSH_OK\n")
    assert "Linux" in completed.stdout
