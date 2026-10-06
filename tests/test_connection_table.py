from unittest.mock import patch
from types import SimpleNamespace

from correlate.connection_table import build_connection_table


def create_fake_connection(
    ip,
    port,
    protocol,
    pid,
    remote_ip="",
    remote_port=0,
):
    """
    Create a fake psutil connection without relying
    on psutil's internal classes.
    """

    if protocol == "TCP":
        connection_type = 1
    elif protocol == "UDP":
        connection_type = 2
    else:
        connection_type = 0

    return SimpleNamespace(
        fd=100,
        family=2,
        type=connection_type,
        laddr=SimpleNamespace(
            ip=ip,
            port=port
        ),
        raddr=SimpleNamespace(
            ip=remote_ip,
            port=remote_port
        ),
        status="ESTABLISHED",
        pid=pid,
    )


def test_connection_table():

    fake_connections = [
        create_fake_connection(
            ip="192.168.1.10",
            port=50000,
            protocol="TCP",
            pid=1234,
            remote_ip="142.250.195.14",
            remote_port=443,
        ),

        create_fake_connection(
            ip="192.168.1.10",
            port=5353,
            protocol="UDP",
            pid=5678,
            remote_ip="8.8.8.8",
            remote_port=53,
        ),
    ]

    with patch(
        "correlate.connection_table.psutil.net_connections",
        return_value=fake_connections
    ), patch(
        "correlate.connection_table.psutil.Process"
    ) as mock_process:

        mock_process.return_value.name.side_effect = [
            "chrome.exe",
            "dns_service.exe",
        ]

        table = build_connection_table()

    assert table[
        ("TCP", "192.168.1.10", 50000)
    ] == (1234, "chrome.exe")

    assert table[
        ("UDP", "192.168.1.10", 5353)
    ] == (5678, "dns_service.exe")