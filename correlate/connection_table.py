import time
import socket
import psutil


def build_connection_table():
    """
    Build a mapping of:

        (protocol, local_ip, local_port)
            ->
        (pid, process_name)

    This provides the process correlation layer for the
    Windows Application-Aware Network Traffic Analyzer.
    """

    connection_table = {}

    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:

            # Skip connections without a local address
            if not conn.laddr:
                continue

            # Skip connections without an associated PID
            if conn.pid is None:
                continue

            local_ip = conn.laddr.ip
            local_port = conn.laddr.port

            # Determine TCP or UDP
            if conn.type == socket.SOCK_STREAM:
                protocol = "TCP"

            elif conn.type == socket.SOCK_DGRAM:
                protocol = "UDP"

            else:
                continue

            # Get process name
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()

            except psutil.NoSuchProcess:
                process_name = "Unknown"

            except psutil.AccessDenied:
                process_name = "AccessDenied"

            except psutil.Error:
                process_name = "Unknown"

            # Create correlation key
            key = (
                protocol,
                local_ip,
                local_port
            )

            connection_table[key] = (
                conn.pid,
                process_name
            )

    except psutil.AccessDenied:
        print("[!] Access denied.")
        print("[!] Run CMD as Administrator.")

    except psutil.Error as error:
        print(f"[!] psutil error: {error}")

    return connection_table


def print_connection_table(table):
    """
    Display the current process/connection mapping.
    """

    print("\n" + "=" * 95)

    print(
        f"{'Protocol':<10}"
        f"{'Local Address':<32}"
        f"{'PID':<10}"
        f"{'Process':<35}"
    )

    print("=" * 95)

    for (protocol, ip, port), (pid, process_name) in sorted(
        table.items()
    ):

        local_address = f"{ip}:{port}"

        print(
            f"{protocol:<10}"
            f"{local_address:<32}"
            f"{pid:<10}"
            f"{process_name:<35}"
        )


def main():
    """
    Continuously refresh the connection table every second.
    """

    print("Windows Network Connection Correlation Engine")
    print("Press Ctrl+C to stop.\n")

    try:

        while True:

            table = build_connection_table()

            # Clear the Windows terminal
            print("\033[2J\033[H", end="")

            print("Windows Network Connection Correlation Engine")
            print("Press Ctrl+C to stop.")

            print_connection_table(table)

            print(
                f"\nActive mapped connections: {len(table)}"
            )

            print("Refreshing every 1 second...")

            time.sleep(1)

    except KeyboardInterrupt:

        print("\n[+] Connection monitor stopped.")


if __name__ == "__main__":
    main()