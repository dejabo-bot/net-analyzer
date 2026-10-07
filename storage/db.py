import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "net_analyzer.db"


def get_connection():
    """
    Create and return a SQLite database connection.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DB_PATH,
        timeout=30
    )

    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA foreign_keys=ON;")

    return connection


def init_db():
    """
    Create all required database tables and indexes.
    """

    connection = get_connection()

    cursor = connection.cursor()

    # ---------------------------------------------------------
    # FLOWS
    # ---------------------------------------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            start_ts TEXT NOT NULL,
            end_ts TEXT,

            protocol TEXT NOT NULL,

            src_ip TEXT NOT NULL,
            src_port INTEGER,

            dst_ip TEXT NOT NULL,
            dst_port INTEGER,

            pid INTEGER,
            process_name TEXT,

            packets INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,

            last_seen_ts TEXT NOT NULL
        )
        """
    )

    # ---------------------------------------------------------
    # 1 SECOND ROLLUPS
    # ---------------------------------------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS rollups_1s (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            protocol TEXT NOT NULL,

            process_name TEXT,

            pid INTEGER,

            packets INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    # ---------------------------------------------------------
    # DNS OBSERVATIONS
    # ---------------------------------------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            process_name TEXT,
            pid INTEGER,

            src_ip TEXT,
            src_port INTEGER,

            dns_server TEXT,
            query_name TEXT
        )
        """
    )

    # ---------------------------------------------------------
    # INDEXES
    # ---------------------------------------------------------

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_flows_process
        ON flows(process_name)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_flows_pid
        ON flows(pid)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_flows_start
        ON flows(start_ts)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_rollups_timestamp
        ON rollups_1s(timestamp)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dns_timestamp
        ON dns_observations(timestamp)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dns_query
        ON dns_observations(query_name)
        """
    )

    connection.commit()
    connection.close()

    print(f"[+] Database initialized: {DB_PATH}")


if __name__ == "__main__":
    init_db()