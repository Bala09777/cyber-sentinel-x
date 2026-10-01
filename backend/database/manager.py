import sqlite3
from pathlib import Path
from contextlib import contextmanager


BASE_DIR = Path(__file__).resolve().parents[2]
DB_FILE = BASE_DIR / "data" / "cyber_sentinel_x.db"


class DatabaseManager:
    """
    Central database manager for Cyber Sentinel X.

    All backend modules should use this class
    instead of opening SQLite connections directly.
    """

    def __init__(self, db_file=None):
        self.db_file = Path(db_file or DB_FILE)

        self.db_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(
            self.db_file,
            timeout=10
        )

        connection.row_factory = sqlite3.Row

        try:
            yield connection
            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def execute(self, query, parameters=()):
        with self.connection() as connection:
            cursor = connection.execute(
                query,
                parameters
            )

            return cursor.lastrowid

    def fetch_one(self, query, parameters=()):
        with self.connection() as connection:
            row = connection.execute(
                query,
                parameters
            ).fetchone()

            return dict(row) if row else None

    def fetch_all(self, query, parameters=()):
        with self.connection() as connection:
            rows = connection.execute(
                query,
                parameters
            ).fetchall()

            return [dict(row) for row in rows]

    def insert(self, table, data):
        columns = ", ".join(data.keys())

        placeholders = ", ".join(
            ["?"] * len(data)
        )

        query = f"""
            INSERT INTO {table}
            ({columns})
            VALUES ({placeholders})
        """

        return self.execute(
            query,
            tuple(data.values())
        )

    def update(
        self,
        table,
        data,
        where_clause,
        where_parameters=()
    ):
        assignments = ", ".join(
            f"{column} = ?"
            for column in data.keys()
        )

        query = f"""
            UPDATE {table}
            SET {assignments}
            WHERE {where_clause}
        """

        parameters = (
            tuple(data.values())
            + tuple(where_parameters)
        )

        return self.execute(
            query,
            parameters
        )

    def delete(
        self,
        table,
        where_clause,
        where_parameters=()
    ):
        query = f"""
            DELETE FROM {table}
            WHERE {where_clause}
        """

        return self.execute(
            query,
            where_parameters
        )

    def count(self, table, where_clause=None, parameters=()):
        query = f"SELECT COUNT(*) AS count FROM {table}"

        if where_clause:
            query += f" WHERE {where_clause}"

        result = self.fetch_one(
            query,
            parameters
        )

        return result["count"] if result else 0

    def health_check(self):
        try:
            result = self.fetch_one(
                "SELECT 1 AS status"
            )

            return result is not None

        except Exception:
            return False


db = DatabaseManager()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - DATABASE MANAGER")
    print("=" * 60)

    print(f"Database : {DB_FILE}")

    if db.health_check():
        print("Database : ONLINE")
        print("Manager  : READY")
    else:
        print("Database : OFFLINE")
        print("Manager  : ERROR")
