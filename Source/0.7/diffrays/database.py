import sqlite3
import zlib
from diffrays.log import get_logger

logger = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_version TEXT NOT NULL,
    function_name TEXT NOT NULL,
    pseudocode BLOB NOT NULL,
    UNIQUE(binary_version, function_name)  -- ← ADD THIS LINE TO PREVENT DUPLICATES
);
"""

def compress_pseudo(pseudo_lines: list[str]) -> bytes:
    text = "\n".join(pseudo_lines)
    return zlib.compress(text.encode("utf-8"))

def decompress_pseudo(blob: bytes) -> str:
    return zlib.decompress(blob).decode("utf-8")

def init_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.execute(SCHEMA)
    conn.commit()
    return conn

def insert_function(conn, version: str, name: str, pseudocode: bytes):
    logger.info(f"Inserting function: {name} ({version})")
    try:
        conn.execute(
            "INSERT INTO functions (binary_version, function_name, pseudocode) VALUES (?, ?, ?)",
            (version, name, pseudocode),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Handle duplicate entry gracefully
        logger.warning(f"Duplicate function skipped: {name} ({version})")
        # Optionally, you can update the existing entry instead:
        # conn.execute(
        #     "UPDATE functions SET pseudocode = ? WHERE binary_version = ? AND function_name = ?",
        #     (pseudocode, version, name),
        # )
        # conn.commit()