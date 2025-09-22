import sqlite3
import zlib
from diffrays.log import log


# Initialize global logger (defaults to INFO on console)


SCHEMA = """
CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_version TEXT NOT NULL,
    function_name TEXT NOT NULL,
    pseudocode BLOB NOT NULL,
    address INTEGER,
    blocks INTEGER,
    signature TEXT,
    UNIQUE(binary_version, function_name)
);

CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_version TEXT NOT NULL CHECK(binary_version IN ('old','new')),
    address_min INTEGER,
    address_max INTEGER,
    function_count INTEGER,
    metadata_blob BLOB NOT NULL,
    UNIQUE(binary_version)
);

CREATE TABLE IF NOT EXISTS function_diffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_name TEXT NOT NULL,
    old_pseudocode BLOB,
    new_pseudocode BLOB,
    old_address INTEGER,
    new_address INTEGER,
    old_blocks INTEGER,
    new_blocks INTEGER,
    old_signature TEXT,
    new_signature TEXT,
    ratio REAL,
    s_ratio REAL,
    UNIQUE(function_name)
);

CREATE INDEX IF NOT EXISTS idx_function_diffs_name ON function_diffs(function_name);
CREATE INDEX IF NOT EXISTS idx_function_diffs_ratio ON function_diffs(ratio);
"""

def compress_pseudo(pseudo_lines: list[str]) -> bytes:
    text = "\n".join(pseudo_lines)
    return zlib.compress(text.encode("utf-8"))

def decompress_pseudo(blob: bytes) -> str:
    return zlib.decompress(blob).decode("utf-8")

def init_db(db_path: str):
    
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    # Lightweight migration: add new columns if they don't exist yet
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)").fetchall()}
        to_add = []
        if "address" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN address INTEGER")
        if "blocks" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN blocks INTEGER")
        if "signature" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN signature TEXT")
        for stmt in to_add:
            try:
                conn.execute(stmt)
            except Exception as e:
                log.warning(f"Migration step failed: {stmt}: {e}")
    except Exception as e:
        log.warning(f"Could not run PRAGMA table_info migration checks: {e}")
    
    # Ensure function_diffs table and indices exist
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS function_diffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_name TEXT NOT NULL,
                old_pseudocode BLOB,
                new_pseudocode BLOB,
                old_address INTEGER,
                new_address INTEGER,
                old_blocks INTEGER,
                new_blocks INTEGER,
                old_signature TEXT,
                new_signature TEXT,
                ratio REAL,
                s_ratio REAL,
                UNIQUE(function_name)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_function_diffs_name ON function_diffs(function_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_function_diffs_ratio ON function_diffs(ratio)")
    except Exception as e:
        log.warning(f"Could not create function_diffs table: {e}")
    
    conn.commit()
    return conn

def insert_function(conn, version: str, name: str, pseudocode: bytes):
    
    log.info(f"Inserting function: {name} ({version})")
    try:
        conn.execute(
            "INSERT INTO functions (binary_version, function_name, pseudocode) VALUES (?, ?, ?)",
            (version, name, pseudocode),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        log.warning(f"Duplicate function skipped: {name} ({version})")

def insert_function_with_meta(conn, version: str, name: str, pseudocode: bytes, address: int | None, blocks: int | None, signature: str | None):
    
    addr_str = hex(address) if isinstance(address, int) else address
    log.info(f"Inserting function: {name} ({version}) addr={addr_str} blocks={blocks}")
    try:
        conn.execute(
            """
            INSERT INTO functions (binary_version, function_name, pseudocode, address, blocks, signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (version, name, pseudocode, address, blocks, signature),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        log.warning(f"Duplicate function skipped: {name} ({version})")

def bulk_upsert_function_diffs(conn, rows):
    """Bulk upsert many rows into function_diffs table in one transaction"""
    try:
        conn.execute("BEGIN TRANSACTION")
        for row in rows:
            conn.execute("""
                INSERT INTO function_diffs (
                    function_name, old_pseudocode, new_pseudocode, old_address, new_address,
                    old_blocks, new_blocks, old_signature, new_signature, ratio, s_ratio
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(function_name) DO UPDATE SET
                    old_pseudocode=excluded.old_pseudocode,
                    new_pseudocode=excluded.new_pseudocode,
                    old_address=excluded.old_address,
                    new_address=excluded.new_address,
                    old_blocks=excluded.old_blocks,
                    new_blocks=excluded.new_blocks,
                    old_signature=excluded.old_signature,
                    new_signature=excluded.new_signature,
                    ratio=excluded.ratio,
                    s_ratio=excluded.s_ratio
            """, row)
        conn.commit()
        log.info(f"Bulk upserted {len(rows)} function diffs")
    except Exception as e:
        conn.rollback()
        log.error(f"Bulk upsert failed: {e}")
        raise

def upsert_binary_metadata(conn, version: str, address_min: int, address_max: int, function_count: int, metadata_blob: bytes):
    
    log.debug(f"Saving metadata for {version}: funcs={function_count}, range={hex(address_min)}-{hex(address_max)}")
    conn.execute(
        """
        INSERT INTO binaries (binary_version, address_min, address_max, function_count, metadata_blob)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(binary_version) DO UPDATE SET
            address_min=excluded.address_min,
            address_max=excluded.address_max,
            function_count=excluded.function_count,
            metadata_blob=excluded.metadata_blob
        """,
        (version, address_min, address_max, function_count, metadata_blob),
    )
    conn.commit()
