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

-- Wide schema optimized for exploration and diffing
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

CREATE TABLE IF NOT EXISTS binaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_version TEXT NOT NULL CHECK(binary_version IN ('old','new')),
    address_min INTEGER,
    address_max INTEGER,
    function_count INTEGER,
    metadata_blob BLOB NOT NULL,
    UNIQUE(binary_version)
);
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
        # Ensure wide table exists (older DBs may miss it)
        conn.execute("CREATE TABLE IF NOT EXISTS function_diffs (\n"
                     "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                     "    function_name TEXT NOT NULL,\n"
                     "    old_pseudocode BLOB,\n"
                     "    new_pseudocode BLOB,\n"
                     "    old_address INTEGER,\n"
                     "    new_address INTEGER,\n"
                     "    old_blocks INTEGER,\n"
                     "    new_blocks INTEGER,\n"
                     "    old_signature TEXT,\n"
                     "    new_signature TEXT,\n"
                     "    ratio REAL,\n"
                     "    s_ratio REAL,\n"
                     "    UNIQUE(function_name)\n"
                     ")")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_function_diffs_name ON function_diffs(function_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_function_diffs_ratio ON function_diffs(ratio)")
    except Exception as e:
        log.warning(f"Could not run PRAGMA table_info migration checks: {e}")
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


def bulk_upsert_function_diffs(conn, rows: list[tuple]):
    """
    Upsert multiple rows into function_diffs in a single transaction.
    Row tuple order:
    (
        function_name,
        old_pseudocode,
        new_pseudocode,
        old_address,
        new_address,
        old_blocks,
        new_blocks,
        old_signature,
        new_signature,
        ratio,
        s_ratio,
    )
    """
    if not rows:
        return
    sql = (
        "INSERT INTO function_diffs (function_name, old_pseudocode, new_pseudocode, old_address, new_address, "
        "old_blocks, new_blocks, old_signature, new_signature, ratio, s_ratio) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(function_name) DO UPDATE SET "
        "old_pseudocode=excluded.old_pseudocode, "
        "new_pseudocode=excluded.new_pseudocode, "
        "old_address=excluded.old_address, "
        "new_address=excluded.new_address, "
        "old_blocks=excluded.old_blocks, "
        "new_blocks=excluded.new_blocks, "
        "old_signature=excluded.old_signature, "
        "new_signature=excluded.new_signature, "
        "ratio=excluded.ratio, "
        "s_ratio=excluded.s_ratio"
    )
    cur = conn.cursor()
    cur.executemany(sql, rows)
    conn.commit()
