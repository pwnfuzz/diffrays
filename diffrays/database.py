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

CREATE TABLE IF NOT EXISTS diff_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_name TEXT NOT NULL,
    old_pseudocode BLOB NOT NULL,
    new_pseudocode BLOB NOT NULL,
    old_address INTEGER,
    new_address INTEGER,
    old_blocks INTEGER,
    new_blocks INTEGER,
    old_signature TEXT,
    new_signature TEXT,
    ratio REAL,
    smart_ratio REAL,
    modification_level TEXT,
    UNIQUE(function_name)
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
        # Ensure diff_results table exists (older DBs won't have it)
        conn.execute("CREATE TABLE IF NOT EXISTS diff_results (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    function_name TEXT NOT NULL,\n    old_pseudocode BLOB NOT NULL,\n    new_pseudocode BLOB NOT NULL,\n    old_address INTEGER,\n    new_address INTEGER,\n    old_blocks INTEGER,\n    new_blocks INTEGER,\n    old_signature TEXT,\n    new_signature TEXT,\n    ratio REAL,\n    smart_ratio REAL,\n    modification_level TEXT,\n    UNIQUE(function_name)\n)")
        # Add modification_level column if it doesn't exist (migration)
        try:
            # Check if modification_level column exists
            cols = {r[1] for r in conn.execute("PRAGMA table_info(diff_results)").fetchall()}
            if "modification_level" not in cols:
                conn.execute("ALTER TABLE diff_results ADD COLUMN modification_level TEXT")
                log.info("Added modification_level column to diff_results table")
        except Exception as e:
            log.warning(f"Could not add modification_level column: {e}")
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


def _safe_ratio(a: str | None, b: str | None) -> float:
    try:
        import difflib
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0
        return difflib.SequenceMatcher(None, a, b).ratio()
    except Exception:
        return 0.0


def _compute_smart_ratio(text_old: str | None, text_new: str | None, blocks_old: int | None, blocks_new: int | None) -> float:
    try:
        base_sim = _safe_ratio(text_old, text_new)
        if blocks_old is None or blocks_new is None:
            return 1.0 - base_sim
        if blocks_old == 0 or blocks_new == 0:
            return 1.0 - base_sim
        
        delta_blocks = abs(blocks_old - blocks_new)
        
        if delta_blocks == 0:
            change_score = (1.0 - base_sim) * 0.05  # Very low for no block changes
        else:
            # Use absolute block delta as primary score
            block_score = delta_blocks / 50.0  # Scale down for readability
            text_score = (1.0 - base_sim) * 0.2
            change_score = block_score + text_score
        
        return change_score
    except Exception:
        return 0.0


def _determine_modification_level(score: float) -> str:
    """Categorize the modification level based on score"""
    if score == 0.0:
        return "unchanged"
    elif score < 0.1:
        return "minor"
    elif score < 0.3:
        return "moderate"
    elif score < 0.6:
        return "significant"
    else:
        return "major"


def compute_and_store_diffs(conn: sqlite3.Connection):
    """
    Populate diff_results with pairs that exist in both old and new and differ.
    Leaves unmatched and unchanged entries in the original functions table.
    """
    # Find candidate names with both versions
    cursor = conn.execute(
        """
        SELECT f_old.function_name
        FROM functions AS f_old
        INNER JOIN functions AS f_new
            ON f_new.function_name = f_old.function_name
           AND f_new.binary_version = 'new'
        WHERE f_old.binary_version = 'old'
        """
    )
    names = [r[0] for r in cursor.fetchall()]
    print("\n[+] Preparing diff computation …")
    print(f"[+] Total matched functions: {len(names)}")
    if not names:
        print("[+] No matched functions found. Skipping diff computation.")
        return

    inserted_names: list[str] = []
    for name in names:
        # Fetch both rows parameterized
        old_row = conn.execute(
            "SELECT pseudocode, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'old'",
            (name,),
        ).fetchone()
        new_row = conn.execute(
            "SELECT pseudocode, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'new'",
            (name,),
        ).fetchone()
        if not old_row or not new_row:
            continue
        try:
            text_old = decompress_pseudo(old_row[0]) if old_row[0] is not None else None
            text_new = decompress_pseudo(new_row[0]) if new_row[0] is not None else None
        except Exception:
            # Skip corrupt entries
            continue
        # Only store when contents differ
        if not text_old or not text_new or text_old == text_new:
            continue
        ratio = _safe_ratio(text_old, text_new)
        smart = _compute_smart_ratio(text_old, text_new, old_row[2], new_row[2])
        modification_score = 1.0 - ratio
        level = _determine_modification_level(modification_score)
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO diff_results (
                    function_name,
                    old_pseudocode, new_pseudocode,
                    old_address, new_address,
                    old_blocks, new_blocks,
                    old_signature, new_signature,
                    ratio, smart_ratio, modification_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    old_row[0], new_row[0],
                    old_row[1], new_row[1],
                    old_row[2], new_row[2],
                    old_row[3], new_row[3],
                    ratio, smart, level,
                ),
            )
            inserted_names.append(name)
        except Exception as e:
            log.warning(f"Failed inserting diff_results for {name}: {e}")
    conn.commit()

    print(f"[+] Diff computation completed, found {len(inserted_names)} functions as changed")

    if inserted_names:
        # Delete matched rows from functions (leave unmatched and unchanged)
        try:
            conn.executemany(
                "DELETE FROM functions WHERE function_name = ?",
                [(n,) for n in inserted_names],
            )
            conn.commit()
        except Exception as e:
            log.warning(f"Failed to prune matched rows from functions: {e}")
