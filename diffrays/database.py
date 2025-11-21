import sqlite3
import zlib
import re
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

CREATE TABLE IF NOT EXISTS matched_pairs (
    old_name TEXT NOT NULL,
    new_name TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (old_name, new_name)
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
        # Basic columns
        if "address" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN address INTEGER")
        if "blocks" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN blocks INTEGER")
        if "signature" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN signature TEXT")
        # CFG features
        if "nodes" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN nodes INTEGER DEFAULT 0")
        if "edges" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN edges INTEGER DEFAULT 0")
        if "indegree" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN indegree INTEGER DEFAULT 0")
        if "outdegree" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN outdegree INTEGER DEFAULT 0")
        if "cyclomatic_complexity" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN cyclomatic_complexity INTEGER DEFAULT 0")
        # Instruction features
        if "instruction_count" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN instruction_count INTEGER DEFAULT 0")
        if "mnemonics" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN mnemonics TEXT DEFAULT ''")
        if "mnemonics_spp" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN mnemonics_spp TEXT DEFAULT ''")
        # Hashes
        if "bytes_hash" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN bytes_hash TEXT DEFAULT ''")
        if "function_hash" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN function_hash TEXT DEFAULT ''")
        if "pseudocode_hash" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN pseudocode_hash TEXT DEFAULT ''")
        if "pseudocode_hash1" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN pseudocode_hash1 TEXT DEFAULT ''")
        if "pseudocode_hash2" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN pseudocode_hash2 TEXT DEFAULT ''")
        if "pseudocode_hash3" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN pseudocode_hash3 TEXT DEFAULT ''")
        # Pseudocode
        if "pseudocode_lines" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN pseudocode_lines INTEGER DEFAULT 0")
        if "clean_pseudocode" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN clean_pseudocode TEXT DEFAULT ''")
        # Assembly
        if "assembly" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN assembly TEXT DEFAULT ''")
        if "clean_assembly" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN clean_assembly TEXT DEFAULT ''")
        # Constants
        if "constants" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN constants TEXT DEFAULT ''")
        if "constants_count" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN constants_count INTEGER DEFAULT 0")
        # Other features
        if "rva" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN rva INTEGER DEFAULT 0")
        if "segment_rva" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN segment_rva INTEGER DEFAULT 0")
        if "md_index" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN md_index TEXT DEFAULT ''")
        if "kgh_hash" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN kgh_hash TEXT DEFAULT ''")
        if "primes_value" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN primes_value TEXT DEFAULT ''")
        if "pseudocode_primes" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN pseudocode_primes TEXT DEFAULT ''")
        # Basic block hashes (for Ghidra-style correlation)
        if "block_hashes" not in cols:
            to_add.append("ALTER TABLE functions ADD COLUMN block_hashes TEXT DEFAULT '[]'")
        
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


def insert_function_with_features(conn, version: str, name: str, pseudocode: bytes, features):
    """
    Insert function with all extracted features.
    features should be a FunctionFeatures object from heuristics.py
    If features is None or invalid, falls back to basic insertion.
    """
    from diffrays.heuristics import FunctionFeatures
    
    if not isinstance(features, FunctionFeatures):
        log.warning(f"Invalid or missing features for {name}, falling back to basic insertion")
        # Fall back to basic insertion - we'll use address from features if available, otherwise 0
        address = getattr(features, 'address', 0) if features else 0
        blocks = getattr(features, 'nodes', 0) if features else 0
        signature = getattr(features, 'signature', '') if features else ''
        insert_function_with_meta(conn, version, name, pseudocode, address, blocks, signature)
        return
    
    try:
        # Compress pseudocode if it's a string
        if isinstance(pseudocode, str):
            pseudocode = compress_pseudo(pseudocode.split('\n'))
        
        conn.execute(
            """
            INSERT INTO functions (
                binary_version, function_name, pseudocode, address, blocks, signature,
                nodes, edges, indegree, outdegree, cyclomatic_complexity,
                instruction_count, mnemonics, mnemonics_spp,
                bytes_hash, function_hash, pseudocode_hash,
                pseudocode_hash1, pseudocode_hash2, pseudocode_hash3,
                pseudocode_lines, clean_pseudocode,
                assembly, clean_assembly,
                constants, constants_count,
                rva, segment_rva, md_index, kgh_hash,
                primes_value, pseudocode_primes, block_hashes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                version, name, pseudocode, features.address, features.nodes, features.signature,
                features.nodes, features.edges, features.indegree, features.outdegree, features.cyclomatic_complexity,
                features.instruction_count, features.mnemonics, features.mnemonics_spp,
                features.bytes_hash, features.function_hash, features.pseudocode_hash,
                features.pseudocode_hash1, features.pseudocode_hash2, features.pseudocode_hash3,
                features.pseudocode_lines, features.clean_pseudocode,
                features.assembly, features.clean_assembly,
                features.constants, features.constants_count,
                features.rva, features.segment_rva, features.md_index, features.kgh_hash,
                features.primes_value, features.pseudocode_primes, features.block_hashes
            ),
        )
        conn.commit()
        log.debug(f"Inserted function with features: {name} ({version})")
    except sqlite3.IntegrityError:
        log.warning(f"Duplicate function skipped: {name} ({version})")
    except Exception as e:
        log.error(f"Failed to insert function with features {name}: {e}")

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


def _compute_smart_ratio(
    text_old: str | None, 
    text_new: str | None, 
    blocks_old: int | None, 
    blocks_new: int | None,
    block_hashes_old: str | None = None,
    block_hashes_new: str | None = None
) -> float:
    """
    Compute smart ratio using Ghidra-style basic block correlation when available.
    
    Falls back to the original block-count-based approach if block hashes aren't available.
    """
    try:
        # Try to use Ghidra-style correlator if block hashes are available
        if block_hashes_old and block_hashes_new:
            try:
                import json
                from diffrays.correlator import compute_correlation_from_hashes
                
                hashes_old = json.loads(block_hashes_old) if isinstance(block_hashes_old, str) else block_hashes_old
                hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                
                if hashes_old and hashes_new:
                    # Compute correlation score (0.0 to 1.0, where 1.0 = identical)
                    correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                    # Convert to change score (0.0 = unchanged, higher = more changed)
                    change_score = 1.0 - correlation
                    return change_score
            except Exception as e:
                # Fall through to original method if correlation fails
                import logging
                logging.getLogger(__name__).debug(f"Block hash correlation failed, using fallback: {e}")
        
        # Fallback to original block-count-based approach
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


_SUB_RE = re.compile(r'sub_[0-9A-Fa-f]+')
_PTR_RE = re.compile(r'\b(?:dword|word|byte|off|unk)_[0-9A-Fa-f]+\b')
_ADDR_NUM_RE = re.compile(r'0x[0-9A-Fa-f]+')


def _normalize_pseudocode(text: str) -> str:
    if not text:
        return ""
    normalized = _SUB_RE.sub('sub_', text)
    normalized = _PTR_RE.sub('ptr_', normalized)
    normalized = _ADDR_NUM_RE.sub('0xADDR', normalized)
    return normalized


def _record_matched_pair(conn: sqlite3.Connection, old_name: str, new_name: str, status: str = "unchanged"):
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO matched_pairs (old_name, new_name, status)
            VALUES (?, ?, ?)
            """,
            (old_name, new_name, status),
        )
    except Exception as e:
        log.warning(f"Failed to record matched pair {old_name} -> {new_name}: {e}")


def compute_and_store_diffs(conn: sqlite3.Connection, use_heuristics: bool = True):
    """
    Populate diff_results with pairs that exist in both old and new and differ.
    Leaves unmatched and unchanged entries in the original functions table.
    
    If use_heuristics is True, uses heuristic-based matching instead of name-only matching.
    """
    # Reset matched pairs table for fresh analysis
    try:
        conn.execute("DELETE FROM matched_pairs")
        conn.commit()
    except Exception as e:
        log.warning(f"Failed to reset matched_pairs table: {e}")

    if use_heuristics:
        # Use heuristic-based matching
        from diffrays.matcher import HeuristicMatcher
        
        print("\n[+] Using heuristic-based function matching...")
        matcher = HeuristicMatcher(conn)
        matches = matcher.find_matches()
        
        print(f"[+] Found {len(matches)} matched function pairs using heuristics")
        
        if not matches:
            print("[+] No matched functions found. Skipping diff computation.")
            return
        
        # Process matches
        names = []
        for match in matches:
            names.append((match.old_name, match.new_name))
    else:
        # Name-based matching: only match functions with identical names
        # This is faster and works well when symbols are available (e.g., Windows binaries)
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
        names = [(r[0], r[0]) for r in cursor.fetchall()]  # (old_name, new_name) pairs
        print(f"[+] Total matched functions: {len(names)}")
        if not names:
            print("[+] No matched functions found. Skipping diff computation.")
            print("[!] Tip: Use --heuristic flag to match functions even when names differ")
            return

    inserted_names: list[str] = []
    skipped_matches = []
    unchanged_count = 0
    for name_pair in names:
        old_name, new_name = name_pair if isinstance(name_pair, tuple) else (name_pair, name_pair)
        
        # Fetch both rows parameterized
        old_row = conn.execute(
            "SELECT pseudocode, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'old'",
            (old_name,),
        ).fetchone()
        new_row = conn.execute(
            "SELECT pseudocode, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'new'",
            (new_name,),
        ).fetchone()
        if not old_row:
            log.warning(f"Matched function '{old_name}' not found in functions table (old version)")
            skipped_matches.append((old_name, new_name, "old_not_found"))
            continue
        if not new_row:
            log.warning(f"Matched function '{new_name}' not found in functions table (new version)")
            skipped_matches.append((old_name, new_name, "new_not_found"))
            continue
        try:
            text_old = decompress_pseudo(old_row[0]) if old_row[0] is not None else None
            text_new = decompress_pseudo(new_row[0]) if new_row[0] is not None else None
        except Exception as e:
            log.warning(f"Failed to decompress pseudocode for match {old_name} <-> {new_name}: {e}")
            skipped_matches.append((old_name, new_name, "decompress_error"))
            continue
        # Log if pseudocode is missing but continue processing so matches are still counted
        if not text_old:
            log.warning(f"Old pseudocode is empty for matched function '{old_name}'")
        if not text_new:
            log.warning(f"New pseudocode is empty for matched function '{new_name}'")
        if not text_old or not text_new:
            text_old = text_old or ""
            text_new = text_new or ""
        # Get block hashes for Ghidra-style correlation
        block_hashes_old = None
        block_hashes_new = None
        try:
            old_hash_row = conn.execute(
                "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'old'",
                (old_name,)
            ).fetchone()
            new_hash_row = conn.execute(
                "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'new'",
                (new_name,)
            ).fetchone()
            if old_hash_row:
                block_hashes_old = old_hash_row[0]
            if new_hash_row:
                block_hashes_new = new_hash_row[0]
        except Exception as e:
            log.debug(f"Could not fetch block hashes: {e}")
        
        # Calculate ratio and modification level
        norm_old = _normalize_pseudocode(text_old)
        norm_new = _normalize_pseudocode(text_new)
        ratio = _safe_ratio(norm_old, norm_new)
        smart = _compute_smart_ratio(norm_old, norm_new, old_row[2], new_row[2], block_hashes_old, block_hashes_new)
        modification_score = 1.0 - ratio
        level = _determine_modification_level(modification_score)
        
        # Check if this is an import thunk with no pseudocode (ratio = 0.000)
        # Import thunks typically have no pseudocode and should be treated as unchanged
        is_import_thunk = (old_name.startswith("__imp_") or old_name.startswith("_imp_") or 
                          new_name.startswith("__imp_") or new_name.startswith("_imp_"))
        
        # Only store in diff_results if the function has actually changed
        # Unchanged functions should remain in the functions table
        if ratio >= 0.999 or level == "unchanged" or (is_import_thunk and ratio <= 0.001):
            if old_name != new_name:
                _record_matched_pair(conn, old_name, new_name, "unchanged")
            # Function is unchanged - leave it in functions table, don't move to diff_results
            unchanged_count += 1
            log.debug(f"Function {old_name} <-> {new_name} is unchanged (ratio={ratio:.3f}, is_import_thunk={is_import_thunk}), leaving in functions table")
            continue
        
        # Use old_name as the primary function name for diff_results
        # (or use new_name if they're different - you may want to adjust this)
        result_name = old_name if old_name == new_name else f"{old_name} -> {new_name}"
        
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
                    result_name,
                    old_row[0], new_row[0],
                    old_row[1], new_row[1],
                    old_row[2], new_row[2],
                    old_row[3], new_row[3],
                    ratio, smart, level,
                ),
            )
            inserted_names.append(result_name)
        except Exception as e:
            log.warning(f"Failed inserting diff_results for {result_name}: {e}")
    conn.commit()

    print(f"[+] Diff computation completed:")
    print(f"    - {len(inserted_names)} changed functions stored in diff_results")
    print(f"    - {unchanged_count} unchanged functions left in functions table")
    if skipped_matches:
        print(f"[!] Warning: {len(skipped_matches)} matched function pairs were skipped (check logs for details)")

    if inserted_names:
        # Delete matched CHANGED rows from functions table
        # Note: Unchanged functions are left in functions table
        # For heuristic matches, we need to delete both old and new names, but only for changed functions
        try:
            names_to_delete = set()
            # Only delete functions that were actually stored in diff_results (i.e., changed)
            for result_name in inserted_names:
                # Handle function names like "old_name -> new_name" from heuristic matching
                if " -> " in result_name:
                    parts = result_name.split(" -> ", 1)
                    names_to_delete.add(parts[0])
                    names_to_delete.add(parts[1])
                else:
                    names_to_delete.add(result_name)
            
            if names_to_delete:
                conn.executemany(
                    "DELETE FROM functions WHERE function_name = ?",
                    [(n,) for n in names_to_delete],
                )
                conn.commit()
                log.info(f"Deleted {len(names_to_delete)} changed function entries from functions table")
        except Exception as e:
            log.warning(f"Failed to prune matched rows from functions: {e}")
