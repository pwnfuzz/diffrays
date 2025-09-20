#!/usr/bin/env python3

import re
import difflib
import traceback
import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.names import DemangleFlags, SetNameFlags
from diffrays.database import (
    insert_function,
    insert_function_with_meta,
    compress_pseudo,
    init_db,
    upsert_binary_metadata,
    bulk_upsert_function_diffs,
)
from diffrays.explorer import explore_database
from diffrays.log import log

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


def sanitize_filename(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def analyze_binary_collect(db_path: str, version: str, debug: bool = False):
    """Analyze binary and return a dict of function_name -> metadata and compressed pseudocode.

    Returns: dict[name] = {
        'text': str, 'compressed': bytes, 'address': int, 'blocks': int, 'signature': str
    }
    """
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    results = {}
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        functions = list(db.functions.get_all())
        total_functions = len(functions)
        analyzed_count = 0

        for func in functions:
            try:
                name = db.functions.get_name(func)
                demangled = db.names.demangle_name(name, DemangleFlags.NODEFINIT)
                if demangled:
                    name = demangled
                    if debug:
                        log.debug(f"Demangled Function: {name}")

                bb_count = len(list(db.functions.get_basic_blocks(func)))
                signature = db.functions.get_signature(func)
                pseudo_lines = db.functions.get_pseudocode(func)
                if not pseudo_lines:
                    if debug:
                        log.warning(f"No pseudocode for function: {name}")
                    continue

                text = "\n".join(pseudo_lines)
                compressed = compress_pseudo(pseudo_lines)

                results[name] = {
                    "text": text,
                    "compressed": compressed,
                    "address": getattr(func, 'start_ea', None),
                    "blocks": bb_count,
                    "signature": signature,
                }

                analyzed_count += 1
                if debug:
                    print(f"\rFunctions Analyzed: {analyzed_count}/{total_functions}", end="", flush=True)

            except Exception as e:
                if debug:
                    log.error(f"Error processing function {func}: {e}")
                continue

        if debug:
            print()  # newline after final progress

    return results


def run_diff(old_path, new_path, db_path):
    """Run binary diff analysis with robust error handling and wide-table population."""
    print("Starting binary diff...")

    conn = None
    try:
        conn = init_db(db_path)

        # Explore and save metadata for OLD/NEW
        try:
            old_info = explore_database(old_path)
            upsert_binary_metadata(
                conn,
                "old",
                old_info["minimum_ea"],
                old_info["maximum_ea"],
                old_info["function_count"],
                old_info["compressed_blob"],
            )
            log.info(f"Analyzing {old_path}")
        except Exception as e:
            log.error(f"Failed to explore/save OLD metadata: {e}")
            traceback.print_exc()

        try:
            new_info = explore_database(new_path)
            upsert_binary_metadata(
                conn,
                "new",
                new_info["minimum_ea"],
                new_info["maximum_ea"],
                new_info["function_count"],
                new_info["compressed_blob"],
            )
            log.info(f"Analyzing {new_path}")
        except Exception as e:
            log.error(f"Failed to explore/save NEW metadata: {e}")
            traceback.print_exc()

        # Collect functions for OLD and NEW
        old_map = analyze_binary_collect(old_path, "old")
        new_map = analyze_binary_collect(new_path, "new")

        # Also backfill tall schema for compatibility using efficient transaction
        try:
            conn.execute("BEGIN")
            for name, meta in old_map.items():
                try:
                    insert_function_with_meta(conn, "old", name, meta["compressed"], meta["address"], meta["blocks"], meta["signature"])
                except Exception:
                    insert_function(conn, "old", name, meta["compressed"])  # best-effort
            for name, meta in new_map.items():
                try:
                    insert_function_with_meta(conn, "new", name, meta["compressed"], meta["address"], meta["blocks"], meta["signature"])
                except Exception:
                    insert_function(conn, "new", name, meta["compressed"])  # best-effort
            conn.commit()
        except Exception:
            conn.rollback()

        # Build unified set of names and compute ratios
        all_names = set(old_map.keys()) | set(new_map.keys())
        rows = []
        for name in all_names:
            o = old_map.get(name)
            n = new_map.get(name)
            old_text = o["text"] if o else None
            new_text = n["text"] if n else None
            # Compute diffs efficiently; if either missing, treat as full change
            if old_text and new_text:
                sm = difflib.SequenceMatcher(None, old_text, new_text)
                ratio_sim = sm.ratio()  # 0..1 similarity
                quick_sim = sm.quick_ratio()
                ratio = 1.0 - ratio_sim
                s_ratio = 1.0 - quick_sim
            else:
                ratio = 1.0
                s_ratio = 1.0

            row = (
                name,
                (o["compressed"] if o else None),
                (n["compressed"] if n else None),
                (o["address"] if o else None),
                (n["address"] if n else None),
                (o["blocks"] if o else None),
                (n["blocks"] if n else None),
                (o["signature"] if o else None),
                (n["signature"] if n else None),
                float(ratio),
                float(s_ratio),
            )
            rows.append(row)

        # Bulk upsert into wide table
        bulk_upsert_function_diffs(conn, rows)

        log.info(f"Wide table populated: {len(rows)} functions")

    except Exception as e:
        log.error(f"Critical error in run_diff: {e}")
        traceback.print_exc()

    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                log.error(f"Error closing DB connection: {e}")
                traceback.print_exc()

        print(f"Database written to {db_path}")
