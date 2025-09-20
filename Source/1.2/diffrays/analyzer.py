#!/usr/bin/env python3

import re
import zlib
import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.names import DemangleFlags, SetNameFlags
from diffrays.database import insert_function, insert_function_with_meta, compress_pseudo, init_db, upsert_binary_metadata, bulk_upsert_function_diffs
from diffrays.explorer import explore_database
from diffrays.log import log
import difflib

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


def sanitize_filename(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def analyze_binary_collect(path: str, version: str, debug: bool = False):
    """Analyze binary and return a dict of function data for the given version"""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(path, ida_options, False) as db:
        # Convert generator to list to get the total count
        functions = list(db.functions.get_all())
        total_functions = len(functions)
        analyzed_count = 0
        result = {}

        for func in functions:
            try:
                name = db.functions.get_name(func)
                demangled = db.names.demangle_name(name, DemangleFlags.NODEFINIT)
                if demangled:
                    name = demangled
                    if debug:
                        log.debug(f"Demangled Function: {name}")

                # Convert generator to list for basic block count
                bb_count = len(list(db.functions.get_basic_blocks(func)))
                signature = db.functions.get_signature(func)
                pseudo = db.functions.get_pseudocode(func)
                if not pseudo:
                    if debug:
                        log.warning(f"No pseudocode for function: {name}")
                    continue

                compressed = compress_pseudo(pseudo)

                analyzed_count += 1
                if debug:
                    print(f"\rFunctions Analyzed: {analyzed_count}/{total_functions}", end="", flush=True)

                result[name] = {
                    'text': compressed,
                    'compressed': compressed,
                    'address': func.start_ea,
                    'blocks': bb_count,
                    'signature': signature
                }

            except Exception as e:
                if debug:
                    log.error(f"Error processing function {func}: {e}")
                continue

        if debug:
            print()  # newline after final progress
        
        return result


def run_diff(old_path, new_path, db_path):
    
    conn = init_db(db_path)
    try:
        # Explore and save OLD metadata
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
        except Exception as e:
            log.error(f"Failed to explore/save OLD metadata: {e}")
            import traceback
            traceback.print_exc()

        # Explore and save NEW metadata
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
        except Exception as e:
            log.error(f"Failed to explore/save NEW metadata: {e}")

        log.info(f"Analyzing {old_path}")
        old_functions = analyze_binary_collect(old_path, "old")
        log.info(f"Analyzed {len(old_functions)} functions from old binary")

        log.info(f"Analyzing {new_path}")
        new_functions = analyze_binary_collect(new_path, "new")
        log.info(f"Analyzed {len(new_functions)} functions from new binary")

        # Backfill the tall functions table (best-effort) in a single transaction
        log.info("Backfilling tall schema...")
        try:
            conn.execute("BEGIN TRANSACTION")
            for name, data in old_functions.items():
                try:
                    insert_function_with_meta(conn, "old", name, data['compressed'], data['address'], data['blocks'], data['signature'])
                except Exception:
                    insert_function(conn, "old", name, data['compressed'])
            for name, data in new_functions.items():
                try:
                    insert_function_with_meta(conn, "new", name, data['compressed'], data['address'], data['blocks'], data['signature'])
                except Exception:
                    insert_function(conn, "new", name, data['compressed'])
            conn.commit()
        except Exception as e:
            conn.rollback()
            log.warning(f"Failed to backfill tall schema: {e}")

        # Build unified names set and compute similarity
        all_names = set(old_functions.keys()) | set(new_functions.keys())
        log.info(f"Computing similarity for {len(all_names)} functions...")

        diff_rows = []
        for name in all_names:
            old_data = old_functions.get(name)
            new_data = new_functions.get(name)
            
            # Extract pseudocode for similarity computation
            old_pseudo = None
            new_pseudo = None
            if old_data:
                old_pseudo = old_data['compressed']
            if new_data:
                new_pseudo = new_data['compressed']
            
            # Compute similarity using difflib.SequenceMatcher
            if old_pseudo and new_pseudo:
                # Decompress for similarity computation
                old_text = zlib.decompress(old_pseudo).decode("utf-8")
                new_text = zlib.decompress(new_pseudo).decode("utf-8")
                matcher = difflib.SequenceMatcher(None, old_text, new_text)
                ratio = 1 - matcher.ratio()
                s_ratio = 1 - matcher.quick_ratio()
            else:
                # Missing one version means completely different
                ratio = 1.0
                s_ratio = 1.0

            # Prepare row for bulk upsert
            row = (
                name,
                old_pseudo,
                new_pseudo,
                old_data['address'] if old_data else None,
                new_data['address'] if new_data else None,
                old_data['blocks'] if old_data else None,
                new_data['blocks'] if new_data else None,
                old_data['signature'] if old_data else None,
                new_data['signature'] if new_data else None,
                ratio,
                s_ratio
            )
            diff_rows.append(row)

        # Bulk upsert all rows into function_diffs
        log.info(f"Bulk upserting {len(diff_rows)} function diffs...")
        bulk_upsert_function_diffs(conn, diff_rows)
        
        log.info(f"Total functions processed: {len(all_names)}")

    except Exception as e:
        log.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        conn.close()
        print(f"Database written to {db_path}")