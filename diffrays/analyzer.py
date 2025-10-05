#!/usr/bin/env python3

import re
import time
import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.names import DemangleFlags, SetNameFlags
from diffrays.database import insert_function, insert_function_with_meta, compress_pseudo, init_db, upsert_binary_metadata, compute_and_store_diffs
from diffrays.explorer import explore_database
from diffrays.log import log

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


def sanitize_filename(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def analyze_binary(db_path: str, version: str, debug: bool = False):
    """Analyze binary and yield (function_name, compressed_pseudocode) for the given version"""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Convert generator to list to get the total count
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

                # Convert generator to list for basic block count
                bb_count = len(db.functions.get_flowchart(func))
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

                yield name, compressed, func.start_ea, bb_count, signature

            except Exception as e:
                if debug:
                    log.error(f"Error processing function {func}: {e}")
                continue

        if debug:
            print()  # newline after final progress


def run_diff(old_path, new_path, db_path):
    start_ts = time.perf_counter()
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

        log.info(f"Decompiling {old_path}")

        # Count total OLD functions - convert generator to list first
        old_total = 0
        try:
            with ida_domain.Database.open(old_path, IdaCommandOptions(auto_analysis=True), False) as db:
                old_total = len(list(db.functions.get_all()))
        except Exception as e:
            log.warning(f"Could not count functions in {old_path}: {e}")

        old_count = 0
        print()
        for name, compressed, addr, blocks, signature in analyze_binary(old_path, "old"):
            try:
                insert_function_with_meta(conn, "old", name, compressed, addr, blocks, signature)
            except Exception:
                insert_function(conn, "old", name, compressed)
            old_count += 1
            
            print(f"[*] Exporting functions from {old_path} : {old_count}/{old_total}", end="\r", flush=True)

        log.info(f"Decompiled {old_count} functions from old binary")
        
        print()
        print("-"*100)
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

        log.info(f"Decompiling {new_path}")

        # Count total NEW functions - convert generator to list first
        new_total = 0
        try:
            with ida_domain.Database.open(new_path, IdaCommandOptions(auto_analysis=True), False) as db:
                new_total = len(list(db.functions.get_all()))
        except Exception as e:
            log.warning(f"Could not count functions in {new_path}: {e}")

        new_count = 0
        print()
        for name, compressed, addr, blocks, signature in analyze_binary(new_path, "new"):
            try:
                insert_function_with_meta(conn, "new", name, compressed, addr, blocks, signature)
            except Exception:
                insert_function(conn, "new", name, compressed)
            new_count += 1
            print(f"[*] Exporting functions from {new_path} : {new_count}/{new_total}", end="\r", flush=True)

        print()
        print("-"*100)
        log.info(f"Decompiled {new_count} functions from new binary")
        log.info(f"Total functions processed: {old_count + new_count}")

        # After exporting functions, compute and store diffs to a dedicated table
        try:
            log.info("Computing diffs and populating diff_results table ...")
            compute_and_store_diffs(conn)
            log.info("Diff computation completed")
        except Exception as e:
            log.error(f"Failed to compute/store diffs: {e}")

    except Exception as e:
        log.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        conn.close()
        print()
        print(f"[+] Database written to {db_path}")
        elapsed = time.perf_counter() - start_ts
        hours, remainder = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            print(f"[+] Time taken: {hours}h {minutes}m {seconds}s")
        elif minutes > 0:
            print(f"[+] Time taken: {minutes}m {seconds}s")
        else:
            print(f"[+] Time taken: {seconds}s")
