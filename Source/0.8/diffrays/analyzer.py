#!/usr/bin/env python3

import re
import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.names import DemangleFlags, SetNameFlags
from diffrays.database import insert_function, insert_function_with_meta, compress_pseudo, init_db, upsert_binary_metadata
from diffrays.explorer import explore_database
from diffrays.log import get_logger

logger = get_logger(__name__)

def sanitize_filename(name):
    # Replace every character that is not a letter, number, or underscore with _
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def analyze_binary(db_path: str, version: str):
    """Analyze binary and yield (function_name, compressed_pseudocode) for the given version"""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        functions = db.functions.get_all()
        for func in functions:
            try:
                name = db.functions.get_name(func)
                demangle_named_name = db.names.demangle_name(name, DemangleFlags.NODEFINIT)
                if demangle_named_name is not None:
                    logger.debug(f'Demangled Function Name: {demangle_named_name}')
                    name = demangle_named_name

                # logger.debug(f'Address: {hex(func.start_ea)}')

                # Get basic blocks
                bb_count = 0
                for _ in db.functions.get_basic_blocks(func):
                    bb_count += 1
                # logger.debug(f'Basic blocks: {bb_count}')

                # Get signature
                signature = db.functions.get_signature(func)
                # logger.debug(f'Signature: {signature}')
                
                pseudo = db.functions.get_pseudocode(func)
                if not pseudo:
                    logger.warning(f"No pseudocode for function: {name}")
                    continue
                    
                compressed = compress_pseudo(pseudo)
                # sanitized_name = sanitize_filename(name)
                
                logger.debug(f"Processed function: {name}")
                yield name, compressed, func.start_ea, bb_count, signature
                
            except Exception as e:
                logger.error(f"Error processing function {func}: {e}")
                continue

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
            logger.error(f"Failed to explore/save OLD metadata: {e}")

        logger.info(f"Decompiling {old_path}")
        old_count = 0
        for name, compressed, addr, blocks, signature in analyze_binary(old_path, "old"):
            try:
                insert_function_with_meta(conn, "old", name, compressed, addr, blocks, signature)
            except Exception:
                # Fallback to legacy insert if schema mismatch
                insert_function(conn, "old", name, compressed)
            old_count += 1
        
        logger.info(f"Decompiled {old_count} functions from old binary")
        
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
            logger.error(f"Failed to explore/save NEW metadata: {e}")

        logger.info(f"Decompiling {new_path}")
        new_count = 0
        for name, compressed, addr, blocks, signature in analyze_binary(new_path, "new"):
            try:
                insert_function_with_meta(conn, "new", name, compressed, addr, blocks, signature)
            except Exception:
                insert_function(conn, "new", name, compressed)
            new_count += 1
        
        logger.info(f"Decompiled {new_count} functions from new binary")
        logger.info(f"Total functions processed: {old_count + new_count}")

    except Exception as e:
        logger.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        conn.close()
        print(f"Database written to {db_path}")