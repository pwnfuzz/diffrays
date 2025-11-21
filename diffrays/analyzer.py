#!/usr/bin/env python3

import re
import time
import traceback
import os
from pathlib import Path
import ida_domain
from ida_domain.database import IdaCommandOptions
from ida_domain.names import DemangleFlags, SetNameFlags
from diffrays.database import insert_function, insert_function_with_meta, insert_function_with_features, compress_pseudo, init_db, upsert_binary_metadata, compute_and_store_diffs
from diffrays.heuristics import extract_function_features
from diffrays.explorer import explore_database
from diffrays.log import log

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Error tracking statistics
class ErrorStats:
    def __init__(self):
        self.total_errors = 0
        self.function_errors = 0
        self.database_errors = 0
        self.file_errors = 0
        self.ida_errors = 0
        self.other_errors = 0
        self.error_details = []
    
    def add_error(self, error_type: str, message: str, exception: Exception = None):
        """Add an error to the statistics"""
        self.total_errors += 1
        
        if error_type == "function":
            self.function_errors += 1
        elif error_type == "database":
            self.database_errors += 1
        elif error_type == "file":
            self.file_errors += 1
        elif error_type == "ida":
            self.ida_errors += 1
        else:
            self.other_errors += 1
        
        error_detail = {
            "type": error_type,
            "message": message,
            "exception": str(exception) if exception else None,
            "timestamp": time.time()
        }
        self.error_details.append(error_detail)
        
        # Log the error
        log.error(f"[{error_type.upper()}] {message}")
        if exception:
            log.error(f"Exception details: {str(exception)}")
    
    def get_summary(self):
        """Get a summary of all errors"""
        return {
            "total_errors": self.total_errors,
            "function_errors": self.function_errors,
            "database_errors": self.database_errors,
            "file_errors": self.file_errors,
            "ida_errors": self.ida_errors,
            "other_errors": self.other_errors,
            "error_details": self.error_details
        }
    
    def log_summary(self):
        """Log error summary"""
        summary = self.get_summary()
        log.info("=== ERROR SUMMARY ===")
        log.info(f"Total errors: {summary['total_errors']}")
        log.info(f"Function processing errors: {summary['function_errors']}")
        log.info(f"Database errors: {summary['database_errors']}")
        log.info(f"File I/O errors: {summary['file_errors']}")
        log.info(f"IDA Pro errors: {summary['ida_errors']}")
        log.info(f"Other errors: {summary['other_errors']}")
        
        if summary['total_errors'] > 0:
            log.warning("Some errors occurred during analysis. Check logs for details.")
        else:
            log.info("No errors occurred during analysis.")


def sanitize_filename(name):
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def analyze_binary(db_path: str, version: str, debug: bool = False, error_stats: ErrorStats = None):
    """Analyze binary and yield (function_name, compressed_pseudocode) for the given version"""
    
    # Input validation
    if not db_path or not isinstance(db_path, str):
        error_msg = f"Invalid database path: {db_path}"
        log.error(error_msg)
        if error_stats:
            error_stats.add_error("file", error_msg)
        return
    
    if not os.path.exists(db_path):
        error_msg = f"Database file does not exist: {db_path}"
        log.error(error_msg)
        if error_stats:
            error_stats.add_error("file", error_msg)
        return
    
    log.info(f"Starting analysis of {version} binary: {db_path}")
    
    try:
        ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
        
        with ida_domain.Database.open(db_path, ida_options, False) as db:
            log.info(f"Successfully opened IDA database for {version} binary")
            
            # Convert generator to list to get the total count
            try:
                functions = list(db.functions.get_all())
                total_functions = len(functions)
                log.info(f"Found {total_functions} functions in {version} binary")
            except Exception as e:
                error_msg = f"Failed to get function list from {version} binary"
                log.error(error_msg)
                if error_stats:
                    error_stats.add_error("ida", error_msg, e)
                return
            
            analyzed_count = 0
            skipped_count = 0
            
            for func_idx, func in enumerate(functions):
                try:
                    # Get function name
                    try:
                        name = db.functions.get_name(func)
                        if not name:
                            name = f"sub_{func.start_ea:X}"
                            log.debug(f"Function at {func.start_ea:X} has no name, using default")
                    except Exception as e:
                        name = f"sub_{func.start_ea:X}"
                        log.warning(f"Failed to get name for function at {func.start_ea:X}: {e}")
                    
                    # Demangle name
                    try:
                        demangled = db.names.demangle_name(name, DemangleFlags.NODEFINIT)
                        if demangled:
                            name = demangled
                            if debug:
                                log.debug(f"Demangled Function: {name}")
                    except Exception as e:
                        log.debug(f"Failed to demangle name '{name}': {e}")
                    
                    # Get basic block count
                    try:
                        bb_count = len(db.functions.get_flowchart(func))
                    except Exception as e:
                        log.warning(f"Failed to get flowchart for function {name}: {e}")
                        bb_count = 0
                    
                    # Get function signature
                    try:
                        signature = db.functions.get_signature(func)
                        if not signature:
                            signature = ""
                    except Exception as e:
                        log.debug(f"Failed to get signature for function {name}: {e}")
                        signature = ""
                    
                    # Get pseudocode
                    pseudo = None
                    try:
                        pseudo = db.functions.get_pseudocode(func)
                        if not pseudo:
                            if debug:
                                log.debug(f"No pseudocode for function: {name}")
                            # Don't skip - insert with empty pseudocode so function is still tracked
                            pseudo = []
                    except Exception as e:
                        log.warning(f"Failed to get pseudocode for function {name}: {e}")
                        # Don't skip - insert with empty pseudocode so function is still tracked
                        pseudo = []
                    
                    # Compress pseudocode
                    try:
                        compressed = compress_pseudo(pseudo) if pseudo else compress_pseudo([""])
                        if not compressed:
                            log.warning(f"Failed to compress pseudocode for function {name}, using empty")
                            compressed = compress_pseudo([""])
                    except Exception as e:
                        log.warning(f"Failed to compress pseudocode for function {name}: {e}, using empty")
                        compressed = compress_pseudo([""])
                    
                    # Extract function features for heuristics
                    try:
                        # Get binary base address for RVA calculation
                        binary_base = db.minimum_ea if hasattr(db, 'minimum_ea') else 0
                        features = extract_function_features(db, func, binary_base)
                    except Exception as e:
                        log.warning(f"Failed to extract features for function {name}: {e}")
                        # Continue with basic features
                        features = None
                    
                    analyzed_count += 1
                    if debug:
                        print(f"\rFunctions Analyzed: {analyzed_count}/{total_functions} (Skipped: {skipped_count})", end="", flush=True)
                    
                    yield name, compressed, func.start_ea, bb_count, signature, features
                    
                except Exception as e:
                    error_msg = f"Error processing function {func_idx} at {func.start_ea:X}"
                    log.error(error_msg)
                    if error_stats:
                        error_stats.add_error("function", error_msg, e)
                    skipped_count += 1
                    continue
            
            if debug:
                print()  # newline after final progress
            
            log.info(f"Analysis completed for {version} binary: {analyzed_count} functions analyzed, {skipped_count} skipped")
            
    except FileNotFoundError as e:
        error_msg = f"Database file not found: {db_path}"
        log.error(error_msg)
        if error_stats:
            error_stats.add_error("file", error_msg, e)
    except PermissionError as e:
        error_msg = f"Permission denied accessing database: {db_path}"
        log.error(error_msg)
        if error_stats:
            error_stats.add_error("file", error_msg, e)
    except Exception as e:
        error_msg = f"Failed to open IDA database for {version} binary"
        log.error(error_msg)
        if error_stats:
            error_stats.add_error("ida", error_msg, e)
        log.error(f"Exception details: {str(e)}")
        if debug:
            traceback.print_exc()


def run_diff(old_path, new_path, db_path, debug: bool = False, use_heuristics: bool = False):
    """Run binary diff analysis between old and new binaries"""
    
    # Initialize error tracking
    error_stats = ErrorStats()
    
    # Input validation
    log.info("=== Starting DiffRays Analysis ===")
    log.info(f"Old binary: {old_path}")
    log.info(f"New binary: {new_path}")
    log.info(f"Output database: {db_path}")
    
    # Validate input files
    for path, name in [(old_path, "old"), (new_path, "new")]:
        is_valid, message = validate_binary_file(path)
        if not is_valid:
            log.error(f"{name.capitalize()} binary validation failed: {message}")
            error_stats.add_error("file", message)
            return False
        else:
            log.info(f"{name.capitalize()} binary validation passed: {path}")
    
    # Validate output directory
    output_dir = os.path.dirname(db_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            log.info(f"Created output directory: {output_dir}")
        except Exception as e:
            error_msg = f"Failed to create output directory: {output_dir}"
            log.error(error_msg)
            error_stats.add_error("file", error_msg, e)
            return False
    
    start_ts = time.perf_counter()
    
    # Initialize database
    try:
        conn = init_db(db_path)
        log.info(f"Database initialized: {db_path}")
    except Exception as e:
        error_msg = f"Failed to initialize database: {db_path}"
        log.error(error_msg)
        error_stats.add_error("database", error_msg, e)
        return False
    
    try:
        # Process OLD binary
        log.info("=== Processing OLD Binary ===")
        
        # Explore and save OLD metadata
        try:
            log.info(f"Exploring metadata for old binary: {old_path}")
            old_info = explore_database(old_path)
            upsert_binary_metadata(
                conn,
                "old",
                old_info["minimum_ea"],
                old_info["maximum_ea"],
                old_info["function_count"],
                old_info["compressed_blob"],
            )
            log.info("Successfully saved old binary metadata")
        except Exception as e:
            error_msg = f"Failed to explore/save OLD metadata: {old_path}"
            log.error(error_msg)
            error_stats.add_error("ida", error_msg, e)
            log.warning("Continuing without old binary metadata...")

        log.info(f"Decompiling {old_path}")

        # Count total OLD functions
        old_total = 0
        try:
            with ida_domain.Database.open(old_path, IdaCommandOptions(auto_analysis=True), False) as db:
                old_total = len(list(db.functions.get_all()))
                log.info(f"Found {old_total} functions in old binary")
        except Exception as e:
            error_msg = f"Could not count functions in {old_path}"
            log.warning(error_msg)
            error_stats.add_error("ida", error_msg, e)

        old_count = 0
        print()
        
        # Process old binary functions
        for result in analyze_binary(old_path, "old", debug=debug, error_stats=error_stats):
            try:
                # Handle both old format (5 items) and new format (6 items with features)
                if len(result) == 6:
                    name, compressed, addr, blocks, signature, features = result
                    if features:
                        insert_function_with_features(conn, "old", name, compressed, features)
                    else:
                        insert_function_with_meta(conn, "old", name, compressed, addr, blocks, signature)
                else:
                    name, compressed, addr, blocks, signature = result[:5]
                    insert_function_with_meta(conn, "old", name, compressed, addr, blocks, signature)
            except Exception as e:
                try:
                    name = result[0]
                    compressed = result[1]
                    insert_function(conn, "old", name, compressed)
                except Exception as e2:
                    error_msg = f"Failed to insert function {name} from old binary"
                    log.error(error_msg)
                    error_stats.add_error("database", error_msg, e2)
                    continue
            
            old_count += 1
            print(f"[*] Exporting functions from {old_path} : {old_count}/{old_total}", end="\r", flush=True)

        log.info(f"Decompiled {old_count} functions from old binary")
        
        print()
        print("-"*100)
        
        # Process NEW binary
        log.info("=== Processing NEW Binary ===")
        
        # Explore and save NEW metadata
        try:
            log.info(f"Exploring metadata for new binary: {new_path}")
            new_info = explore_database(new_path)
            upsert_binary_metadata(
                conn,
                "new",
                new_info["minimum_ea"],
                new_info["maximum_ea"],
                new_info["function_count"],
                new_info["compressed_blob"],
            )
            log.info("Successfully saved new binary metadata")
        except Exception as e:
            error_msg = f"Failed to explore/save NEW metadata: {new_path}"
            log.error(error_msg)
            error_stats.add_error("ida", error_msg, e)
            log.warning("Continuing without new binary metadata...")

        log.info(f"Decompiling {new_path}")

        # Count total NEW functions
        new_total = 0
        try:
            with ida_domain.Database.open(new_path, IdaCommandOptions(auto_analysis=True), False) as db:
                new_total = len(list(db.functions.get_all()))
                log.info(f"Found {new_total} functions in new binary")
        except Exception as e:
            error_msg = f"Could not count functions in {new_path}"
            log.warning(error_msg)
            error_stats.add_error("ida", error_msg, e)

        new_count = 0
        print()
        
        # Process new binary functions
        for result in analyze_binary(new_path, "new", debug=debug, error_stats=error_stats):
            try:
                # Handle both old format (5 items) and new format (6 items with features)
                if len(result) == 6:
                    name, compressed, addr, blocks, signature, features = result
                    if features:
                        insert_function_with_features(conn, "new", name, compressed, features)
                    else:
                        insert_function_with_meta(conn, "new", name, compressed, addr, blocks, signature)
                else:
                    name, compressed, addr, blocks, signature = result[:5]
                    insert_function_with_meta(conn, "new", name, compressed, addr, blocks, signature)
            except Exception as e:
                try:
                    name = result[0]
                    compressed = result[1]
                    insert_function(conn, "new", name, compressed)
                except Exception as e2:
                    error_msg = f"Failed to insert function {name} from new binary"
                    log.error(error_msg)
                    error_stats.add_error("database", error_msg, e2)
                    continue
            
            new_count += 1
            print(f"[*] Exporting functions from {new_path} : {new_count}/{new_total}", end="\r", flush=True)

        print()
        print("-"*100)
        log.info(f"Decompiled {new_count} functions from new binary")
        log.info(f"Total functions processed: {old_count + new_count}")

        # Compute and store diffs
        try:
            log.info("Computing diffs and populating diff_results table...")
            log.info(f"Using heuristics: {use_heuristics}")
            compute_and_store_diffs(conn, use_heuristics=use_heuristics)
            log.info("Diff computation completed successfully")
        except Exception as e:
            error_msg = "Failed to compute/store diffs"
            log.error(error_msg)
            error_stats.add_error("database", error_msg, e)
            log.warning("Analysis completed but diff computation failed")

    except Exception as e:
        error_msg = "Critical error during analysis"
        log.error(error_msg)
        error_stats.add_error("other", error_msg, e)
        log.error(f"Exception details: {str(e)}")
        traceback.print_exc()
        return False
    
    finally:
        try:
            conn.close()
            log.info("Database connection closed")
        except Exception as e:
            log.warning(f"Error closing database connection: {e}")
        
        # Log final results
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
        
        # Log error summary and analysis summary
        error_stats.log_summary()
        log_analysis_summary(old_count, new_count, error_stats)
        
        log.info("=== DiffRays Analysis Completed ===")
    
    return True


def get_error_report(error_stats: ErrorStats) -> dict:
    """Generate a comprehensive error report"""
    summary = error_stats.get_summary()
    
    report = {
        "analysis_status": "SUCCESS" if summary["total_errors"] == 0 else "PARTIAL" if summary["total_errors"] < 10 else "FAILED",
        "error_summary": summary,
        "recommendations": []
    }
    
    # Generate recommendations based on error types
    if summary["file_errors"] > 0:
        report["recommendations"].append("Check file paths and permissions")
    
    if summary["ida_errors"] > 0:
        report["recommendations"].append("Verify IDA Pro installation and IDADIR environment variable")
    
    if summary["database_errors"] > 0:
        report["recommendations"].append("Check database permissions and disk space")
    
    if summary["function_errors"] > 0:
        report["recommendations"].append("Some functions could not be processed - check binary integrity")
    
    if summary["total_errors"] == 0:
        report["recommendations"].append("Analysis completed successfully with no errors")
    
    return report


def log_analysis_summary(old_count: int, new_count: int, error_stats: ErrorStats):
    """Log a comprehensive analysis summary"""
    log.info("=== ANALYSIS SUMMARY ===")
    log.info(f"Old binary functions processed: {old_count}")
    log.info(f"New binary functions processed: {new_count}")
    log.info(f"Total functions processed: {old_count + new_count}")
    
    error_report = get_error_report(error_stats)
    log.info(f"Analysis status: {error_report['analysis_status']}")
    
    if error_report["recommendations"]:
        log.info("Recommendations:")
        for rec in error_report["recommendations"]:
            log.info(f"  - {rec}")


def validate_binary_file(file_path: str) -> tuple[bool, str]:
    """Validate if a file is a valid binary for analysis"""
    try:
        if not os.path.exists(file_path):
            return False, f"File does not exist: {file_path}"
        
        if not os.path.isfile(file_path):
            return False, f"Path is not a file: {file_path}"
        
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return False, f"File is empty: {file_path}"
        
        if file_size < 1024:  # Less than 1KB
            return False, f"File too small to be a valid binary: {file_path} ({file_size} bytes)"
        
        # Check file extension (basic check)
        valid_extensions = ['.exe', '.dll', '.sys', '.bin', '.so', '.elf', '']
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in valid_extensions:
            log.warning(f"Unusual file extension: {file_ext} for {file_path}")
        
        return True, "Valid binary file"
        
    except Exception as e:
        return False, f"Error validating file {file_path}: {str(e)}"
