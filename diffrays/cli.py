import argparse
import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from diffrays.log import log


BANNER = r"""
______ _  __  ________                
|  _  (_)/ _|/ _| ___ \               
| | | |_| |_| |_| |_/ /__ _ _   _ ___ 
| | | | |  _|  _|    // _` | | | / __|
| |/ /| | | | | | |\ \ (_| | |_| \__ \
|___/ |_|_| |_| \_| \_\__,_|\__, |___/
                             __/ |    
                            |___/      v1.1 Lambda
"""

def generate_db_name(old_path: str, new_path: str) -> str:
    """Generate database name with timestamp"""
    old_name = Path(old_path).stem
    new_name = Path(new_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"result_{old_name}_{new_name}_{timestamp}.sqlite"

def generate_log_name(old_path: str, new_path: str) -> str:
    """Generate log file name"""
    old_name = Path(old_path).stem
    new_name = Path(new_path).stem
    return f"log_{old_name}_{new_name}.txt"

def check_ida_available():
    """Check if IDA analysis dependencies are available"""
    try:
        import ida_domain
        from ida_domain.database import IdaCommandOptions
        return True
    except ImportError:
        return False
    except Exception as e:
        # Only log warning if debug mode is enabled elsewhere
        return False

def run_diff_safe(old_path, new_path, output_db, log_file, debug_mode):
    """Safely run diff analysis with proper error handling"""
    try:
        from diffrays.analyzer import run_diff
        
        if debug_mode:
            log.info(f"Starting analysis: {old_path} -> {new_path}")
            log.info(f"Output database: {output_db}")
        
        run_diff(old_path, new_path, output_db)
        
        if debug_mode:
            log.info("Analysis completed successfully!")
        print(f"\nAnalysis complete! Database: {output_db}")
        if log_file:
            print(f"Log file: {log_file}")
        print(f"To view results: diffrays server --db-path {output_db}")
        
    except ImportError as e:
        if debug_mode:
            log.error(f"IDA analysis components not available: {e}")
        print(f"\nIDA analysis not available: {e}")
        print("Please ensure:")
        print("1. IDA Pro is installed")
        print("2. IDADIR environment variable is set")
        print("3. ida_domain Python package is installed")
        sys.exit(1)
    except Exception as e:
        if debug_mode:
            log.error(f"Analysis failed: {e}")
        print(f"\nAnalysis failed: {e}")
        sys.exit(1)

def main():
    # Display banner (always show)
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="diffrays",
        description="Binary Diff Analysis Tool - Decompile, Compare, and Visualize Binary Changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  diffrays diff old_binary.exe new_binary.exe
  diffrays diff old.so new.so -o custom_name.sqlite --log
  diffrays server --db-path result_old_new_20231201.sqlite --debug

For more information, visit: https://github.com/pwnfuzz/diffrays
        """
    )

    sub = parser.add_subparsers(dest="command", required=True, help="Command to execute")

    # Diff command
    diff_parser = sub.add_parser(
        "diff", 
        help="Analyze two binaries and generate differential database"
    )
    diff_parser.add_argument("old", help="Path to old/original binary")
    diff_parser.add_argument("new", help="Path to new/modified binary")
    diff_parser.add_argument("-o", "--output", help="SQLite output file (default: auto-generated)")
    diff_parser.add_argument("--log", action="store_true", help="Store logs in file")
    diff_parser.add_argument("--debug", action="store_true", help="Enable debug logging and verbose output")

    # Server command
    server_parser = sub.add_parser("server", help="Launch web server to view diff results")
    server_parser.add_argument("--db-path", required=True, help="Path to SQLite database file")
    server_parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    server_parser.add_argument("--port", type=int, default=5555, help="Server port (default: 5555)")
    server_parser.add_argument("--debug", action="store_true", help="Enable debug mode and verbose output")
    server_parser.add_argument("--log", action="store_true", help="Store server logs in file")

    args = parser.parse_args()

    # Determine if we're in debug mode
    debug_mode = getattr(args, 'debug', False)

    if args.command == "diff":
        if not check_ida_available():
            print("\nIDA analysis components not available!")
            print("The 'diff' command requires IDA Pro to be installed and configured.\n")
            sys.exit(1)

        # Output filename
        output_db = args.output or generate_db_name(args.old, args.new)

        # Log file (optional)
        log_file = generate_log_name(args.old, args.new) if getattr(args, "log", False) else None
        
        # Configure the global logger
        log.configure(debug=debug_mode, log_file=log_file)
        
        if args.log and debug_mode:
            log.info(f"Logging to file: {log_file}")

        # Run diff safely
        run_diff_safe(args.old, args.new, output_db, log_file, debug_mode)

    elif args.command == "server":
        log_file = None
        if args.log:
            db_stem = Path(args.db_path).stem
            log_file = f"server_{db_stem}.log"
        
        # Configure the global logger
        log.configure(debug=debug_mode, log_file=log_file)
        
        if debug_mode and args.log:
            log.info(f"Server logging to file: {log_file}")

        try:
            from diffrays.server import run_server

            if debug_mode:
                log.info(f"Starting server for database: {args.db_path}")
                log.info(f"Server URL: http://{args.host}:{args.port}")

            print(f"\nStarting DiffRays Server")
            print(f"Database: {args.db_path}")
            print(f"URL: http://{args.host}:{args.port}")
            if not debug_mode:
                print("Use --debug for detailed logging")
            print("Press Ctrl+C to stop the server\n")

            run_server(db_path=args.db_path, host=args.host, port=args.port)

        except Exception as e:
            log.error(f"Server failed to start: {e}")
            print(f"\nServer failed to start: {e}")
            if debug_mode:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Close the log file at the end
    log.close()

if __name__ == "__main__":
    main()