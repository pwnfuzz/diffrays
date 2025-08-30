import argparse
import sys
import os
import logging
from datetime import datetime
from pathlib import Path
from diffrays.log import get_logger

logger = get_logger(__name__)

BANNER = r"""
______ _  __  ________                
|  _  (_)/ _|/ _| ___ \               
| | | |_| |_| |_| |_/ /__ _ _   _ ___ 
| | | | |  _|  _|    // _` | | | / __|
| |/ /| | | | | | |\ \ (_| | |_| \__ \
|___/ |_|_| |_| \_| \_\__,_|\__, |___/
                             __/ |    
                            |___/      v1.0 Kappa
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

def run_diff_safe(old_path, new_path, output_db, log_file, log_level, debug_mode):
    """Safely run diff analysis with proper error handling"""
    try:
        from diffrays.analyzer import run_diff
        
        if debug_mode:
            logger.info("Starting analysis: %s -> %s", old_path, new_path)
            logger.info("Output database: %s", output_db)
        
        run_diff(old_path, new_path, output_db)
        
        if debug_mode:
            logger.info("Analysis completed successfully!")
        print(f"\nAnalysis complete! Database: {output_db}")
        if log_file:
            print(f"Log file: {log_file}")
        print(f"To view results: diffrays server --db-path {output_db}")
        
    except ImportError as e:
        if debug_mode:
            logger.error("IDA analysis components not available: %s", e)
        print(f"\nIDA analysis not available: {e}")
        print("Please ensure:")
        print("1. IDA Pro is installed")
        print("2. IDADIR environment variable is set")
        print("3. ida_domain Python package is installed")
        sys.exit(1)
    except Exception as e:
        if debug_mode:
            logger.error("Analysis failed: %s", e)
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
  
For more information, visit: https://github.com/yourusername/diffrays
        """
    )
    
    sub = parser.add_subparsers(dest="command", required=True, help="Command to execute")

    # Diff command
    diff_parser = sub.add_parser("diff", help="Analyze two binaries and generate differential database\n\nRequirements:\n• IDA Pro with HexRays Decompiler plugin\n• Valid IDADIR environment variable configuration\n• ida_domain Python package installation")
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
        # Check if IDA is available first
        if not check_ida_available():
            print("\nIDA analysis components not available!")
            print("The 'diff' command requires IDA Pro to be installed and configured.")
            print("\nPlease ensure:")
            print("1. IDA Pro is installed")
            print("2. IDADIR environment variable is set correctly")
            print("3. ida_domain Python package is installed")
            print("\nYou can still use the server to view existing databases:")
            print("diffrays server --db-path existing_database.sqlite")
            sys.exit(1)

        # Set log level - only show warnings/errors unless debug mode
        log_level = logging.DEBUG if debug_mode else logging.CRITICAL + 1
        
        # Generate output filename if not provided
        output_db = args.output or generate_db_name(args.old, args.new)
        
        # Setup logging - file gets everything, console gets only based on debug mode
        log_file = None
        if args.log:
            log_file = generate_log_name(args.old, args.new)
            if debug_mode:
                print(f"Logging to file: {log_file}")
        
        # Configure logger - file gets all levels, console gets only warnings+ or debug
        logger = get_logger("diffrays.analyzer", log_file, 
                           file_level=logging.DEBUG if args.log else None,
                           console_level=log_level)
        
        # Run analysis with safe error handling
        run_diff_safe(args.old, args.new, output_db, log_file, log_level, debug_mode)

    elif args.command == "server":
        # Set log level - only show warnings/errors unless debug mode
        log_level = logging.DEBUG if debug_mode else logging.CRITICAL + 1
        
        # Setup logging
        log_file = None
        if args.log:
            db_stem = Path(args.db_path).stem
            log_file = f"server_{db_stem}.log"
            if debug_mode:
                print(f"Server logging to file: {log_file}")
        
        # Configure logger
        logger = get_logger("diffrays.server", log_file, 
                           file_level=logging.DEBUG if args.log else None,
                           console_level=log_level)
        
        try:
            # Import server components (should work without IDA)
            from diffrays.server import run_server
            
            if debug_mode:
                logger.info("Starting server for database: %s", args.db_path)
                logger.info("Server URL: http://%s:%d", args.host, args.port)
            
            print(f"\nStarting DiffRays Server")
            print(f"Database: {args.db_path}")
            print(f"URL: http://{args.host}:{args.port}")
            if not debug_mode:
                print("Use --debug for detailed logging")
            print("Press Ctrl+C to stop the server\n")
            
            run_server(db_path=args.db_path, host=args.host, port=args.port, 
                      log_file=log_file, debug_mode=debug_mode)
            
        except Exception as e:
            # Always show critical errors, but details only in debug mode
            if debug_mode:
                logger.error("Server failed to start: %s", e)
            print(f"\nServer failed to start: {e}")
            if debug_mode:
                import traceback
                traceback.print_exc()
            sys.exit(1)

if __name__ == '__main__':
    main()