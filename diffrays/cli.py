import argparse
import sys
import os
import logging
from datetime import datetime
from pathlib import Path
import re
from colorama import Fore, Back, Style, init

from diffrays.log import log
from diffrays.file_downloader import (
                DEFAULT_WINDOWS_VERSION,
                validate_cve_format,
                fetch_cve_data,
                extract_cve_info,
                get_component_mapping,
                find_matching_components,
                release_number_to_patch_month,
                download_database,
                get_target_versions,
                download_symbol_file,
)

# Initialize colorama
init(autoreset=True)
BANNER = f"""{Fore.CYAN}
______ _  __  ________                
|  _  (_)/ _|/ _| ___ \               
| | | |_| |_| |_| |_/ /__ _ _   _ ___ 
| | | | |  _|  _|    // _` | | | / __|
| |/ /| | | | | | |\ \ (_| | |_| \__ \ 
|___/ |_|_| |_| \_| \_\__,_|\__, |___/ 
                             __/ |    
                            |___/      {Fore.YELLOW}v1.5 Omicron{Style.RESET_ALL}
"""

def print_success(message):
    """Print success message in green"""
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message in blue"""
    print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

def print_warning(message):
    """Print warning message in yellow"""
    print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message in red"""
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

def print_section_header(title):
    """Print a colored section header"""
    print(f"\n{Fore.MAGENTA}=== {title} ==={Style.RESET_ALL}\n")

def print_config_line(key, value, color=Fore.CYAN):
    """Print configuration line with colored key"""
    print(f"{color}{key:18}{Style.RESET_ALL} {value}")

def print_separator(length=100, color=Fore.WHITE):
    """Print a colored separator line"""
    print(f"{color}{'-' * length}{Style.RESET_ALL}")

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
        
        # print_info(f"Analyzing binaries...")
        run_diff(old_path, new_path, output_db)
        
        if debug_mode:
            log.info("Analysis completed successfully!")
        
        print_success("Analysis complete!")
        print_config_line("Database:", output_db, Fore.GREEN)
        if log_file:
            print_config_line("Log file:", log_file, Fore.GREEN)
        print_info(f"To view results: {Fore.WHITE}diffrays server --db-path {output_db}{Style.RESET_ALL}")
        
    except ImportError as e:
        if debug_mode:
            log.error(f"IDA analysis components not available: {e}")
        print_error(f"IDA analysis not available: {e}")
        print("Please ensure:")
        print("1. IDA Pro is installed")
        print("2. IDADIR environment variable is set")
        print("3. ida_domain Python package is installed")
        sys.exit(1)
    except Exception as e:
        if debug_mode:
            log.error(f"Analysis failed: {e}")
        print_error(f"Analysis failed: {e}")
        sys.exit(1)

def main():
    # Display banner (always show)
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="diffrays",
        description="Binary Diff Analysis Tool - Decompile, Compare, and Visualize Binary Changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{Style.RESET_ALL}
  {Fore.WHITE}diffrays autodiff --cve CVE-2025-29824 {Style.RESET_ALL}
  {Fore.WHITE}diffrays autodiff -f clfs.sys -m 2025-09 {Style.RESET_ALL}
  {Fore.WHITE}diffrays autodiff -f clfs.sys -m 2025-09 -w 2023-H2 {Style.RESET_ALL}
  {Fore.WHITE}diffrays diff old_binary.exe new_binary.exe{Style.RESET_ALL}
  {Fore.WHITE}diffrays diff old.so new.so -o custom_name.sqlite --log{Style.RESET_ALL}
  {Fore.WHITE}diffrays server --db-path result_old_new_20231201.sqlite --debug{Style.RESET_ALL}

{Fore.YELLOW}For more information, visit: https://github.com/pwnfuzz/diffrays{Style.RESET_ALL}
        """
    )

    sub = parser.add_subparsers(dest="command", required=True, help="Command to execute")

    # Diff command
    diff_parser = sub.add_parser("diff", help="Analyze two binaries and generate differential database")
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

    # Autodiff command
    autodiff_parser = sub.add_parser("autodiff", help="Auto-download binaries (via CVE or manual input) and run diff",)
    auto_me = autodiff_parser.add_mutually_exclusive_group(required=True)
    auto_me.add_argument("--cve", help="CVE ID (e.g., CVE-2025-54099)")
    auto_me.add_argument("-f", "--filename", help="Component filename (e.g., afd.sys)")
    autodiff_parser.add_argument("-m", "--patch-month", help="Patch month in YYYY-MM format (e.g., 2025-09). Required if --filename is used.",)
    autodiff_parser.add_argument("-w", "--windows-version", default=DEFAULT_WINDOWS_VERSION, help=f"Windows version (default: {DEFAULT_WINDOWS_VERSION})",)
    autodiff_parser.add_argument("-d", "--dbname", help="Optional override for downloaded winbindex DB filename (e.g., afd.json.gz), this can be found here: https://winbindex.m417z.com/data/by_filename_compressed",)
    autodiff_parser.add_argument("-o", "--output", help="SQLite output file (default: auto-generated)",)
    autodiff_parser.add_argument("--log", action="store_true", help="Store logs in file")
    autodiff_parser.add_argument("--debug", action="store_true", help="Enable debug logging and verbose output")

    args = parser.parse_args()

    # Determine if we're in debug mode
    debug_mode = getattr(args, 'debug', False)

    if args.command == "diff":
        if not check_ida_available():
            print_error("IDA analysis components not available!")
            print("The 'diff' command requires IDA Pro to be installed and configured.\n")
            sys.exit(1)

        # Output filename
        output_db = args.output or generate_db_name(args.old, args.new)

        # Log file (optional)
        log_file = generate_log_name(args.old, args.new) if getattr(args, "log", False) else None
        
        # Display current configuration before proceeding
        print_section_header("DiffRays Diff Configuration")
        print_config_line("Old Binary:", args.old)
        print_config_line("New Binary:", args.new)
        print_config_line("Output DB:", output_db)
        print_config_line("Log File:", log_file or 'None')
        print_config_line("Debug Mode:", f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if debug_mode else f"{Fore.RED}Disabled{Style.RESET_ALL}")
        print_config_line("Logging:", f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if getattr(args, 'log', False) else f"{Fore.RED}Disabled{Style.RESET_ALL}")
        print_separator()
        print()
        
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
        
        # Display current configuration before proceeding
        print_section_header("DiffRays Server Configuration")
        print_config_line("Database Path:", args.db_path)
        print_config_line("Host:", args.host)
        print_config_line("Port:", str(args.port))
        print_config_line("Server URL:", f"{Fore.GREEN}http://{args.host}:{args.port}{Style.RESET_ALL}")
        print_config_line("Log File:", log_file or 'None')
        print_config_line("Debug Mode:", f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if debug_mode else f"{Fore.RED}Disabled{Style.RESET_ALL}")
        print_config_line("Logging:", f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if getattr(args, 'log', False) else f"{Fore.RED}Disabled{Style.RESET_ALL}")
        print_separator()
        print()
        
        # Configure the global logger
        log.configure(debug=debug_mode, log_file=log_file)
        
        if debug_mode and args.log:
            log.info(f"Server logging to file: {log_file}")

        try:
            from diffrays.server import run_server

            if debug_mode:
                log.info(f"Starting server for database: {args.db_path}")
                log.info(f"Server URL: http://{args.host}:{args.port}")

            print_info("Starting DiffRays Server")
            print_config_line("Database:", args.db_path, Fore.CYAN)
            print_config_line("URL:", f"{Fore.GREEN}http://{args.host}:{args.port}{Style.RESET_ALL}", Fore.CYAN)
            if not debug_mode:
                print_info("Use --debug for detailed logging")
            print_warning("Press Ctrl+C to stop the server\n")

            run_server(db_path=args.db_path, host=args.host, port=args.port)

        except Exception as e:
            log.error(f"Server failed to start: {e}")
            print_error(f"Server failed to start: {e}")
            if debug_mode:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    elif args.command == "autodiff":

        # Validate IDA availability before heavy-lifting
        if not check_ida_available():
            print_error("IDA analysis components not available!")
            print("The 'autodiff' command requires IDA Pro to be installed and configured.\n")
            sys.exit(1)

        # Resolve filename and patch_month either from CVE or manual args
        filename = None
        patch_month = None

        if getattr(args, "cve", None):
            cve_id = args.cve.strip().upper()
            if not validate_cve_format(cve_id):
                print_error("Invalid CVE format. Please use format: CVE-YYYY-NNNNN")
                sys.exit(1)

            # Fetch and derive component + month
            cve_data = fetch_cve_data(cve_id)
            if not cve_data:
                print_error("Failed to retrieve CVE data.")
                sys.exit(1)

            cve_info = extract_cve_info(cve_data)

            component_mapping = get_component_mapping()
            matches = find_matching_components(cve_info, component_mapping)
            if not matches:
                print_error("[-] No matching components found for CVE. Use manual mode with --filename and --patch-month.")
                sys.exit(1)

            filename = matches[0]["file"]
            patch_month = release_number_to_patch_month(cve_info.get("release_number", ""))
            if not patch_month:
                print_error("[-] Could not parse patch month from CVE release number.")
                sys.exit(1)
        else:
            # Manual mode requires both filename and patch-month
            if not args.filename:
                print_error("[-] --filename is required in manual mode")
                sys.exit(1)
            if not args.patch_month:
                print_error("[-] --patch-month is required in manual mode")
                sys.exit(1)
            if not re.match(r"^\d{4}-\d{2}$", args.patch_month):
                print_error("[-] Invalid patch month format. Please use YYYY-MM")
                sys.exit(1)
            filename = args.filename
            patch_month = args.patch_month

        # Resolve winbindex DB name
        if args.dbname:
            dbname = args.dbname
        else:
            dbname = f"{Path(filename).stem}.json.gz"

        # Display current configuration before proceeding
        print_section_header("DiffRays AutoDiff Configuration")
        print_config_line("CVE:", getattr(args, 'cve', f'{Fore.YELLOW}N/A (Manual mode){Style.RESET_ALL}'))
        print_config_line("Filename:", filename)
        print_config_line("Patch Month:", patch_month)
        print_config_line("Windows Version:", args.windows_version)
        print_config_line("Database Name:", dbname)
        print_config_line("Output DB:", args.output or f'{Fore.YELLOW}Auto-generated{Style.RESET_ALL}')
        print_config_line("Debug Mode:", f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if debug_mode else f"{Fore.RED}Disabled{Style.RESET_ALL}")
        print_config_line("Logging:", f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if getattr(args, 'log', False) else f"{Fore.RED}Disabled{Style.RESET_ALL}")
        print_separator()
        print()

        # Configure logging now that we have inputs
        # We will configure based on eventual downloaded filenames for better log names, so temporary for now
        temp_old = f"{Path(filename).stem}_OLD"
        temp_new = f"{Path(filename).stem}_NEW"
        log_file = generate_log_name(temp_old, temp_new) if getattr(args, "log", False) else None
        log.configure(debug=debug_mode, log_file=log_file)

        try:

            print_section_header(f"Downloading Non-Patched & Patched Components for {filename}")

            print_success(f"Found the patched version in: {Fore.YELLOW}{patch_month}{Style.RESET_ALL}")

            # Step 1: Download DB
            db_path = download_database(filename, dbname)

            # Step 2: Determine target versions
            patch_info, vuln_info = get_target_versions(db_path, args.windows_version, patch_month)
            if not patch_info:
                print_error(f"No patch version found for {patch_month}")
                sys.exit(1)
            if not vuln_info:
                print_error("No vulnerable version found for previous month")
                sys.exit(1)

            if debug_mode:
                log.info(f"Found patch: {patch_info['release_version']} ({patch_info['release_date']})")
                log.info(f"Found vulnerable: {vuln_info['release_version']} ({vuln_info['release_date']})")

            print_success(f"Patch version: {Fore.YELLOW}{patch_info['release_version']}{Style.RESET_ALL} ({patch_info['release_date']})")
            print_success(f"Vulnerable version: {Fore.YELLOW}{vuln_info['release_version']}{Style.RESET_ALL} ({vuln_info['release_date']})")

            # Step 3: Download binaries (returns local filenames with release version)
            patched_file = download_symbol_file(patch_info, "patch", filename)
            vulnerable_file = download_symbol_file(vuln_info, "vulnerable", filename)

            # Reconfigure log file name now that we have actual file names (optional)
            if getattr(args, "log", False):
                log.close()
                log_file = generate_log_name(vulnerable_file, patched_file)
                log.configure(debug=debug_mode, log_file=log_file)

            # Step 4: Run diff
            output_db = args.output or generate_db_name(vulnerable_file, patched_file)
            if debug_mode and log_file:
                log.info(f"Logging to file: {log_file}")

            print_separator()
            print()
            run_diff_safe(vulnerable_file, patched_file, output_db, log_file, debug_mode)

        except Exception as e:
            if debug_mode:
                log.error(f"Autodiff failed: {e}")
            print_error(f"Autodiff failed: {e}")
            sys.exit(1)
        finally:
            # Clean up DB gz file if present
            try:
                if dbname and Path(dbname).exists():
                    Path(dbname).unlink()
                    if debug_mode:
                        log.info(f"Cleaned up database file: {dbname}")
            except Exception:
                pass

    # Close the log file at the end
    log.close()

if __name__ == "__main__":
    main()