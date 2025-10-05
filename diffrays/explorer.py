from dataclasses import asdict
from typing import Dict, Any
from ida_domain.database import IdaCommandOptions
from diffrays.log import log
import json
import zlib
import ida_domain
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

def print_success(message):
    """Print success message in green"""
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message in blue"""
    print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message in red"""
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

def print_section_header(title):
    """Print a colored section header"""
    print(f"\n{Fore.MAGENTA}=== {title} ==={Style.RESET_ALL}\n")

def print_metadata(full_meta: dict) -> None:
    metadata = full_meta["metadata"]

    print_section_header(f"Analyzing: {Fore.YELLOW}{metadata['module']}{Style.RESET_ALL}")
    print()
    print(f"Path            : {metadata['path']}")
    print(f"Base Address    : {Fore.GREEN}0x{metadata['base_address']:X}{Style.RESET_ALL}")
    print(f"Minimum EA      : {Fore.GREEN}0x{full_meta['minimum_ea']:X}{Style.RESET_ALL}")
    print(f"Maximum EA      : {Fore.GREEN}0x{full_meta['maximum_ea']:X}{Style.RESET_ALL}")
    
    func_count = full_meta['function_count']
    func_color = Fore.GREEN if func_count > 1000 else Fore.CYAN if func_count > 100 else Fore.YELLOW
    print(f"Function Count  : {func_color}{func_count:,}{Style.RESET_ALL}")
    
    file_size = metadata['filesize']
    if file_size < 1024 * 1024:
        size_str = f"{file_size / 1024:.1f} KB"
        size_color = Fore.CYAN
    elif file_size < 1024 * 1024 * 1024:
        size_str = f"{file_size / (1024 * 1024):.1f} MB"
        size_color = Fore.YELLOW
    else:
        size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
        size_color = Fore.RED
    
    print(f"File Size       : {size_color}{size_str} ({file_size:,} bytes){Style.RESET_ALL}")
    print(f"MD5             : {Fore.YELLOW}{metadata['md5']}{Style.RESET_ALL}")
    print(f"SHA256          : {Fore.CYAN}{metadata['sha256']}{Style.RESET_ALL}")
    print(f"CRC32           : {Fore.MAGENTA}{metadata['crc32']}{Style.RESET_ALL}")
    
    arch_color = Fore.GREEN if metadata['bitness'] == 64 else Fore.CYAN
    print(f"Architecture    : {arch_color}{metadata['architecture']} ({metadata['bitness']}-bit){Style.RESET_ALL}")
    print(f"Format          : {Fore.CYAN}{metadata['format']}{Style.RESET_ALL}")
    print(f"Load Time       : {metadata['load_time']}")
    print(f"Compiler Info   : {Fore.YELLOW}{metadata['compiler_information']}{Style.RESET_ALL}")
    print(f"Execution Mode  : {Fore.CYAN}{metadata['execution_mode']}{Style.RESET_ALL}")

def _compress_metadata(metadata: Dict[str, Any]) -> bytes:
    """Compress metadata dictionary to bytes"""
    text = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    compressed = zlib.compress(text.encode("utf-8"))
    
    original_size = len(text.encode("utf-8"))
    compressed_size = len(compressed)
    compression_ratio = (1 - compressed_size / original_size) * 100
        
    return compressed

def explore_database(binary_path: str) -> Dict[str, Any]:
    """Explore basic database information for a single binary path.

    Returns a dict with keys: minimum_ea, maximum_ea, function_count, metadata (dict), compressed_blob (bytes)
    """
    
    try:
        ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
        
        with ida_domain.Database.open(binary_path, ida_options) as db:
            
            minimum_ea = db.minimum_ea
            maximum_ea = db.maximum_ea

            # Raw metadata as dict
            metadata_dict = asdict(db.metadata)

            # Count functions
            function_count = 0
            for _ in db.functions:
                function_count += 1

            full_meta = {
                "minimum_ea": minimum_ea,
                "maximum_ea": maximum_ea,
                "function_count": function_count,
                "metadata": metadata_dict,
            }

            print_metadata(full_meta)

            compressed_blob = _compress_metadata(full_meta)

            log.info(f"Explored binary: range {hex(minimum_ea)} - {hex(maximum_ea)}, functions: {function_count}")

            return {
                "minimum_ea": minimum_ea,
                "maximum_ea": maximum_ea,
                "function_count": function_count,
                "metadata": metadata_dict,
                "compressed_blob": compressed_blob,
            }
            
    except Exception as e:
        print_error(f"Failed to analyze binary: {e}")
        log.error(f"Database exploration failed for {binary_path}: {e}")
        raise