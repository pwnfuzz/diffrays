from dataclasses import asdict
from typing import Dict, Any
from ida_domain.database import IdaCommandOptions
from diffrays.log import log
import json
import zlib
import ida_domain
import traceback

def print_metadata(full_meta: dict) -> None:
    metadata = full_meta["metadata"]

    print(f"\n=== Analyzing: {metadata['module']} ===")
    print()
    print(f"Path            : {metadata['path']}")
    print(f"Base Address    : 0x{metadata['base_address']:X}")
    print(f"Minimum EA      : 0x{full_meta['minimum_ea']:X}")
    print(f"Maximum EA      : 0x{full_meta['maximum_ea']:X}")
    print(f"Function Count  : {full_meta['function_count']}")
    print(f"File Size       : {metadata['filesize']} bytes")
    print(f"MD5             : {metadata['md5']}")
    print(f"SHA256          : {metadata['sha256']}")
    print(f"CRC32           : {metadata['crc32']}")
    print(f"Architecture    : {metadata['architecture']}")
    print(f"Bitness         : {metadata['bitness']}")
    print(f"Format          : {metadata['format']}")
    print(f"Load Time       : {metadata['load_time']}")
    print(f"Compiler Info   : {metadata['compiler_information']}")
    print(f"Execution Mode  : {metadata['execution_mode']}")


def _compress_metadata(metadata: Dict[str, Any]) -> bytes:
    text = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    return zlib.compress(text.encode("utf-8"))


def explore_database(binary_path: str) -> Dict[str, Any]:
    
    """Explore basic database information for a single binary path.

    Returns a dict with keys: minimum_ea, maximum_ea, function_count, metadata (dict), compressed_blob (bytes)
    """
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

        log.info(
            f"Explored binary: range {hex(minimum_ea)} - {hex(maximum_ea)}, functions{function_count}")

        return {
            "minimum_ea": minimum_ea,
            "maximum_ea": maximum_ea,
            "function_count": function_count,
            "metadata": metadata_dict,
            "compressed_blob": compressed_blob,
        }


