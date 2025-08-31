from dataclasses import asdict
from typing import Dict, Any
from ida_domain.database import IdaCommandOptions
from diffrays.log import log
import json
import zlib
import ida_domain




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


