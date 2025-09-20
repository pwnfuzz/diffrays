from dataclasses import asdict
from typing import Dict, Any
from ida_domain.database import IdaCommandOptions
from diffrays.log import log
import json
import zlib
import ida_domain
import traceback




def _compress_metadata(metadata: Dict[str, Any]) -> bytes:
    text = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    return zlib.compress(text.encode("utf-8"))


def explore_database(binary_path: str) -> Dict[str, Any]:
    """Explore basic database information for a single binary path.

    Returns a dict with keys: minimum_ea, maximum_ea, function_count, metadata (dict), compressed_blob (bytes)
    """
    try:
        ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
        log.debug(f"Opening binary database: {binary_path} with options: {ida_options}")

        with ida_domain.Database.open(binary_path, ida_options) as db:
            try:
                minimum_ea = db.minimum_ea
                maximum_ea = db.maximum_ea
            except Exception as e:
                log.error(f"Failed to read address range from {binary_path}: {e}")
                traceback.print_exc()
                raise

            try:
                # Raw metadata as dict
                metadata_dict = asdict(db.metadata)
            except Exception as e:
                log.error(f"Failed to extract metadata from {binary_path}: {e}")
                traceback.print_exc()
                metadata_dict = {}

            # Count functions
            function_count = 0
            try:
                for _ in db.functions:
                    function_count += 1
            except Exception as e:
                log.error(f"Failed while counting functions in {binary_path}: {e}")
                traceback.print_exc()

            full_meta = {
                "minimum_ea": minimum_ea,
                "maximum_ea": maximum_ea,
                "function_count": function_count,
                "metadata": metadata_dict,
            }

            try:
                compressed_blob = _compress_metadata(full_meta)
            except Exception as e:
                log.error(f"Failed to compress metadata for {binary_path}: {e}")
                traceback.print_exc()
                compressed_blob = b""

            log.info(
                f"Explored binary: range {hex(minimum_ea)} - {hex(maximum_ea)}, "
                f"functions {function_count}"
            )

            return {
                "minimum_ea": minimum_ea,
                "maximum_ea": maximum_ea,
                "function_count": function_count,
                "metadata": metadata_dict,
                "compressed_blob": compressed_blob,
            }

    except Exception as e:
        log.error(f"Critical error exploring database {binary_path}: {e}")
        traceback.print_exc()
        # Fail-safe return to avoid NoneType crashes further down
        return {
            "minimum_ea": 0,
            "maximum_ea": 0,
            "function_count": 0,
            "metadata": {},
            "compressed_blob": b"",
        }
