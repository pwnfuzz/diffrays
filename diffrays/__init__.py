"""
DiffRays - Binary Diff Analysis Tool
Decompile, Compare, and Visualize Binary Changes
"""

__version__ = "0.1.0"
__author__ = "PwnFuzz"
__license__ = "MIT"

from .cli import main
from .server import run_server

# Don't import analyzer at module level
run_diff = None

def _get_run_diff():
    """Helper to get run_diff with proper error handling"""
    global run_diff
    if run_diff is None:
        try:
            from .analyzer import run_diff as rd
            run_diff = rd
        except ImportError as e:
            # Only show message when actually trying to use it
            def run_diff_stub(*args, **kwargs):
                print("\nIDA analysis not available")
                print("Required: IDA Pro with HexRays Decompiler + ida_domain package")
                print(f"Error: {e}")
                raise ImportError("IDA analysis components not available") from e
            run_diff = run_diff_stub
    return run_diff

# Override the run_diff name to use our lazy loader
def run_diff_wrapper(*args, **kwargs):
    return _get_run_diff()(*args, **kwargs)

# Replace the None with our wrapper
run_diff = run_diff_wrapper

__all__ = ['main', 'run_diff', 'run_server']