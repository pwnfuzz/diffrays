#!/usr/bin/env python3
"""
Ghidra-style Basic Block Mnemonic Correlator for Diffrays.

Implements the BulkBasicBlockMnemonicProgramCorrelator algorithm which:
1. Extracts basic blocks from functions
2. For each block, collects and sorts instruction mnemonics
3. Hashes the sorted mnemonics to create a block signature
4. Compares functions by counting common block signatures

This provides a robust, order-independent similarity metric that's excellent
for detecting truly changed functions vs. compiler reorderings.
"""

import hashlib
import logging
from typing import List, Set, Dict, Optional, Tuple
from collections import Counter

try:
    import ida_domain
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

logger = logging.getLogger(__name__)


def hash_mnemonics_list(mnemonics: List[str]) -> int:
    """
    Hash a sorted list of mnemonics using the same algorithm as Ghidra.
    
    Uses a simple polynomial hash: hash = hash * 31 + mnemonic_hash
    This matches the Java implementation: bbhash = (bbhash*31 + hash)
    """
    result = 0
    for mnem in mnemonics:
        # Use Python's built-in hash, which is similar to Java's hashCode()
        mnem_hash = hash(mnem) & 0xFFFFFFFFFFFFFFFF  # Keep as 64-bit
        result = (result * 31 + mnem_hash) & 0xFFFFFFFFFFFFFFFF
    return result


def extract_basic_block_hashes(db, func) -> List[int]:
    """
    Extract basic block mnemonic hashes from a function.
    
    This implements the BasicBlockMnemonicFunctionBulker.hashes() algorithm:
    1. Get all basic blocks in the function
    2. For each block, collect all instruction mnemonics
    3. Sort the mnemonics (order-independent within block)
    4. Hash the sorted mnemonics to create a block signature
    
    Returns a list of block hashes (one per basic block).
    """
    if not IDA_AVAILABLE:
        raise ImportError("ida_domain is not available")
    
    try:
        flow = db.functions.get_flowchart(func)
        block_hashes = []
        
        # Build a mapping of instruction addresses to mnemonics
        # First, collect all instructions with their addresses
        all_instructions = {}
        for insn in db.functions.get_instructions(func):
            try:
                mnem = db.instructions.get_mnemonic(insn)
                if mnem:
                    all_instructions[insn.ea] = mnem
            except Exception:
                continue
        
        # Process each basic block
        for block_idx, block in enumerate(flow):
            mnemonics = []
            
            try:
                # Try to get block address range
                block_start = getattr(block, 'start_ea', None)
                block_end = getattr(block, 'end_ea', None)
                
                if block_start is not None and block_end is not None:
                    # Get instructions within this block's address range
                    for ea, mnem in all_instructions.items():
                        if block_start <= ea < block_end:
                            mnemonics.append(mnem)
                else:
                    # Fallback: try to get instructions from block directly
                    # Some IDA Domain API implementations might have block.get_instructions()
                    if hasattr(block, 'get_instructions'):
                        for insn in block.get_instructions():
                            try:
                                mnem = db.instructions.get_mnemonic(insn)
                                if mnem:
                                    mnemonics.append(mnem)
                            except Exception:
                                continue
                    else:
                        # Last resort: if we can't determine block boundaries,
                        # we'll skip this block (better than incorrect data)
                        logger.debug(f"Block {block_idx} has no address range, skipping")
                        continue
                        
            except Exception as e:
                logger.debug(f"Error extracting instructions from block {block_idx}: {e}")
                continue
            
            if not mnemonics:
                # Empty block - skip it
                continue
            
            # Sort mnemonics (order-independent within block)
            # This helps with cases where compiler swaps instructions
            mnemonics.sort()
            
            # Hash the sorted mnemonics
            bbhash = hash_mnemonics_list(mnemonics)
            block_hashes.append(bbhash)
        
        return block_hashes
        
    except Exception as e:
        logger.error(f"Error extracting basic block hashes: {e}")
        return []


def compute_bulk_similarity(hashes1: List[int], hashes2: List[int]) -> float:
    """
    Compute similarity between two lists of basic block hashes.
    
    This implements the getBulkSimilarity() algorithm:
    1. Sort both hash lists
    2. Count common hashes (using sorted merge)
    3. Return similarity = common / max(size1, size2)
    
    Returns a similarity score between 0.0 and 1.0.
    """
    if not hashes1 or not hashes2:
        return 0.0
    
    # Sort both lists (as done in Java Collections.sort)
    sorted1 = sorted(hashes1)
    sorted2 = sorted(hashes2)
    
    # Count common hashes using sorted merge (efficient)
    common = 0
    i = 0
    j = 0
    
    while i < len(sorted1) and j < len(sorted2):
        if sorted1[i] < sorted2[j]:
            i += 1
        elif sorted1[i] > sorted2[j]:
            j += 1
        else:  # sorted1[i] == sorted2[j]
            common += 1
            i += 1
            j += 1
    
    # Similarity = common blocks / max(total blocks)
    total = max(len(sorted1), len(sorted2))
    if total == 0:
        return 0.0
    
    return float(common) / float(total)


def compute_correlation_score(
    db_old, func_old,
    db_new, func_new
) -> Optional[float]:
    """
    Compute the Ghidra-style correlation score between two functions.
    
    This is the main entry point that:
    1. Extracts basic block hashes from both functions
    2. Computes bulk similarity
    3. Returns a score between 0.0 and 1.0
    
    Returns None if extraction fails, otherwise returns similarity score.
    """
    try:
        hashes_old = extract_basic_block_hashes(db_old, func_old)
        hashes_new = extract_basic_block_hashes(db_new, func_new)
        
        if not hashes_old or not hashes_new:
            return None
        
        similarity = compute_bulk_similarity(hashes_old, hashes_new)
        return similarity
        
    except Exception as e:
        logger.error(f"Error computing correlation score: {e}")
        return None


def compute_correlation_from_hashes(hashes_old: List[int], hashes_new: List[int]) -> float:
    """
    Compute correlation score from pre-extracted block hashes.
    
    Useful when hashes are already stored in the database.
    """
    return compute_bulk_similarity(hashes_old, hashes_new)

