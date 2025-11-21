#!/usr/bin/env python3
"""
Heuristics module for diffrays - implements diaphora-style function matching heuristics.

This module extracts function features and implements multiple heuristics for matching
functions between two binaries, even when function names differ.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import List, Set, Dict, Tuple, Optional, Any

try:
    import ida_domain
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False
    # Create a dummy module to prevent errors
    class DummyModule:
        pass
    ida_domain = DummyModule()

logger = logging.getLogger(__name__)


@dataclass
class FunctionFeatures:
    """Comprehensive function features for matching heuristics."""
    # Basic info
    name: str
    address: int
    size: int
    
    # CFG structure
    nodes: int = 0  # Basic blocks
    edges: int = 0  # CFG edges
    indegree: int = 0
    outdegree: int = 0
    cyclomatic_complexity: int = 0
    
    # Instructions
    instruction_count: int = 0
    mnemonics: str = ""  # Comma-separated mnemonics
    mnemonics_spp: str = ""  # Small primes product of mnemonics
    
    # Hashes
    bytes_hash: str = ""  # MD5 of all function bytes
    function_hash: str = ""  # MD5 of non-relative bytes
    pseudocode_hash: str = ""  # MD5 of pseudocode
    pseudocode_hash1: str = ""  # Fuzzy hash 1
    pseudocode_hash2: str = ""  # Fuzzy hash 2
    pseudocode_hash3: str = ""  # Fuzzy hash 3
    
    # Pseudocode
    pseudocode: str = ""
    pseudocode_lines: int = 0
    clean_pseudocode: str = ""  # Cleaned (no sub_XXX names)
    
    # Assembly
    assembly: str = ""
    clean_assembly: str = ""  # Cleaned assembly
    
    # Constants and data
    constants: str = ""  # JSON array of constants
    constants_count: int = 0
    
    # Graph features
    strongly_connected: int = 0
    loops: int = 0
    switches: str = ""  # JSON array
    
    # Other
    signature: str = ""
    rva: int = 0  # Relative virtual address
    segment_rva: int = 0
    
    # Primes (for matching)
    primes_value: str = ""
    pseudocode_primes: str = ""
    
    # MD Index (graph-based hash)
    md_index: str = ""
    
    # KGH hash (Koret-Karamitas hash)
    kgh_hash: str = ""
    
    # Basic block mnemonic hashes (for Ghidra-style correlation)
    block_hashes: str = ""  # JSON array of block hash integers


# Small primes for SPP (Small Primes Product) calculation
SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def calculate_small_primes_product(items: List[str]) -> str:
    """Calculate small primes product for a list of items."""
    if not items:
        return "1"
    
    # Create a mapping of unique items to primes
    unique_items = sorted(set(items))
    prime_map = {item: SMALL_PRIMES[i % len(SMALL_PRIMES)] for i, item in enumerate(unique_items)}
    
    # Calculate product
    product = 1
    for item in items:
        product *= prime_map[item]
        # Prevent overflow
        if product > 10**20:
            product = product % (10**18)
    
    return str(product)


def clean_name(name: str) -> str:
    """Remove IDA auto-generated names like sub_XXX."""
    import re
    # Remove sub_XXXX patterns
    cleaned = re.sub(r'sub_[0-9A-Fa-f]+', 'sub_', name)
    return cleaned


def extract_bytes_hash(db, func) -> Tuple[str, str]:
    """
    Extract bytes hash and function hash.
    Returns (bytes_hash, function_hash).
    Note: IDA Domain API may not have direct byte access, so we use a simplified approach.
    """
    try:
        # For now, create a hash based on instruction addresses and mnemonics
        # This is a simplified version - full implementation would need raw bytes
        components = []
        for insn in db.functions.get_instructions(func):
            try:
                mnem = db.instructions.get_mnemonic(insn)
                if mnem:
                    components.append(f"{insn.ea}:{mnem}")
            except Exception:
                continue
        
        bytes_hash = hashlib.md5("|".join(components).encode()).hexdigest() if components else ""
        function_hash = bytes_hash  # Simplified - same for now
        
        return bytes_hash, function_hash
    except Exception as e:
        logger.error(f"Error extracting bytes hash: {e}")
        return "", ""


def extract_mnemonics(db, func) -> Tuple[List[str], str, str]:
    """
    Extract mnemonics and calculate SPP.
    Returns (mnemonics_list, mnemonics_string, mnemonics_spp).
    """
    try:
        mnemonics = []
        for insn in db.functions.get_instructions(func):
            try:
                mnem = db.instructions.get_mnemonic(insn)
                if mnem:
                    mnemonics.append(mnem)
            except Exception as e:
                logger.debug(f"Error getting mnemonic: {e}")
                continue
        
        mnemonics_str = ",".join(mnemonics)
        mnemonics_spp = calculate_small_primes_product(mnemonics)
        
        return mnemonics, mnemonics_str, mnemonics_spp
    except Exception as e:
        logger.error(f"Error extracting mnemonics: {e}")
        return [], "", "1"


def extract_constants(db, func) -> Tuple[List[int], str, int]:
    """
    Extract numeric constants from function.
    Returns (constants_list, constants_json, count).
    """
    try:
        constants = set()
        for insn in db.functions.get_instructions(func):
            try:
                for op in db.instructions.get_operands(insn):
                    if hasattr(op, "get_value"):
                        try:
                            val = op.get_value()
                            if isinstance(val, int):
                                # Filter out addresses and small immediate values
                                if 0 < val < 0x100000000:  # Reasonable range
                                    constants.add(val)
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"Error processing operands: {e}")
                continue
        
        constants_list = sorted(list(constants))
        constants_json = json.dumps(constants_list)
        return constants_list, constants_json, len(constants_list)
    except Exception as e:
        logger.error(f"Error extracting constants: {e}")
        return [], "[]", 0


def extract_cfg_features(db, func) -> Dict[str, int]:
    """
    Extract CFG features: nodes, edges, indegree, outdegree, cyclomatic complexity.
    """
    try:
        flow = db.functions.get_flowchart(func)
        nodes = len(flow)
        
        # Count edges
        edges = 0
        indegree_map = {}
        outdegree_map = {}
        
        for i, block in enumerate(flow):
            outdegree = 0
            if hasattr(block, 'succ') and block.succ:
                for succ_idx in block.succ:
                    if isinstance(succ_idx, int) and 0 <= succ_idx < len(flow):
                        edges += 1
                        outdegree += 1
                        # Track indegree
                        if succ_idx not in indegree_map:
                            indegree_map[succ_idx] = 0
                        indegree_map[succ_idx] += 1
            
            outdegree_map[i] = outdegree
        
        # Calculate indegree/outdegree
        indegree = max(indegree_map.values()) if indegree_map else 0
        outdegree = max(outdegree_map.values()) if outdegree_map else 0
        
        # Cyclomatic complexity = edges - nodes + 2
        cyclomatic_complexity = max(0, edges - nodes + 2)
        
        return {
            "nodes": nodes,
            "edges": edges,
            "indegree": indegree,
            "outdegree": outdegree,
            "cyclomatic_complexity": cyclomatic_complexity
        }
    except Exception as e:
        logger.error(f"Error extracting CFG features: {e}")
        return {
            "nodes": 0,
            "edges": 0,
            "indegree": 0,
            "outdegree": 0,
            "cyclomatic_complexity": 0
        }


def extract_assembly(db, func, max_lines: int = 600) -> Tuple[str, str]:
    """
    Extract assembly code using IDA's disassembly when possible.
    Returns (assembly, clean_assembly).
    """
    try:
        assembly_lines: List[str] = []

        # Try native IDA disassembly first for higher fidelity output
        try:
            if hasattr(db.functions, "get_disassembly"):
                disasm_iter = db.functions.get_disassembly(func)
                for idx, line in enumerate(disasm_iter):
                    assembly_lines.append(line.rstrip())
                    if idx + 1 >= max_lines:
                        break
        except Exception as e:
            logger.debug(f"get_disassembly not available, falling back: {e}")

        # Fallback to manual instruction walk if no disassembly gathered
        if not assembly_lines:
            for insn in db.functions.get_instructions(func):
                try:
                    mnem = db.instructions.get_mnemonic(insn)
                    if not mnem:
                        continue

                    operands = []
                    try:
                        for op in db.instructions.get_operands(insn):
                            if hasattr(op, "get_text"):
                                operands.append(op.get_text())
                            elif hasattr(op, "text"):
                                operands.append(str(op.text))
                    except Exception:
                        pass

                    disasm_line = mnem
                    if operands:
                        disasm_line += " " + ", ".join(operands)

                    assembly_lines.append(f"{hex(insn.ea)}: {disasm_line}")
                    if len(assembly_lines) >= max_lines:
                        break
                except Exception as inner:
                    logger.debug(f"Error getting disassembly: {inner}")
                    continue

        assembly = "\n".join(assembly_lines)
        clean_assembly = clean_name(assembly)
        return assembly, clean_assembly
    except Exception as e:
        logger.error(f"Error extracting assembly: {e}")
        return "", ""


def extract_pseudocode_hashes(pseudocode: str) -> Tuple[str, str, str, str]:
    """
    Extract pseudocode hashes.
    Returns (hash, hash1, hash2, hash3).
    """
    if not pseudocode:
        return "", "", "", ""
    
    try:
        # Basic hash
        hash_val = hashlib.md5(pseudocode.encode()).hexdigest()
        
        # Clean pseudocode for fuzzy hashes
        clean_pseudo = clean_name(pseudocode)
        hash1 = hashlib.md5(clean_pseudo.encode()).hexdigest()
        
        # Reverse hash
        hash2 = hashlib.md5(clean_pseudo[::-1].encode()).hexdigest()
        
        # Mixed hash (alternating)
        mixed = "".join(c if i % 2 == 0 else c.upper() for i, c in enumerate(clean_pseudo))
        hash3 = hashlib.md5(mixed.encode()).hexdigest()
        
        return hash_val, hash1, hash2, hash3
    except Exception as e:
        logger.error(f"Error extracting pseudocode hashes: {e}")
        return "", "", "", ""


def calculate_md_index(cfg_features: Dict[str, int], mnemonics: List[str]) -> str:
    """
    Calculate MD Index (graph-based hash).
    Simplified version - full implementation would use graph isomorphism.
    """
    try:
        components = [
            str(cfg_features.get("nodes", 0)),
            str(cfg_features.get("edges", 0)),
            str(cfg_features.get("cyclomatic_complexity", 0)),
            ",".join(sorted(set(mnemonics)))
        ]
        md_index = hashlib.md5("|".join(components).encode()).hexdigest()[:16]
        return md_index
    except Exception as e:
        logger.error(f"Error calculating MD index: {e}")
        return ""


def calculate_kgh_hash(features: FunctionFeatures) -> str:
    """
    Calculate KGH (Koret-Karamitas Hash).
    Simplified version combining multiple features.
    """
    try:
        components = [
            str(features.nodes),
            str(features.edges),
            str(features.instruction_count),
            features.mnemonics_spp,
            str(features.constants_count)
        ]
        kgh_hash = hashlib.md5("|".join(components).encode()).hexdigest()[:16]
        return kgh_hash
    except Exception as e:
        logger.error(f"Error calculating KGH hash: {e}")
        return ""


def extract_function_features(db, func, binary_base: int = 0) -> FunctionFeatures:
    """
    Extract comprehensive function features for heuristics matching.
    """
    if not IDA_AVAILABLE:
        raise ImportError("ida_domain is not available. IDA Pro with ida_domain package is required.")
    
    try:
        name = db.functions.get_name(func) or f"sub_{func.start_ea:X}"
        address = func.start_ea
        size = func.end_ea - func.start_ea
        rva = address - binary_base if binary_base > 0 else address
        
        # Extract CFG features
        cfg_features = extract_cfg_features(db, func)
        
        # Extract instructions and mnemonics
        mnemonics, mnemonics_str, mnemonics_spp = extract_mnemonics(db, func)
        instruction_count = len(mnemonics)
        
        # Extract bytes hashes
        bytes_hash, function_hash = extract_bytes_hash(db, func)
        
        # Extract constants
        constants_list, constants_json, constants_count = extract_constants(db, func)
        
        # Extract assembly
        assembly, clean_assembly = extract_assembly(db, func)
        
        # Extract pseudocode
        try:
            pseudocode_lines = db.functions.get_pseudocode(func)
            pseudocode = "\n".join(pseudocode_lines) if pseudocode_lines else ""
            clean_pseudocode = clean_name(pseudocode)
            pseudocode_line_count = len(pseudocode_lines) if pseudocode_lines else 0
        except Exception as e:
            logger.debug(f"Error getting pseudocode: {e}")
            pseudocode = ""
            clean_pseudocode = ""
            pseudocode_line_count = 0
        
        # Extract pseudocode hashes
        pseudocode_hash, hash1, hash2, hash3 = extract_pseudocode_hashes(pseudocode)
        
        # Get signature
        try:
            signature = db.functions.get_signature(func) or ""
        except Exception:
            signature = ""
        
        # Calculate MD index
        md_index = calculate_md_index(cfg_features, mnemonics)
        
        # Create features object
        features = FunctionFeatures(
            name=name,
            address=address,
            size=size,
            nodes=cfg_features["nodes"],
            edges=cfg_features["edges"],
            indegree=cfg_features["indegree"],
            outdegree=cfg_features["outdegree"],
            cyclomatic_complexity=cfg_features["cyclomatic_complexity"],
            instruction_count=instruction_count,
            mnemonics=mnemonics_str,
            mnemonics_spp=mnemonics_spp,
            bytes_hash=bytes_hash,
            function_hash=function_hash,
            pseudocode_hash=pseudocode_hash,
            pseudocode_hash1=hash1,
            pseudocode_hash2=hash2,
            pseudocode_hash3=hash3,
            pseudocode=pseudocode,
            pseudocode_lines=pseudocode_line_count,
            clean_pseudocode=clean_pseudocode,
            assembly=assembly,
            clean_assembly=clean_assembly,
            constants=constants_json,
            constants_count=constants_count,
            signature=signature,
            rva=rva,
            segment_rva=rva,  # Simplified
            md_index=md_index,
            primes_value=mnemonics_spp,  # Simplified
            pseudocode_primes=calculate_small_primes_product(pseudocode.split()) if pseudocode else "1"
        )
        
        # Calculate KGH hash
        features.kgh_hash = calculate_kgh_hash(features)
        
        # Extract basic block mnemonic hashes (Ghidra-style correlator)
        try:
            from diffrays.correlator import extract_basic_block_hashes
            block_hashes_list = extract_basic_block_hashes(db, func)
            features.block_hashes = json.dumps(block_hashes_list) if block_hashes_list else "[]"
        except Exception as e:
            logger.debug(f"Error extracting block hashes: {e}")
            features.block_hashes = "[]"
        
        return features
        
    except Exception as e:
        logger.error(f"Error extracting function features: {e}")
        # Return minimal features
        return FunctionFeatures(
            name=db.functions.get_name(func) or f"sub_{func.start_ea:X}",
            address=func.start_ea,
            size=func.end_ea - func.start_ea
        )

