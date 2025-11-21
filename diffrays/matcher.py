#!/usr/bin/env python3
"""
Function matching module using Diaphora-inspired heuristics.

All heuristics operate on the data stored in the local SQLite database and rely
on features extracted through the modern IDA Domain API.
"""

import difflib
import logging
import re
import sqlite3
import textwrap
import zlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from diffrays.log import log as app_log

logger = logging.getLogger(__name__)
CALL_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_:$@?]{3,}")
PSEUDO_SUB_RE = re.compile(r"sub_[0-9A-Fa-f]+")
PSEUDO_PTR_RE = re.compile(r"\b(?:dword|word|byte|off|unk)_[0-9A-Fa-f]+\b", re.IGNORECASE)
PSEUDO_ADDR_RE = re.compile(r"0x[0-9A-Fa-f]+")


@dataclass
class Match:
    """Represents a matched function pair."""

    old_name: str
    new_name: str
    heuristic: str
    confidence: float
    old_address: int
    new_address: int


@dataclass(frozen=True)
class HeuristicDefinition:
    """Declarative description of a matching heuristic."""

    name: str
    category: str
    confidence: float
    condition: Optional[str] = None
    query: Optional[str] = None
    min_ratio: Optional[float] = None
    flags: Tuple[str, ...] = ()
    description: str = ""

    def build_query(self) -> str:
        if self.query:
            return self.query
        if not self.condition:
            raise ValueError(f"Heuristic '{self.name}' requires either condition or query")
        return BASE_SELECT.format(condition=self.condition)


def _sql(text: str) -> str:
    """Normalize multi-line SQL snippets."""
    return textwrap.dedent(text).strip()


BASE_SELECT = _sql(
    """
    SELECT DISTINCT
           f_old.function_name AS old_name,
           f_new.function_name AS new_name,
           COALESCE(f_old.address, 0) AS old_address,
           COALESCE(f_new.address, 0) AS new_address
      FROM functions AS f_old,
           functions AS f_new
            WHERE f_old.binary_version = 'old'
       AND f_new.binary_version = 'new'
       AND f_old.function_name != ''
       AND f_new.function_name != ''
       AND {condition}
    """
)


def _build_default_heuristics() -> Tuple[HeuristicDefinition, ...]:
    """Return the ordered list of heuristics modeled after Diaphora."""
    heuristics: List[HeuristicDefinition] = []

    heuristics.append(
        HeuristicDefinition(
            name="Same name",
            category="Best",
            confidence=1.0,
            condition=_sql(
                """
                f_old.function_name = f_new.function_name
                AND f_old.function_name NOT LIKE 'sub_%'
                AND f_old.function_name NOT LIKE 'nullsub%'
                """
            ),
        )
    )

    # Import thunk matching: __imp_FuncName <-> FuncName or _imp_FuncName <-> FuncName
    heuristics.append(
        HeuristicDefinition(
            name="Import thunk match",
            category="Best",
            confidence=0.98,
            condition=_sql(
                """
                (
                    (f_old.function_name LIKE '__imp_%' AND f_new.function_name = SUBSTR(f_old.function_name, 7))
                    OR (f_old.function_name LIKE '_imp_%' AND f_new.function_name = SUBSTR(f_old.function_name, 6))
                    OR (f_new.function_name LIKE '__imp_%' AND f_old.function_name = SUBSTR(f_new.function_name, 7))
                    OR (f_new.function_name LIKE '_imp_%' AND f_old.function_name = SUBSTR(f_new.function_name, 6))
                )
                AND f_old.function_name NOT LIKE 'sub_%'
                AND f_new.function_name NOT LIKE 'sub_%'
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same RVA and hash",
            category="Best",
            confidence=0.99,
            condition=_sql(
                """
                (f_old.rva = f_new.rva OR f_old.segment_rva = f_new.segment_rva)
              AND f_old.bytes_hash != ''
                AND f_old.bytes_hash = f_new.bytes_hash
                AND f_old.instruction_count = f_new.instruction_count
                AND f_old.nodes >= 3
                AND f_new.nodes >= 3
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Bytes hash",
            category="Best",
            confidence=0.97,
            condition=_sql(
                """
                f_old.bytes_hash != ''
                AND f_old.bytes_hash = f_new.bytes_hash
              AND f_old.instruction_count > 5
              AND f_new.instruction_count > 5
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Function hash",
            category="Best",
            confidence=0.96,
            condition=_sql(
                """
                f_old.function_hash != ''
                AND f_old.function_hash = f_new.function_hash
              AND f_old.nodes > 1
              AND f_new.nodes > 1
              AND (f_old.instruction_count > 5 OR f_new.instruction_count > 10)
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same address and mnemonics",
            category="Best",
            confidence=0.94,
            condition=_sql(
                """
                f_old.address IS NOT NULL
                AND f_old.address = f_new.address
                AND f_old.mnemonics = f_new.mnemonics
                AND f_old.instruction_count = f_new.instruction_count
                AND f_old.instruction_count > 5
                AND (
                    (f_old.function_name = f_new.function_name AND substr(f_old.function_name, 1, 4) != 'sub_')
                    OR substr(f_old.function_name, 1, 4) = 'sub_'
                    OR substr(f_new.function_name, 1, 4) = 'sub_'
                )
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same cleaned assembly",
            category="Best",
            confidence=0.92,
            condition=_sql(
                """
                f_old.clean_assembly != ''
                AND f_old.clean_assembly = f_new.clean_assembly
              AND f_old.nodes >= 3
              AND f_new.nodes >= 3
                AND f_old.function_name NOT LIKE 'nullsub%'
                AND f_new.function_name NOT LIKE 'nullsub%'
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same cleaned pseudocode",
            category="Best",
            confidence=0.92,
            condition=_sql(
                """
                f_old.clean_pseudocode != ''
                AND f_old.clean_pseudocode = f_new.clean_pseudocode
                AND f_old.pseudocode_lines > 5
                AND f_new.pseudocode_lines > 5
                AND f_old.function_name NOT LIKE 'nullsub%'
                AND f_new.function_name NOT LIKE 'nullsub%'
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Equal pseudocode",
            category="Best",
            confidence=0.95,
            condition=_sql(
                """
                f_old.pseudocode_hash != ''
                AND f_old.pseudocode_hash = f_new.pseudocode_hash
              AND f_old.pseudocode_lines >= 5
                AND f_new.pseudocode_lines >= 5
              AND f_old.function_name NOT LIKE 'nullsub%'
              AND f_new.function_name NOT LIKE 'nullsub%'
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Equal assembly",
            category="Best",
            confidence=0.93,
            condition=_sql(
                """
                f_old.assembly != ''
                AND f_old.assembly = f_new.assembly
              AND f_old.instruction_count >= 4
              AND f_new.instruction_count >= 4
              AND f_old.function_name NOT LIKE 'nullsub%'
              AND f_new.function_name NOT LIKE 'nullsub%'
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same address, nodes, edges and mnemonics",
            category="Best",
            confidence=0.9,
            condition=_sql(
                """
                f_old.rva = f_new.rva
                AND f_old.instruction_count = f_new.instruction_count
                AND f_old.nodes = f_new.nodes
                AND f_old.edges = f_new.edges
                AND f_old.mnemonics = f_new.mnemonics
              AND f_old.instruction_count > 3
              AND f_new.instruction_count > 3
              AND f_old.nodes > 1
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same RVA",
            category="Best",
            confidence=0.82,
            condition=_sql(
                """
                f_old.rva = f_new.rva
                AND f_old.nodes >= 3
                AND f_new.nodes >= 3
                AND (
                    (f_old.function_name = f_new.function_name AND substr(f_old.function_name, 1, 4) != 'sub_')
                    OR substr(f_old.function_name, 1, 4) = 'sub_'
                    OR substr(f_new.function_name, 1, 4) = 'sub_'
                )
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same constants",
            category="Partial",
            confidence=0.78,
            condition=_sql(
                """
                f_old.constants_count > 1
                AND f_old.constants = f_new.constants
                AND f_old.constants_count = f_new.constants_count
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same MD index and constants",
            category="Partial",
            confidence=0.82,
            condition=_sql(
                """
                f_old.md_index != ''
                AND f_old.md_index = f_new.md_index
                AND f_old.nodes >= 3
                AND f_new.nodes >= 3
                AND f_old.constants = f_new.constants
                AND f_old.constants_count > 0
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same MD index",
            category="Partial",
            confidence=0.74,
            condition=_sql(
                """
                f_old.md_index != ''
                AND f_old.md_index = f_new.md_index
              AND f_old.nodes >= 3
              AND f_new.nodes >= 3
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same KGH hash",
            category="Partial",
            confidence=0.75,
            condition=_sql(
                """
                f_old.kgh_hash != ''
                AND f_old.kgh_hash = f_new.kgh_hash
                AND f_old.nodes >= 4
                AND f_new.nodes >= 4
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same KGH hash and constants",
            category="Partial",
            confidence=0.83,
            condition=_sql(
                """
                f_old.kgh_hash != ''
                AND f_old.kgh_hash = f_new.kgh_hash
                AND f_old.constants = f_new.constants
                AND f_old.constants_count = f_new.constants_count
                AND f_old.nodes >= 3
                AND f_new.nodes >= 3
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same KGH hash and MD index",
            category="Partial",
            confidence=0.82,
            condition=_sql(
                """
                f_old.kgh_hash != ''
                AND f_old.kgh_hash = f_new.kgh_hash
              AND f_old.md_index != ''
                AND f_old.md_index = f_new.md_index
                AND f_old.nodes = f_new.nodes
                AND f_old.nodes >= 4
                AND f_old.outdegree = f_new.outdegree
                AND f_old.indegree = f_new.indegree
                AND (substr(f_old.function_name, 1, 4) = 'sub_' OR substr(f_new.function_name, 1, 4) = 'sub_')
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same rare KGH hash",
            category="Partial",
            confidence=0.72,
            query=_sql(
                """
                WITH rare_kgh AS (
                    SELECT kgh_hash
                      FROM functions
                     WHERE kgh_hash != ''
                     GROUP BY kgh_hash
                    HAVING COUNT(*) <= 2
                )
                SELECT DISTINCT
                       f_old.function_name AS old_name,
                       f_new.function_name AS new_name,
                       COALESCE(f_old.address, 0) AS old_address,
                       COALESCE(f_new.address, 0) AS new_address
            FROM functions AS f_old
                  JOIN functions AS f_new
                    ON f_old.binary_version = 'old'
               AND f_new.binary_version = 'new'
                   AND f_old.kgh_hash = f_new.kgh_hash
              AND f_old.kgh_hash != ''
                  JOIN rare_kgh
                    ON rare_kgh.kgh_hash = f_old.kgh_hash
                 WHERE f_old.nodes > 5
                   AND f_new.nodes > 5
                   AND (substr(f_old.function_name, 1, 4) = 'sub_' OR substr(f_new.function_name, 1, 4) = 'sub_')
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Same rare MD index",
            category="Partial",
            confidence=0.72,
            query=_sql(
                """
                WITH rare_md AS (
                    SELECT md_index
                      FROM functions
                     WHERE md_index != ''
                     GROUP BY md_index
                    HAVING COUNT(*) <= 2
                )
                SELECT DISTINCT
                       f_old.function_name AS old_name,
                       f_new.function_name AS new_name,
                       COALESCE(f_old.address, 0) AS old_address,
                       COALESCE(f_new.address, 0) AS new_address
            FROM functions AS f_old
                  JOIN functions AS f_new
                    ON f_old.binary_version = 'old'
               AND f_new.binary_version = 'new'
                   AND f_old.md_index = f_new.md_index
                   AND f_old.md_index != ''
                  JOIN rare_md
                    ON rare_md.md_index = f_old.md_index
                 WHERE f_old.nodes > 10
                   AND f_new.nodes > 10
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Mnemonics small primes product",
            category="Partial",
            confidence=0.68,
            condition=_sql(
                """
                f_old.mnemonics_spp != ''
                AND f_old.mnemonics_spp = f_new.mnemonics_spp
                AND f_old.instruction_count = f_new.instruction_count
                AND f_old.instruction_count > 5
                AND f_old.nodes > 1
                AND f_new.nodes > 1
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Pseudo-code AST hash",
            category="Partial",
            confidence=0.7,
            condition=_sql(
                """
                f_old.pseudocode_primes != ''
                AND length(f_old.pseudocode_primes) >= 35
                AND f_old.pseudocode_primes = f_new.pseudocode_primes
                AND f_old.pseudocode_lines >= 3
                """
            ),
        )
    )

    for idx, field in enumerate(("pseudocode_hash1", "pseudocode_hash2", "pseudocode_hash3"), start=1):
        heuristics.append(
            HeuristicDefinition(
                name=f"Pseudo-code fuzzy ({['normal','reverse','mixed'][idx-1]})",
                category="Partial",
                confidence=0.69 if idx == 1 else 0.68,
                condition=_sql(
                    f"""
                    f_old.{field} != ''
                    AND f_old.{field} = f_new.{field}
              AND f_old.pseudocode_lines > 5
              AND f_new.pseudocode_lines > 5
                    """
                ),
            )
        )

    for idx, field in enumerate(("pseudocode_hash1", "pseudocode_hash2", "pseudocode_hash3"), start=1):
        heuristics.append(
            HeuristicDefinition(
                name=f"Partial pseudo-code fuzzy ({['normal','reverse','mixed'][idx-1]})",
                category="Partial",
                confidence=0.6,
                condition=_sql(
                    f"""
                    f_old.{field} != ''
                    AND substr(f_old.{field}, 1, 16) = substr(f_new.{field}, 1, 16)
                    AND f_old.nodes > 5
                    AND f_new.nodes > 5
                    """
                ),
            )
        )

    heuristics.append(
        HeuristicDefinition(
            name="Similar pseudocode (any hash)",
            category="Partial",
            confidence=0.65,
            condition=_sql(
                """
                (
                    (f_old.pseudocode_hash1 != '' AND f_old.pseudocode_hash1 = f_new.pseudocode_hash1)
                    OR (f_old.pseudocode_hash2 != '' AND f_old.pseudocode_hash2 = f_new.pseudocode_hash2)
                    OR (f_old.pseudocode_hash3 != '' AND f_old.pseudocode_hash3 = f_new.pseudocode_hash3)
                )
                AND f_old.pseudocode_lines > 5
                AND f_new.pseudocode_lines > 5
                """
            ),
        )
    )

    heuristics.append(
        HeuristicDefinition(
            name="Similar structure",
            category="Partial",
            confidence=0.62,
            condition=_sql(
                """
                f_old.nodes = f_new.nodes
                AND f_old.edges = f_new.edges
                AND f_old.cyclomatic_complexity = f_new.cyclomatic_complexity
                AND f_old.mnemonics = f_new.mnemonics
              AND f_old.nodes > 3
              AND f_new.nodes > 3
                """
            ),
        )
    )

    return tuple(heuristics)


DEFAULT_HEURISTICS = _build_default_heuristics()


class HeuristicMatcher:
    """Matches functions using the declarative heuristic catalog."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        heuristics: Optional[Iterable[HeuristicDefinition]] = None,
    ):
        self.conn = conn
        if heuristics is None:
            self.heuristics: List[HeuristicDefinition] = list(DEFAULT_HEURISTICS)
        else:
            self.heuristics = list(heuristics)
        self.matched_old: Set[str] = set()
        self.matched_new: Set[str] = set()
        self.matches: List[Match] = []
        self._old_match_map: Dict[str, Match] = {}
        self._new_match_map: Dict[str, Match] = {}

    def find_matches(self) -> List[Match]:
        """Execute heuristics in order of confidence."""
        logger.info("Starting heuristic-based function matching (%d heuristics)...", len(self.heuristics))
        for heuristic in self.heuristics:
            self._run_heuristic(heuristic)
        self._find_block_correlation_matches()  # Ghidra correlator heuristic
        self._find_pseudocode_similarity_matches()  # Deep pseudocode similarity heuristic
        self._find_callee_diff_matches()
        self._post_validate_matches()
        self._validate_smart_ratio_matches()  # Remove incorrect matches (smart_ratio = 1.0)
        self._reevaluate_suspicious_matches()  # Re-evaluate matches with smart_ratio 0.4-1.0
        logger.info("Found %d total matches", len(self.matches))
        return self.matches

    def _is_already_matched(self, old_name: str, new_name: str) -> bool:
        """Check if either function already matched by a stronger heuristic."""
        return old_name in self.matched_old or new_name in self.matched_new

    def _remove_match(self, match: Match):
        """Remove a previously stored match."""
        try:
            self.matches.remove(match)
        except ValueError:
            pass
        self.matched_old.discard(match.old_name)
        self.matched_new.discard(match.new_name)
        self._old_match_map.pop(match.old_name, None)
        self._new_match_map.pop(match.new_name, None)

    def _add_match(
        self,
        old_name: str,
        new_name: str,
        heuristic: str,
        confidence: float,
        old_addr: int,
        new_addr: int,
    ):
        """Register a match."""
        existing_old = self._old_match_map.get(old_name)
        existing_new = self._new_match_map.get(new_name)

        if existing_old and existing_old.confidence >= confidence:
            return
        if existing_new and existing_new.confidence >= confidence:
            return

        if existing_old:
            logger.debug(
                "Replacing previous match for %s (%s %.2f -> %s %.2f)",
                old_name,
                existing_old.new_name,
                existing_old.confidence,
                new_name,
                confidence,
            )
            self._remove_match(existing_old)
        if existing_new:
            logger.debug(
                "Replacing previous match for %s (%s %.2f -> %s %.2f)",
                new_name,
                existing_new.old_name,
                existing_new.confidence,
                old_name,
                confidence,
            )
            self._remove_match(existing_new)
        if self._is_already_matched(old_name, new_name):
            return
        self.matches.append(
            Match(
                old_name=old_name,
                new_name=new_name,
                heuristic=heuristic,
                confidence=confidence,
                old_address=old_addr,
                new_address=new_addr,
            )
        )
        self.matched_old.add(old_name)
        self.matched_new.add(new_name)
        self._old_match_map[old_name] = self.matches[-1]
        self._new_match_map[new_name] = self.matches[-1]
        logger.debug("Matched %s <-> %s via %s (%.2f)", old_name, new_name, heuristic, confidence)

    def _run_heuristic(self, heuristic: HeuristicDefinition):
        """Execute a single heuristic and register new matches."""
        query = heuristic.build_query()
        logger.info("Running heuristic (%s): %s", heuristic.category, heuristic.name)
        try:
            cursor = self.conn.execute(query)
        except sqlite3.Error as exc:
            logger.error("Heuristic %s failed: %s", heuristic.name, exc)
            return

        matches_added = 0
        for old_name, new_name, old_addr, new_addr in cursor:
            if self._is_already_matched(old_name, new_name):
                continue
            self._add_match(
                old_name,
                new_name,
                heuristic.name,
                heuristic.confidence,
                int(old_addr or 0),
                int(new_addr or 0),
            )
            matches_added += 1

        if matches_added:
            logger.info("Heuristic %s produced %d matches", heuristic.name, matches_added)
        else:
            logger.debug("Heuristic %s produced no new matches", heuristic.name)

    # ------------------------------------------------------------------
    # Block correlation heuristic (Ghidra-style)
    # ------------------------------------------------------------------
    def _find_block_correlation_matches(
        self,
        min_correlation: float = 0.6,
        heuristic: str = "Block correlation (Ghidra)",
    ):
        """
        Match functions using Ghidra-style block correlation.
        This heuristic uses basic block mnemonic hashes to find structurally similar functions.
        """
        logger.info("Running heuristic: %s (min_correlation=%.2f)", heuristic, min_correlation)
        import json
        from diffrays.correlator import compute_correlation_from_hashes
        
        # Get all unmatched old functions with block hashes
        unmatched_old = []
        cursor = self.conn.execute(
            """
            SELECT function_name, block_hashes, address
            FROM functions
            WHERE binary_version = 'old'
              AND function_name NOT LIKE 'nullsub%'
              AND block_hashes IS NOT NULL
              AND block_hashes != ''
              AND block_hashes != '[]'
            """
        )
        for row in cursor:
            func_name = row[0]
            if func_name not in self.matched_old:
                unmatched_old.append((func_name, row[1], int(row[2] or 0)))
        
        if not unmatched_old:
            logger.debug("No unmatched old functions with block hashes")
            return
        
        # Get all unmatched new functions with block hashes
        unmatched_new = {}
        cursor = self.conn.execute(
            """
            SELECT function_name, block_hashes, address
            FROM functions
            WHERE binary_version = 'new'
              AND function_name NOT LIKE 'nullsub%'
              AND block_hashes IS NOT NULL
              AND block_hashes != ''
              AND block_hashes != '[]'
            """
        )
        for row in cursor:
            func_name = row[0]
            if func_name not in self.matched_new:
                unmatched_new[func_name] = (row[1], int(row[2] or 0))
        
        if not unmatched_new:
            logger.debug("No unmatched new functions with block hashes")
            return
        
        logger.info("Comparing %d old functions against %d new functions using block correlation...", 
                   len(unmatched_old), len(unmatched_new))
        
        matches_found = 0
        for old_name, block_hashes_old, old_addr in unmatched_old:
            try:
                # Parse old function's block hashes
                try:
                    hashes_old = json.loads(block_hashes_old) if isinstance(block_hashes_old, str) else block_hashes_old
                except (json.JSONDecodeError, TypeError):
                    continue
                
                if not hashes_old or not isinstance(hashes_old, list) or len(hashes_old) == 0:
                    continue
                
                # Find best match among unmatched new functions
                best_candidate = None
                best_correlation = 0.0
                best_addr = 0
                
                for new_name, (block_hashes_new, new_addr) in unmatched_new.items():
                    try:
                        # Parse new function's block hashes
                        try:
                            hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                        except (json.JSONDecodeError, TypeError):
                            continue
                        
                        if not hashes_new or not isinstance(hashes_new, list) or len(hashes_new) == 0:
                            continue
                        
                        # Compute correlation
                        correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                        
                        if correlation > best_correlation and correlation >= min_correlation:
                            best_correlation = correlation
                            best_candidate = new_name
                            best_addr = new_addr
                            
                    except Exception as e:
                        logger.debug(f"Error comparing {old_name} with {new_name}: {e}")
                        continue
                
                # If we found a good match, add it
                if best_candidate and best_correlation >= min_correlation:
                    # Confidence based on correlation: 0.6 -> 0.7, 0.8 -> 0.85, 1.0 -> 0.95
                    confidence = min(0.7 + (best_correlation - min_correlation) / (1.0 - min_correlation) * 0.25, 0.95)
                    
                    # Check if this new function is already matched (shouldn't happen, but safety check)
                    if best_candidate in self.matched_new:
                        # Check if existing match is weaker
                        existing_match = self._new_match_map.get(best_candidate)
                        if existing_match and confidence > existing_match.confidence:
                            logger.info(
                                "Block correlation found better match: %s <-> %s (correlation=%.3f, confidence=%.2f) "
                                "replacing existing match %s <-> %s (confidence=%.2f)",
                                old_name, best_candidate, best_correlation, confidence,
                                existing_match.old_name, existing_match.new_name, existing_match.confidence
                            )
                            self._remove_match(existing_match)
                            self._add_match(old_name, best_candidate, heuristic, confidence, old_addr, best_addr)
                            matches_found += 1
                        continue
                    
                    logger.debug(
                        "Block correlation match: %s <-> %s (correlation=%.3f, confidence=%.2f)",
                        old_name, best_candidate, best_correlation, confidence
                    )
                    self._add_match(old_name, best_candidate, heuristic, confidence, old_addr, best_addr)
                    matches_found += 1
                    # Remove from unmatched set to avoid duplicate work
                    unmatched_new.pop(best_candidate, None)
                    
            except Exception as e:
                logger.debug(f"Error finding block correlation matches for {old_name}: {e}")
                continue
        
        if matches_found > 0:
            logger.info("Block correlation heuristic found %d matches", matches_found)
        else:
            logger.debug("Block correlation heuristic found no new matches")

    def _find_pseudocode_similarity_matches(
        self,
        min_ratio: float = 0.9,
        heuristic: str = "Pseudocode similarity (normalized)",
        max_old: int = 800,
    ):
        """
        Match functions by normalized pseudocode similarity.
        This acts as a fallback when structural/block hash matches fail.
        """
        logger.info("Running heuristic: %s (min_ratio=%.2f)", heuristic, min_ratio)

        # Gather unmatched old function names (limit to avoid huge runtime)
        cursor = self.conn.execute(
            """
            SELECT function_name
            FROM functions
            WHERE binary_version = 'old'
              AND function_name NOT LIKE 'nullsub%'
            """
        )
        unmatched_old = [row[0] for row in cursor if row[0] not in self.matched_old]

        if not unmatched_old:
            logger.debug("No unmatched old functions for pseudocode similarity heuristic")
            return

        processed = 0
        matches_found = 0

        for old_name in unmatched_old:
            if processed >= max_old:
                break
            processed += 1

            old_record = self._fetch_function_data(old_name, "old")
            if not old_record:
                continue
            old_text = self._normalize_pseudocode(self._get_pseudocode_text(old_record))
            if not old_text:
                continue

            lines = old_record.get("pseudocode_lines", len(old_text.splitlines()))
            min_lines = max(lines - 15, 1)
            max_lines = lines + 15
            nodes = old_record.get("nodes", 0)
            min_nodes = max(nodes - 8, 0) if nodes else 0
            max_nodes = nodes + 8 if nodes else 0

            # Query candidate new functions with similar size/structure
            candidates = self.conn.execute(
                """
                SELECT function_name, clean_pseudocode, pseudocode, pseudocode_lines, nodes, address
                FROM functions
                WHERE binary_version = 'new'
                  AND function_name NOT LIKE 'nullsub%'
                  AND pseudocode_lines BETWEEN ? AND ?
                """,
                (min_lines, max_lines),
            )

            best_name = None
            best_ratio = 0.0
            best_addr = 0

            for row in candidates:
                new_name = row[0]
                if new_name in self.matched_new:
                    continue

                candidate_nodes = row[4] or 0
                if nodes and candidate_nodes:
                    if candidate_nodes < min_nodes or candidate_nodes > max_nodes:
                        continue

                cand_text = row[1] or ""
                if not cand_text and row[2]:
                    try:
                        cand_text = zlib.decompress(row[2]).decode("utf-8", errors="replace")
                    except Exception:
                        cand_text = ""
                cand_text = self._normalize_pseudocode(cand_text)
                if not cand_text:
                    continue

                ratio = difflib.SequenceMatcher(None, old_text, cand_text).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_name = new_name
                    best_addr = int(row[5] or 0)
                if best_ratio >= 0.99:
                    break

            if best_name and best_ratio >= min_ratio:
                confidence = min(0.65 + (best_ratio - min_ratio) * 0.3 / (1.0 - min_ratio), 0.9)
                logger.debug(
                    "Pseudocode similarity match: %s <-> %s (ratio=%.3f, confidence=%.2f)",
                    old_name,
                    best_name,
                    best_ratio,
                    confidence,
                )
                self._add_match(
                    old_name,
                    best_name,
                    heuristic,
                    confidence,
                    old_record.get("address", 0),
                    best_addr,
                )
                matches_found += 1

        if matches_found:
            logger.info("Pseudocode similarity heuristic found %d matches", matches_found)
        else:
            logger.debug("Pseudocode similarity heuristic found no new matches")

    # ------------------------------------------------------------------
    # Callee diffing heuristic
    # ------------------------------------------------------------------
    def _fetch_function_data(self, name: str, version: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute(
            """
            SELECT address, nodes, instruction_count, assembly, clean_assembly,
                   clean_pseudocode, pseudocode, pseudocode_lines
              FROM functions
             WHERE function_name = ?
               AND binary_version = ?
            """,
            (name, version),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "address": int(row[0] or 0),
            "nodes": int(row[1] or 0),
            "instructions": int(row[2] or 0),
            "assembly": row[3] or "",
            "clean_assembly": row[4] or "",
            "clean_pseudocode": row[5] or "",
            "pseudocode_blob": row[6],
            "pseudocode_lines": int(row[7] or 0),
        }

    def _extract_call_names(self, text: str) -> List[str]:
        return [m.group(0) for m in CALL_NAME_RE.finditer(text)]

    def _normalize_pseudocode(self, text: str) -> str:
        if not text:
            return ""
        text = PSEUDO_SUB_RE.sub("sub_", text)
        text = PSEUDO_PTR_RE.sub("ptr_", text)
        text = PSEUDO_ADDR_RE.sub("0xADDR", text)
        return text

    def _get_pseudocode_text(self, record: Dict[str, Any]) -> str:
        if not record:
            return ""
        if record.get("clean_pseudocode"):
            return record["clean_pseudocode"]
        blob = record.get("pseudocode_blob")
        if blob:
            try:
                return zlib.decompress(blob).decode("utf-8", errors="replace")
            except Exception:
                return ""
        return ""

    def _try_match_callee_pair(self, old_name: str, new_name: str, heuristic: str) -> bool:
        if old_name == new_name:
            return False
        if self._is_already_matched(old_name, new_name):
            return False

        old_row = self._fetch_function_data(old_name, "old")
        new_row = self._fetch_function_data(new_name, "new")
        if not old_row or not new_row:
            return False

        nodes_old = old_row["nodes"]
        nodes_new = new_row["nodes"]
        if nodes_old < 3 or nodes_new < 3:
            return False
        min_nodes = min(nodes_old, nodes_new)
        max_nodes = max(nodes_old, nodes_new)
        if max_nodes == 0 or (min_nodes * 100) / max_nodes < 40:
            return False

        asm_old = old_row["clean_assembly"] or old_row["assembly"]
        asm_new = new_row["clean_assembly"] or new_row["assembly"]
        if not asm_old or not asm_new:
            return False

        ratio = difflib.SequenceMatcher(None, asm_old, asm_new).ratio()
        if ratio < 0.82:
            return False

        confidence = min(0.75 + (ratio * 0.2), 0.96)
        self._add_match(
            old_name,
            new_name,
            heuristic,
            confidence,
            old_row["address"],
            new_row["address"],
        )
        return True

    def _process_diff_block(
        self,
        minus_lines: List[str],
        plus_lines: List[str],
        processed: Set[Tuple[str, str]],
        heuristic: str,
    ) -> bool:
        if not minus_lines or not plus_lines:
            minus_lines.clear()
            plus_lines.clear()
            return False

        minus_names = self._extract_call_names("\n".join(minus_lines))
        plus_names = self._extract_call_names("\n".join(plus_lines))
        minus_lines.clear()
        plus_lines.clear()

        changed = False
        for old_name, new_name in zip(minus_names, plus_names):
            key = (old_name, new_name)
            if key in processed:
                continue
            processed.add(key)
            if self._try_match_callee_pair(old_name, new_name, heuristic):
                changed = True
        return changed

    def _diff_and_match_callees(
        self,
        old_name: str,
        new_name: str,
        field: str,
        heuristic: str,
        processed: Set[Tuple[str, str]],
    ) -> bool:
        old_row = self._fetch_function_data(old_name, "old")
        new_row = self._fetch_function_data(new_name, "new")
        if not old_row or not new_row:
            return False

        text_old = old_row["clean_assembly"] if field == "assembly" else old_row["assembly"]
        text_new = new_row["clean_assembly"] if field == "assembly" else new_row["assembly"]
        if not text_old or not text_new:
            return False

        diff_iter = difflib.unified_diff(
            text_old.splitlines(),
            text_new.splitlines(),
            lineterm="",
        )
        minus: List[str] = []
        plus: List[str] = []
        changed = False
        for line in diff_iter:
            if not line:
                continue
            prefix = line[0]
            if prefix == "-":
                minus.append(line)
            elif prefix == "+":
                plus.append(line)
            elif prefix == " ":
                if self._process_diff_block(minus, plus, processed, heuristic):
                    changed = True
        if self._process_diff_block(minus, plus, processed, heuristic):
            changed = True
        return changed

    def _find_callee_diff_matches(
        self,
        field: str = "assembly",
        heuristic: str = "Callee diffing matches assembly",
        max_iterations: int = 2,
    ):
        logger.info("Running heuristic: %s", heuristic)
        processed_pairs: Set[Tuple[str, str]] = set()
        iteration = 1
        while iteration <= max_iterations:
            start_count = len(self.matches)
            existing_matches = list(self.matches)
            for match in existing_matches:
                self._diff_and_match_callees(
                    match.old_name,
                    match.new_name,
                    field,
                    heuristic + f" (iteration {iteration})",
                    processed_pairs,
                )
            if len(self.matches) == start_count:
                break
            iteration += 1

    # ------------------------------------------------------------------
    # Post-match validation using pseudocode similarity
    # ------------------------------------------------------------------
    def _compute_match_ratio(self, match: Match) -> float:
        old_record = self._fetch_function_data(match.old_name, "old")
        new_record = self._fetch_function_data(match.new_name, "new")
        if not old_record or not new_record:
            return 0.0
        old_text = self._normalize_pseudocode(self._get_pseudocode_text(old_record))
        new_text = self._normalize_pseudocode(self._get_pseudocode_text(new_record))
        if not old_text or not new_text:
            return 0.0
        return difflib.SequenceMatcher(None, old_text, new_text).ratio()

    def _search_pseudocode_candidate(
        self,
        old_record: Dict[str, Any],
        current_match: Match,
        current_ratio: float,
    ) -> Optional[Tuple[str, int, float]]:
        old_text = self._normalize_pseudocode(self._get_pseudocode_text(old_record))
        if not old_text:
            return None
        # Use line count to narrow search - much faster than checking all functions
        lines = old_record.get("pseudocode_lines", 0) or len(old_text.splitlines())
        min_lines = max(lines - 10, 1)  # Wider range but still bounded
        max_lines = lines + 10
        # Also check nodes for structural similarity
        nodes = old_record.get("nodes", 0)
        min_nodes = max(nodes - 5, 1) if nodes > 0 else 1
        max_nodes = nodes + 5 if nodes > 0 else 1000
        
        cursor = self.conn.execute(
            """
            SELECT function_name, address, clean_pseudocode, pseudocode, pseudocode_lines, nodes
              FROM functions
             WHERE binary_version = 'new'
               AND function_name NOT LIKE 'nullsub%'
               AND function_name != ?
               AND pseudocode_lines BETWEEN ? AND ?
               AND (nodes = 0 OR nodes BETWEEN ? AND ?)
            LIMIT 200
            """,
            (current_match.new_name, min_lines, max_lines, min_nodes, max_nodes),
        )
        best_name = None
        best_addr = 0
        best_ratio = 0.0
        checked = 0
        for row in cursor:
            checked += 1
            cand_name = row[0]
            # Allow checking already-matched functions - we might need to swap matches
            cand_text = row[2] or ""
            if not cand_text and row[3]:
                try:
                    cand_text = zlib.decompress(row[3]).decode("utf-8", errors="replace")
                except Exception:
                    cand_text = ""
            cand_norm = self._normalize_pseudocode(cand_text)
            if not cand_norm:
                continue
            ratio = difflib.SequenceMatcher(None, old_text, cand_norm).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_name = cand_name
                best_addr = int(row[1] or 0)
            # Early exit if we found a very good match
            if best_ratio >= 0.98:
                break
        # More aggressive replacement: if we find a much better match (ratio >= 0.9 and significantly better)
        if best_name and best_ratio >= 0.9 and best_ratio - current_ratio >= 0.15:
            return best_name, best_addr, best_ratio
        return None

    def _post_validate_matches(self):
        logger.info("Running post-match pseudocode validation on %d matches", len(self.matches))
        # Only validate matches with low confidence or suspicious ratios
        # Run limited passes to allow cascading corrections
        max_passes = 2
        max_to_check = min(500, len(self.matches))  # Limit how many we check
        for pass_num in range(max_passes):
            snapshot = list(self.matches)
            # Prioritize checking matches with lower confidence first
            snapshot.sort(key=lambda m: m.confidence)
            changes_made = False
            checked = 0
            for match in snapshot:
                if checked >= max_to_check:
                    break
                checked += 1
                ratio = self._compute_match_ratio(match)
                # Check all matches, even if ratio seems okay - might be blocking a better match
                old_record = self._fetch_function_data(match.old_name, "old")
                if not old_record:
                    continue
                candidate = self._search_pseudocode_candidate(old_record, match, ratio)
                if not candidate:
                    continue
                # If candidate is already matched, check if we should swap
                if candidate[0] in self.matched_new:
                    # Find what the candidate is currently matched to
                    existing_match = next((m for m in self.matches if m.new_name == candidate[0]), None)
                    if existing_match:
                        # Check if swapping would improve both matches
                        existing_ratio = self._compute_match_ratio(existing_match)
                        # Compute ratio for the potential swap
                        old_record2 = self._fetch_function_data(existing_match.old_name, "old")
                        new_record2 = self._fetch_function_data(match.new_name, "new")
                        swap_ratio = 0.0
                        if old_record2 and new_record2:
                            old_text2 = self._normalize_pseudocode(self._get_pseudocode_text(old_record2))
                            new_text2 = self._normalize_pseudocode(self._get_pseudocode_text(new_record2))
                            if old_text2 and new_text2:
                                swap_ratio = difflib.SequenceMatcher(None, old_text2, new_text2).ratio()
                        if candidate[2] > ratio + 0.1 and candidate[2] > existing_ratio + 0.1:
                            logger.info(
                                "Swapping matches: %s<->%s and %s<->%s (ratios %.3f/%.3f -> %.3f/%.3f)",
                                match.old_name, match.new_name,
                                existing_match.old_name, existing_match.new_name,
                                ratio, existing_ratio,
                                candidate[2], swap_ratio
                            )
                            # Remove both matches
                            self._remove_match(match)
                            self._remove_match(existing_match)
                            # Add new matches
                            confidence1 = min(0.85 + candidate[2] * 0.1, 0.99)
                            self._add_match(
                                match.old_name,
                                candidate[0],
                                "Pseudocode diff refinement (swap)",
                                confidence1,
                                match.old_address,
                                candidate[1],
                            )
                            # Try to find a better match for the old new_name
                            if old_record2:
                                candidate2 = self._search_pseudocode_candidate(
                                    old_record2,
                                    Match(existing_match.old_name, match.new_name, "", 0.0, 0, 0),
                                    swap_ratio
                                )
                                if candidate2:
                                    confidence2 = min(0.85 + candidate2[2] * 0.1, 0.99)
                                    self._add_match(
                                        existing_match.old_name,
                                        candidate2[0],
                                        "Pseudocode diff refinement (swap)",
                                        confidence2,
                                        existing_match.old_address,
                                        candidate2[1],
                                    )
                                else:
                                    # Fallback: match to the freed function
                                    confidence2 = min(0.75 + existing_ratio * 0.1, 0.85)
                                    self._add_match(
                                        existing_match.old_name,
                                        match.new_name,
                                        "Pseudocode diff refinement (swap fallback)",
                                        confidence2,
                                        existing_match.old_address,
                                        match.new_address,
                                    )
                            changes_made = True
                            continue
                logger.info(
                    "Reassigning %s from %s to %s based on pseudocode ratio %.3f -> %.3f",
                    match.old_name,
                    match.new_name,
                    candidate[0],
                    ratio,
                    candidate[2],
                )
                self._remove_match(match)
                confidence = min(0.85 + candidate[2] * 0.1, 0.99)
                self._add_match(
                    match.old_name,
                    candidate[0],
                    "Pseudocode diff refinement",
                    confidence,
                    match.old_address,
                    candidate[1],
                )
                changes_made = True
            if not changes_made:
                logger.info("Post-validation pass %d: no changes, stopping", pass_num + 1)
                break
            logger.info("Post-validation pass %d completed, %d matches checked, %d total matches", 
                       pass_num + 1, checked, len(self.matches))

    def _validate_smart_ratio_matches(self):
        """
        Validate matches using smart ratio (Ghidra correlator).
        If smart_ratio >= 0.95 (completely different), the match is likely incorrect.
        Remove bad matches and try to find better ones.
        """
        logger.info("Validating matches using smart ratio (block correlation)...")
        import json
        from diffrays.correlator import compute_correlation_from_hashes
        
        bad_matches = []
        for match in list(self.matches):
            try:
                # Get block hashes for both functions
                old_row = self.conn.execute(
                    "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'old'",
                    (match.old_name,)
                ).fetchone()
                new_row = self.conn.execute(
                    "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'new'",
                    (match.new_name,)
                ).fetchone()
                
                if not old_row or not new_row:
                    continue
                
                block_hashes_old = old_row[0]
                block_hashes_new = new_row[0]
                
                if not block_hashes_old or not block_hashes_new:
                    continue
                
                # Parse block hashes
                try:
                    hashes_old = json.loads(block_hashes_old) if isinstance(block_hashes_old, str) else block_hashes_old
                    hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                except (json.JSONDecodeError, TypeError):
                    continue
                
                if not hashes_old or not hashes_new:
                    continue
                
                # Compute correlation (0.0 = completely different, 1.0 = identical)
                correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                smart_ratio = 1.0 - correlation  # Convert to change score
                
                # If smart_ratio >= 0.95, functions are completely different - match is likely wrong
                if smart_ratio >= 0.95:
                    message = (
                        f"Removing incorrect match: {match.old_name} <-> {match.new_name} "
                        f"(smart_ratio={smart_ratio:.3f}, correlation={correlation:.3f})"
                    )
                    app_log.info(message)
                    logger.debug(message)
                    bad_matches.append((match, correlation))
                    
            except Exception as e:
                logger.debug(f"Error validating match {match.old_name} <-> {match.new_name}: {e}")
                continue
        
        # Remove bad matches
        for match, _ in bad_matches:
            self._remove_match(match)
        
        if not bad_matches:
            logger.info("All matches validated successfully (smart_ratio < 0.95)")
            return
        
        logger.info("Removed %d incorrect matches (smart_ratio >= 0.95), attempting to find better matches...", len(bad_matches))
        
        # Try to find better matches for the functions that had bad matches
        # Use fast block hash correlation to find better candidates
        self._find_better_matches_using_correlator(bad_matches)
    
    def _find_better_matches_using_correlator(self, bad_matches: List[Tuple[Match, float]]):
        """
        Find better matches for functions that had incorrect matches.
        Uses fast block hash correlation to find candidates.
        """
        import json
        from diffrays.correlator import compute_correlation_from_hashes
        
        logger.info("Searching for better matches using block correlation...")
        
        # Get all unmatched new functions (for fast lookup)
        unmatched_new = set()
        cursor = self.conn.execute(
            "SELECT function_name, block_hashes FROM functions WHERE binary_version = 'new'"
        )
        for row in cursor:
            func_name = row[0]
            if func_name not in self.matched_new:
                unmatched_new.add((func_name, row[1]))
        
        if not unmatched_new:
            logger.info("No unmatched functions available for re-matching")
            return
        
        matches_found = 0
        for bad_match, _ in bad_matches:
            old_name = bad_match.old_name
            try:
                # Get old function's block hashes
                old_row = self.conn.execute(
                    "SELECT block_hashes, address FROM functions WHERE function_name = ? AND binary_version = 'old'",
                    (old_name,)
                ).fetchone()
                
                if not old_row or not old_row[0]:
                    continue
                
                try:
                    hashes_old = json.loads(old_row[0]) if isinstance(old_row[0], str) else old_row[0]
                except (json.JSONDecodeError, TypeError):
                    continue
                
                if not hashes_old:
                    continue
                
                # Find best match among unmatched functions
                best_candidate = None
                best_correlation = 0.0
                best_addr = 0
                
                for new_name, block_hashes_new in unmatched_new:
                    if not block_hashes_new:
                        continue
                    
                    try:
                        hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                    except (json.JSONDecodeError, TypeError):
                        continue
                    
                    if not hashes_new:
                        continue
                    
                    # Compute correlation
                    correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                    
                    # Only consider if correlation is significantly better (at least 0.3)
                    # and better than the bad match (which had correlation < 0.05)
                    if correlation > best_correlation and correlation >= 0.3:
                        best_correlation = correlation
                        best_candidate = new_name
                        # Get address for the new function
                        addr_row = self.conn.execute(
                            "SELECT address FROM functions WHERE function_name = ? AND binary_version = 'new'",
                            (new_name,)
                        ).fetchone()
                        best_addr = int(addr_row[0] or 0) if addr_row else 0
                
                # If we found a better match, add it
                if best_candidate and best_correlation >= 0.3:
                    smart_ratio = 1.0 - best_correlation
                    logger.info(
                        "Found better match for %s: %s (correlation=%.3f, smart_ratio=%.3f)",
                        old_name, best_candidate, best_correlation, smart_ratio
                    )
                    # Use moderate confidence since we're using block correlation
                    confidence = min(0.7 + best_correlation * 0.2, 0.9)
                    self._add_match(
                        old_name,
                        best_candidate,
                        "Block correlation re-match",
                        confidence,
                        bad_match.old_address,
                        best_addr,
                    )
                    matches_found += 1
                    # Remove from unmatched set
                    unmatched_new = {(n, h) for n, h in unmatched_new if n != best_candidate}
                    
            except Exception as e:
                logger.debug(f"Error finding better match for {old_name}: {e}")
                continue
        
        if matches_found > 0:
            logger.info("Found %d better matches using block correlation", matches_found)
        else:
            logger.info("No better matches found for removed incorrect matches")
    
    def _reevaluate_suspicious_matches(self):
        """
        Re-evaluate matches with smart_ratio between 0.5 and 1.0 (suspicious range).
        These matches might be wrong - check against unmatched functions and other diff functions
        to find better matches.
        """
        import json
        from diffrays.correlator import compute_correlation_from_hashes
        
        logger.info("Re-evaluating suspicious matches (smart_ratio 0.4-1.0)...")
        
        # Find suspicious matches (smart_ratio 0.4-1.0)
        suspicious_matches = []
        for match in list(self.matches):
            try:
                old_row = self.conn.execute(
                    "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'old'",
                    (match.old_name,)
                ).fetchone()
                new_row = self.conn.execute(
                    "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'new'",
                    (match.new_name,)
                ).fetchone()
                
                if not old_row or not new_row or not old_row[0] or not new_row[0]:
                    continue
                
                try:
                    hashes_old = json.loads(old_row[0]) if isinstance(old_row[0], str) else old_row[0]
                    hashes_new = json.loads(new_row[0]) if isinstance(new_row[0], str) else new_row[0]
                except (json.JSONDecodeError, TypeError):
                    continue
                
                if not hashes_old or not hashes_new:
                    continue
                
                correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                smart_ratio = 1.0 - correlation
                
                # Suspicious range: 0.4 to 1.0 (correlation 0.6 to 0.0)
                if 0.4 <= smart_ratio <= 1.0:
                    suspicious_matches.append((match, correlation, smart_ratio))
                    
            except Exception as e:
                logger.debug(f"Error checking match {match.old_name} <-> {match.new_name}: {e}")
                continue
        
        if not suspicious_matches:
            logger.info("No suspicious matches found (smart_ratio 0.4-1.0)")
            return
        
        logger.info("Found %d suspicious matches to re-evaluate", len(suspicious_matches))
        
        # Get all unmatched functions with block hashes
        unmatched_old = {}
        unmatched_new = {}
        cursor = self.conn.execute(
            """
            SELECT function_name, block_hashes, address
            FROM functions
            WHERE binary_version = 'old'
              AND function_name NOT LIKE 'nullsub%'
              AND block_hashes IS NOT NULL
              AND block_hashes != ''
              AND block_hashes != '[]'
            """
        )
        for row in cursor:
            func_name = row[0]
            if func_name not in self.matched_old:
                unmatched_old[func_name] = (row[1], int(row[2] or 0))
        
        cursor = self.conn.execute(
            """
            SELECT function_name, block_hashes, address
            FROM functions
            WHERE binary_version = 'new'
              AND function_name NOT LIKE 'nullsub%'
              AND block_hashes IS NOT NULL
              AND block_hashes != ''
              AND block_hashes != '[]'
            """
        )
        for row in cursor:
            func_name = row[0]
            if func_name not in self.matched_new:
                unmatched_new[func_name] = (row[1], int(row[2] or 0))
        
        # Also get other matched functions (for potential swapping)
        other_matched_new = {}
        for other_match in self.matches:
            if other_match.new_name not in unmatched_new:
                try:
                    row = self.conn.execute(
                        "SELECT block_hashes, address FROM functions WHERE function_name = ? AND binary_version = 'new'",
                        (other_match.new_name,)
                    ).fetchone()
                    if row and row[0]:
                        other_matched_new[other_match.new_name] = (row[0], int(row[1] or 0))
                except Exception:
                    pass
        
        matches_improved = 0
        for match, current_correlation, current_smart_ratio in suspicious_matches:
            try:
                # Get old function's block hashes
                old_row = self.conn.execute(
                    "SELECT block_hashes, address FROM functions WHERE function_name = ? AND binary_version = 'old'",
                    (match.old_name,)
                ).fetchone()
                
                if not old_row or not old_row[0]:
                    continue
                
                try:
                    hashes_old = json.loads(old_row[0]) if isinstance(old_row[0], str) else old_row[0]
                except (json.JSONDecodeError, TypeError):
                    continue
                
                if not hashes_old:
                    continue
                
                # First, check if there's an exact name match available (excluding sub_*)
                exact_name_match = None
                if not match.old_name.startswith("sub_") and not match.old_name.startswith("nullsub"):
                    exact_row = self.conn.execute(
                        "SELECT address FROM functions WHERE function_name = ? AND binary_version = 'new'",
                        (match.old_name,)
                    ).fetchone()
                    if exact_row and match.old_name not in self.matched_new:
                        exact_name_match = (match.old_name, int(exact_row[0] or 0))
                
                # Search for better matches
                best_candidate = None
                best_correlation = current_correlation
                best_addr = 0
                best_source = None  # 'unmatched' or 'matched'
                
                # If exact name match exists, prefer it (but still check if current match is better)
                if exact_name_match:
                    exact_name, exact_addr = exact_name_match
                    # Get block hashes for exact match
                    exact_hash_row = self.conn.execute(
                        "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'new'",
                        (exact_name,)
                    ).fetchone()
                    if exact_hash_row and exact_hash_row[0]:
                        try:
                            exact_hashes_new = json.loads(exact_hash_row[0]) if isinstance(exact_hash_row[0], str) else exact_hash_row[0]
                            if exact_hashes_new:
                                exact_correlation = compute_correlation_from_hashes(hashes_old, exact_hashes_new)
                                # Prefer exact name match if correlation is reasonable (>= 0.3)
                                if exact_correlation >= 0.3:
                                    best_correlation = exact_correlation
                                    best_candidate = exact_name
                                    best_addr = exact_addr
                                    best_source = 'exact_name'
                        except Exception:
                            pass
                
                # Check unmatched new functions
                try:
                    for new_name, (block_hashes_new, new_addr) in unmatched_new.items():
                        if new_name == match.new_name:
                            continue
                        try:
                            hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                        except (json.JSONDecodeError, TypeError):
                            continue
                        if not hashes_new:
                            continue
                        
                        correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                        # Only consider if significantly better (at least 0.15 improvement)
                        if correlation > best_correlation + 0.15:
                            best_correlation = correlation
                            best_candidate = new_name
                            best_addr = new_addr
                            best_source = 'unmatched'
                except Exception:
                    pass
                
                # Check other matched functions (for potential swapping)
                try:
                    for new_name, (block_hashes_new, new_addr) in other_matched_new.items():
                        if new_name == match.new_name:
                            continue
                        try:
                            hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                        except (json.JSONDecodeError, TypeError):
                            continue
                        if not hashes_new:
                            continue
                        
                        correlation = compute_correlation_from_hashes(hashes_old, hashes_new)
                        # For swapping, require even better improvement (0.2) since we're disrupting existing matches
                        if correlation > best_correlation + 0.2:
                            # Check if swapping would improve both matches
                            existing_match = self._new_match_map.get(new_name)
                            if existing_match:
                                # Get correlation for the swap
                                existing_old_row = self.conn.execute(
                                    "SELECT block_hashes FROM functions WHERE function_name = ? AND binary_version = 'old'",
                                    (existing_match.old_name,)
                                ).fetchone()
                                if existing_old_row and existing_old_row[0]:
                                    try:
                                        existing_hashes_old = json.loads(existing_old_row[0]) if isinstance(existing_old_row[0], str) else existing_old_row[0]
                                        current_hashes_new = json.loads(block_hashes_new) if isinstance(block_hashes_new, str) else block_hashes_new
                                        if existing_hashes_old and current_hashes_new:
                                            swap_correlation = compute_correlation_from_hashes(existing_hashes_old, current_hashes_new)
                                            # Only swap if both matches improve
                                            if swap_correlation > current_correlation + 0.1:
                                                best_correlation = correlation
                                                best_candidate = new_name
                                                best_addr = new_addr
                                                best_source = 'matched'
                                    except Exception:
                                        pass
                except Exception:
                    pass
                
                # If we found a better match, replace it
                if best_candidate and best_correlation > current_correlation + 0.15:
                    new_smart_ratio = 1.0 - best_correlation
                    logger.info(
                        "Improving suspicious match: %s <-> %s (correlation %.3f->%.3f, smart_ratio %.3f->%.3f) from %s",
                        match.old_name, match.new_name,
                        current_correlation, best_correlation,
                        current_smart_ratio, new_smart_ratio,
                        best_source
                    )
                    
                    # If swapping with another match, handle both
                    if best_source == 'matched':
                        existing_match = self._new_match_map.get(best_candidate)
                        if existing_match:
                            self._remove_match(existing_match)
                            # Try to find a new match for the old new_name
                            # (This is simplified - could be improved)
                    
                    self._remove_match(match)
                    confidence = min(0.75 + best_correlation * 0.2, 0.95)
                    self._add_match(
                        match.old_name,
                        best_candidate,
                        f"Re-evaluation (suspicious match improved from {best_source})",
                        confidence,
                        match.old_address,
                        best_addr,
                    )
                    matches_improved += 1
                    
            except Exception as e:
                logger.debug(f"Error re-evaluating match {match.old_name} <-> {match.new_name}: {e}")
                continue
        
        if matches_improved > 0:
            logger.info("Improved %d suspicious matches through re-evaluation", matches_improved)
        else:
            logger.info("No improvements found for suspicious matches")

