from __future__ import annotations
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from flask import Flask, g, render_template, request, abort, url_for, redirect, send_from_directory
from diffrays.log import log
import logging
import sqlite3
import zlib
import difflib
import re
import os
import json

# -----------------------------
# Data classes
# -----------------------------
@dataclass
class FunctionInfo:
    name: str
    old_text: Optional[str]
    new_text: Optional[str]
    modification_score: float = 0.0
    modification_level: str = "unchanged"

    def compute_modification_score(self) -> float:
        if not self.old_text or not self.new_text:
            return 1.0
        if self.old_text == self.new_text:
            return 0.0
        matcher = difflib.SequenceMatcher(None, self.old_text, self.new_text)
        similarity = matcher.ratio()
        return 1.0 - similarity

    def determine_modification_level(self) -> str:
        score = self.compute_modification_score()
        self.modification_score = score
        if score == 0.0:
            return "unchanged"
        elif score < 0.1:
            return "minor"
        elif score < 0.3:
            return "moderate"
        elif score < 0.6:
            return "significant"
        else:
            return "major"

# -----------------------------
# Utility helpers
# -----------------------------

def decompress(blob: Optional[bytes]) -> Optional[str]:
    if blob is None:
        return None
    try:
        return zlib.decompress(blob).decode("utf-8", errors="replace")
    except Exception:
        # Return raw bytes decoded best-effort if decompression fails
        try:
            return blob.decode("utf-8", errors="replace")
        except Exception:
            return None

# -----------------------------
# App factory & DB helpers
# -----------------------------

def create_app(db_path: str, log_file: Optional[str] = None, host: str = "127.0.0.1", port: int = 5050, debug_mode=False):
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))
    app.static_folder = os.path.join(os.path.dirname(__file__), 'static')
    app.config["DB_PATH"] = str(Path(db_path).resolve())
    app.config["HOST"] = host
    app.config["PORT"] = port

    # In-memory caches
    # CATEGORIES_CACHE: Dict[level, List[FunctionInfo]] -- computed once and reused
    # FUNC_META: Dict[function_name, {'has_old':bool,'has_new':bool,'old_meta':..., 'new_meta':..., 'size_old':int, 'size_new':int}]
    # SCORE_CACHE: Dict[function_name, (score, level)] -- stores computed scores
    app.config.setdefault("CATEGORIES_CACHE", None)
    app.config.setdefault("FUNC_META", {})
    app.config.setdefault("SCORE_CACHE", {})

    if debug_mode:
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)

    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory(app.static_folder, filename)

    @app.before_request
    def _log_request():
        app.logger.info("HTTP %s %s", request.method, request.path)

    def get_conn() -> sqlite3.Connection:
        if "db_conn" not in g:
            path = app.config["DB_PATH"]
            if not Path(path).exists():
                app.logger.error("DB not found at %s", path)
                abort(500, description=f"DB not found at {path}")
            # Use default connection per-request (Flask's g)
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            g.db_conn = conn
            app.logger.debug("Opened SQLite connection to %s", path)
        return g.db_conn

    @app.teardown_appcontext
    def close_conn(exc):
        conn = g.pop("db_conn", None)
        if conn is not None:
            conn.close()
            app.logger.debug("Closed SQLite connection")

    def ensure_indices(conn: sqlite3.Connection):
        # Create helpful indices if not present. Safe to run repeatedly.
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_functions_name_version ON functions(function_name, binary_version)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(function_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_function_diffs_name ON function_diffs(function_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_function_diffs_ratio ON function_diffs(ratio)")
            conn.commit()
        except Exception:
            # Non-fatal: some read-only DBs or older schemas may not allow DDL
            conn.rollback()

    def detect_schema(conn: sqlite3.Connection) -> Dict[str, bool]:
        cols_functions = [r[1] for r in conn.execute("PRAGMA table_info(functions)").fetchall()]
        cols_wide = [r[1] for r in conn.execute("PRAGMA table_info(function_diffs)").fetchall()]
        schema = {
            "has_wide": all(c in cols_wide for c in ["function_name", "old_pseudocode", "new_pseudocode", "ratio", "s_ratio"]),
            "has_tall": all(c in cols_functions for c in ["function_name", "binary_version", "pseudocode"]),
        }
        if not schema["has_wide"] and not schema["has_tall"]:
            app.logger.error("Unsupported schema. functions cols: %s; function_diffs cols: %s", cols_functions, cols_wide)
        else:
            app.logger.info("Detected schema: %s", "wide" if schema["has_wide"] else "tall")
        return schema

    def build_function_meta(conn: sqlite3.Connection):
        """
        Build lightweight metadata for functions. Prefer wide table to avoid decompression.
        """
        func_meta: Dict[str, Any] = {}
        schema = detect_schema(conn)
        if schema.get("has_wide"):
            rows = conn.execute(
                "SELECT function_name, LENGTH(old_pseudocode) as size_old, LENGTH(new_pseudocode) as size_new, "
                "old_address, new_address, old_blocks, new_blocks, old_signature, new_signature, ratio, s_ratio "
                "FROM function_diffs"
            ).fetchall()
            for r in rows:
                name = r["function_name"]
                func_meta[name] = {
                    "old": True if r["size_old"] else None,
                    "new": True if r["size_new"] else None,
                    "old_meta": {"address": r["old_address"], "blocks": r["old_blocks"], "signature": r["old_signature"]},
                    "new_meta": {"address": r["new_address"], "blocks": r["new_blocks"], "signature": r["new_signature"]},
                    "size_old": r["size_old"] or 0,
                    "size_new": r["size_new"] or 0,
                    "ratio": r["ratio"],
                    "s_ratio": r["s_ratio"],
                }
            app.config["FUNC_META"] = func_meta
            return func_meta
        # Fallback to tall schema
        rows = conn.execute("SELECT function_name, binary_version, LENGTH(pseudocode) as size, address, blocks, signature FROM functions").fetchall()
        for r in rows:
            name = r["function_name"]
            ver = r["binary_version"]
            if name not in func_meta:
                func_meta[name] = {
                    "old": None,
                    "new": None,
                    "old_meta": {"address": None, "blocks": None, "signature": None},
                    "new_meta": {"address": None, "blocks": None, "signature": None},
                    "size_old": 0,
                    "size_new": 0,
                }
            if ver == 'old':
                func_meta[name]["old"] = True
                func_meta[name]["size_old"] = r["size"] or 0
                func_meta[name]["old_meta"] = {"address": r["address"], "blocks": r["blocks"], "signature": r["signature"]}
            elif ver == 'new':
                func_meta[name]["new"] = True
                func_meta[name]["size_new"] = r["size"] or 0
                func_meta[name]["new_meta"] = {"address": r["address"], "blocks": r["blocks"], "signature": r["signature"]}
        app.config["FUNC_META"] = func_meta
        return func_meta

    def fetch_binary_metadata(conn: sqlite3.Connection) -> Dict[str, Any]:
        rows = conn.execute("SELECT binary_version, address_min, address_max, function_count, metadata_blob FROM binaries").fetchall()
        result: Dict[str, Any] = {"old": None, "new": None}
        for r in rows:
            try:
                data_text = decompress(r["metadata_blob"]) or "{}"
                parsed = None
                try:
                    parsed = json.loads(data_text)
                except Exception:
                    parsed = {"raw_text": data_text}
                result[r["binary_version"]] = {
                    "address_min": r["address_min"],
                    "address_max": r["address_max"],
                    "function_count": r["function_count"],
                    "metadata": parsed,
                }
            except Exception as e:
                app.logger.exception("Failed to parse metadata for %s: %s", r["binary_version"], e)
        return result

    def fetch_function_pair(conn: sqlite3.Connection, func_name: str) -> Tuple[Optional[str], Optional[str]]:
        # Fetch both versions in one query -- faster than two separate queries
        rows = conn.execute(
            "SELECT binary_version, pseudocode FROM functions WHERE function_name = ? AND binary_version IN ('old','new')",
            (func_name,)
        ).fetchall()
        old_text = None
        new_text = None
        for r in rows:
            if r["binary_version"] == 'old':
                old_text = decompress(r["pseudocode"])
            elif r["binary_version"] == 'new':
                new_text = decompress(r["pseudocode"])
        app.logger.debug(f"Function {func_name}: old={bool(old_text)}, new={bool(new_text)}")
        return old_text, new_text

    def make_dracula_diff_html(file1_text, file2_text, file1_name="OLD", file2_name="NEW"):
        a = file1_text.splitlines(keepends=True) if file1_text else []
        b = file2_text.splitlines(keepends=True) if file2_text else []
        table = difflib.HtmlDiff().make_table(a, b, fromdesc=file1_name, todesc=file2_name)
        table = re.sub(r"</?a\b[^>]*>", "", table, flags=re.I)
        table = re.sub(r"<th[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</th>", "", table, flags=re.I|re.S)
        table = re.sub(r"<td[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</td>", "", table, flags=re.I|re.S)
        # Keep original styling from previous file (omitted here for brevity in code block)
        html = f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"/><title>Diff Output</title></head><body>{table}</body></html>"""
        return html

    def compute_all_categories_once(conn: sqlite3.Connection):
        """
        Compute categories on first need and cache results. This avoids recomputing for every request.
        It still decompresses pseudocode for each function once, which is required to get exact diffs.
        """
        if app.config.get("CATEGORIES_CACHE") is not None:
            return app.config["CATEGORIES_CACHE"]

        app.logger.info("Building function metadata cache and computing modification scores (one-time)")
        ensure_indices(conn)
        func_meta = build_function_meta(conn)

        # Use precomputed ratios from wide table when available
        functions_by_level = {"significant": [], "moderate": [], "minor": [], "major": [], "unchanged": [], "added": [], "removed": []}

        for name, meta in func_meta.items():
            if meta.get("ratio") is not None:
                score = float(meta["ratio"])  # ratio is change score here (1 - sim)
                if score == 0.0:
                    level = "unchanged"
                elif score < 0.1:
                    level = "minor"
                elif score < 0.3:
                    level = "moderate"
                elif score < 0.6:
                    level = "significant"
                else:
                    level = "major"
                fi = FunctionInfo(name, None, None)
                fi.modification_score = score
                fi.modification_level = level
                functions_by_level[level].append(fi)
                app.config["SCORE_CACHE"][name] = (score, level)
                continue

            # Fallback path when wide ratios are not available
            if meta["old"] is None and meta["new"] is not None:
                fi = FunctionInfo(name, None, None)
                functions_by_level["added"].append(fi)
                continue
            if meta["old"] is not None and meta["new"] is None:
                fi = FunctionInfo(name, None, None)
                functions_by_level["removed"].append(fi)
                continue

            sig_old = meta["old_meta"].get("signature")
            sig_new = meta["new_meta"].get("signature")
            size_old = meta.get("size_old", 0) or 0
            size_new = meta.get("size_new", 0) or 0
            try_cheap = (sig_old is not None and sig_new is not None)
            if try_cheap and sig_old == sig_new and size_old == size_new:
                fi = FunctionInfo(name, "", "")
                fi.modification_score = 0.0
                fi.modification_level = "unchanged"
                functions_by_level["unchanged"].append(fi)
                app.config["SCORE_CACHE"][name] = (0.0, "unchanged")
                continue

            old_text, new_text = fetch_function_pair(conn, name)
            fi = FunctionInfo(name, old_text, new_text)
            level = fi.determine_modification_level()
            functions_by_level[level].append(fi)
            app.config["SCORE_CACHE"][name] = (fi.modification_score, level)

        # Attach meta references (addresses/signatures) so list pages can show them without decompression
        for lvl, lst in functions_by_level.items():
            for f in lst:
                m = func_meta.get(f.name, {})
                f.old_meta = m.get("old_meta") if isinstance(m, dict) else None
                f.new_meta = m.get("new_meta") if isinstance(m, dict) else None

        app.config["CATEGORIES_CACHE"] = functions_by_level
        return functions_by_level

    # -----------------------------
    # Routes
    # -----------------------------

    @app.route("/")
    def dashboard():
        conn = get_conn()
        try:
            categories = compute_all_categories_once(conn)
        except Exception as e:
            app.logger.exception("Failed to categorize functions: %s", e)
            abort(500, description="Failed to categorize functions")

        total = sum(len(v) for v in categories.values())
        changed = sum(len(v) for k, v in categories.items() if k in ["minor", "moderate", "significant", "major"])
        unchanged = len(categories["unchanged"]) if "unchanged" in categories else 0
        unmatched = len(categories["added"]) + len(categories["removed"]) if "added" in categories and "removed" in categories else 0

        counts = {
            "significant": len(categories.get("significant", [])) + len(categories.get("major", [])),
            "moderate": len(categories.get("moderate", [])),
            "minor": len(categories.get("minor", [])),
            "unchanged": unchanged,
            "unmatched": unmatched,
            "total": total,
            "changed": changed,
        }

        meta = fetch_binary_metadata(conn)
        return render_template(
            "dashboard.html",
            subtitle=f"Dashboard — {Path(app.config['DB_PATH']).name}",
            stats={"total": total, "changed": changed, "unchanged": unchanged, "unmatched": unmatched},
            counts=counts,
            meta=meta
        )

    @app.route("/diffs")
    def diffs_page():
        conn = get_conn()
        categories = compute_all_categories_once(conn)
        levels = ["significant", "moderate", "minor", "major"]
        filter_level = (request.args.get("level") or "").lower()
        if filter_level in levels:
            if filter_level == "significant":
                levels = ["significant", "major"]
            else:
                levels = [filter_level]
        items = []
        for lvl in levels:
            for f in categories.get(lvl, []):
                items.append({
                    "name": f.name,
                    "score": f.modification_score,
                    "old_addr": (f.old_meta or {}).get("address"),
                    "new_addr": (f.new_meta or {}).get("address"),
                    "old_blocks": (f.old_meta or {}).get("blocks"),
                    "new_blocks": (f.new_meta or {}).get("blocks"),
                    "signature": (f.new_meta or {}).get("signature") or (f.old_meta or {}).get("signature"),
                })
        return render_template(
            "list.html",
            title=(f"Diff Result — {levels[0].title()}" if filter_level else "Diff Result"),
            items=items,
            show_score=True,
            show_version=False,
            open_raw=False,
            current_tab='diffs',
            show_diff_columns=True
        )

    @app.route("/unchanged")
    def unchanged_page():
        conn = get_conn()
        categories = compute_all_categories_once(conn)
        items = []
        for f in categories.get("unchanged", []):
            items.append({
                "name": f.name,
                "version": "old",
                "old_addr": (getattr(f, 'old_meta', None) or {}).get("address"),
                "new_addr": (getattr(f, 'new_meta', None) or {}).get("address"),
                "signature": (getattr(f, 'new_meta', None) or {}).get("signature") or (getattr(f, 'old_meta', None) or {}).get("signature"),
            })
        return render_template(
            "list.html",
            title="Unchanged",
            items=items,
            show_score=False,
            show_version=False,
            open_raw=True,
            current_tab='unchanged',
            show_signature_only=True
        )

    @app.route("/unmatched")
    def unmatched_page():
        conn = get_conn()
        categories = compute_all_categories_once(conn)
        items = []
        for f in categories.get("added", []):
            items.append({
                "name": f.name,
                "version": "new",
                "old_addr": (getattr(f, 'old_meta', None) or {}).get("address"),
                "new_addr": (getattr(f, 'new_meta', None) or {}).get("address"),
                "signature": (getattr(f, 'new_meta', None) or {}).get("signature") or (getattr(f, 'old_meta', None) or {}).get("signature"),
            })
        for f in categories.get("removed", []):
            items.append({
                "name": f.name,
                "version": "old",
                "old_addr": (getattr(f, 'old_meta', None) or {}).get("address"),
                "new_addr": (getattr(f, 'new_meta', None) or {}).get("address"),
                "signature": (getattr(f, 'new_meta', None) or {}).get("signature") or (getattr(f, 'old_meta', None) or {}).get("signature"),
            })
        return render_template(
            "list.html",
            title="Unmatched",
            items=list(items),
            show_score=False,
            show_version=True,
            open_raw=True,
            current_tab='unmatched',
            show_signature_only=True
        )

    @app.route("/function/<path:name>")
    def function_view(name: str):
        conn = get_conn()
        # Prefer wide table for direct fetch of blobs
        schema = detect_schema(conn)
        old_text = None
        new_text = None
        if schema.get("has_wide"):
            r = conn.execute(
                "SELECT old_pseudocode, new_pseudocode FROM function_diffs WHERE function_name = ?",
                (name,)
            ).fetchone()
            if r:
                old_text = decompress(r["old_pseudocode"]) if r["old_pseudocode"] is not None else None
                new_text = decompress(r["new_pseudocode"]) if r["new_pseudocode"] is not None else None
        if old_text is None and new_text is None:
            old_text, new_text = fetch_function_pair(conn, name)
        has_old = bool(old_text)
        has_new = bool(new_text)
        app.logger.info(f"Function {name}: has_old={has_old}, has_new={has_new}")
        if not has_old and not has_new:
            return render_template("diff.html", name=name, has_old=False, has_new=False)

        meta = fetch_binary_metadata(conn)
        old_module = "OLD"
        new_module = "NEW"
        try:
            if meta and meta.get("old") and meta["old"].get("metadata") and meta["old"]["metadata"].get("metadata"):
                old_module = meta["old"]["metadata"]["metadata"].get("module", "OLD")
            if meta and meta.get("new") and meta["new"].get("metadata") and meta["new"]["metadata"].get("metadata"):
                new_module = meta["new"]["metadata"]["metadata"].get("module", "NEW")
        except Exception:
            pass

        diff_html = make_dracula_diff_html(old_text or "", new_text or "", f"{old_module}", f"{new_module}")
        return diff_html

    @app.route("/debug/functions")
    def debug_functions():
        conn = get_conn()
        # Stream minimal listing (no full pseudocode)
        rows = conn.execute(
            "SELECT function_name, binary_version, LENGTH(pseudocode) as size FROM functions ORDER BY function_name, binary_version"
        ).fetchall()
        result = "<h1>Database Contents</h1><table border='1'><tr><th>Function Name</th><th>Version</th><th>Size</th></tr>"
        for row in rows:
            result += f"<tr><td>{row['function_name']}</td><td>{row['binary_version']}</td><td>{row['size']}</td></tr>"
        result += "</table>"
        return result

    @app.route("/raw/<path:name>")
    def raw_view(name: str):
        version = (request.args.get("version") or "").lower()
        if version not in {"old", "new"}:
            return redirect(url_for("function_view", name=name))
        conn = get_conn()
        old_text, new_text = fetch_function_pair(conn, name)
        text = old_text if version == "old" else new_text
        return render_template(
            "raw.html",
            name=name,
            version=version,
            text=text or f"No content available for {version.upper()} version"
        )

    return app


def run_server(db_path: str, host: str = "127.0.0.1", port: int = 5555, log_file: Optional[str] = None, debug_mode=None):
    app = create_app(db_path=db_path, host=host, port=port, log_file=log_file, debug_mode=debug_mode)
    app.logger.info("Starting Flask on http://%s:%d (DB: %s)", host, port, db_path)
    app.run(host=host, port=port, debug=False)
