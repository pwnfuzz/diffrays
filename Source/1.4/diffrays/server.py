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
    smart_ratio: float = 0.0
    id: Optional[int] = None
    old_meta: Optional[Dict[str, Any]] = None
    new_meta: Optional[Dict[str, Any]] = None


# -----------------------------
# App factory & DB helpers
# -----------------------------

def create_app(db_path: str, log_file: Optional[str] = None, host: str = "127.0.0.1", port: int = 5050, debug_mode=False):
    """
    Create a Flask app that serves function lists and HTML diffs from a diffrays SQLite DB.
    """
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))
    app.static_folder = os.path.join(os.path.dirname(__file__), 'static')
    app.config["DB_PATH"] = str(Path(db_path).resolve())
    app.config["HOST"] = host
    app.config["PORT"] = port

    if debug_mode:
        app.logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
    
    # If log file is specified, add a file handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        if debug:
            file_handler.setLevel(logging.DEBUG)
        else:
            file_handler.setLevel(logging.INFO)
        
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

    # -----------------------------
    # Schema detection
    # -----------------------------
    def detect_schema(conn: sqlite3.Connection) -> Dict[str, bool]:
        cols_functions = [r["name"] for r in conn.execute("PRAGMA table_info(functions)").fetchall()]
        cols_diff = [r["name"] for r in conn.execute("PRAGMA table_info(diff_results)").fetchall()]
        schema = {
            "has_tall": all(c in cols_functions for c in ["function_name", "binary_version", "pseudocode"]),
            "has_diff": all(c in cols_diff for c in [
                "id","function_name","old_pseudocode","new_pseudocode","ratio","smart_ratio"
            ]),
        }
        app.logger.info("Detected tables: functions=%s, diff_results=%s", bool(cols_functions), bool(cols_diff))
        return schema

    def decompress(blob: Optional[bytes]) -> Optional[str]:
        if blob is None:
            return None
        try:
            return zlib.decompress(blob).decode("utf-8", errors="replace")
        except Exception as e:
            app.logger.exception("Failed to decompress blob: %s", e)
            return None

    # -----------------------------
    # Data access with modification scoring
    # -----------------------------
    def get_all_functions_with_scores(conn: sqlite3.Connection) -> Dict[str, List[FunctionInfo]]:
        """Get all functions categorized by modification level using precomputed diff_results when available."""
        functions_by_level = {
            "significant": [],
            "moderate": [],
            "minor": [],
            "major": [],
            "unchanged": [],
            "added": [],
            "removed": []
        }

        schema = detect_schema(conn)
        func_dict: Dict[str, Dict[str, Any]] = {}

        if schema.get("has_diff"):
            # Use precomputed diffs for changed items
            rows = conn.execute(
                "SELECT id, function_name, old_pseudocode, new_pseudocode, old_address, new_address, old_blocks, new_blocks, old_signature, new_signature, ratio, smart_ratio, modification_level FROM diff_results"
            ).fetchall()
            for r in rows:
                old_text = decompress(r["old_pseudocode"]) if r["old_pseudocode"] else None
                new_text = decompress(r["new_pseudocode"]) if r["new_pseudocode"] else None
                fi = FunctionInfo(r["function_name"], old_text, new_text)
                fi.modification_score = 1.0 - float(r["ratio"] or 0.0)
                fi.smart_ratio = float(r["smart_ratio"] or 0.0)
                fi.id = r["id"]
                fi.old_meta = {"address": r["old_address"], "blocks": r["old_blocks"], "signature": r["old_signature"]}
                fi.new_meta = {"address": r["new_address"], "blocks": r["new_blocks"], "signature": r["new_signature"]}
                # Use precomputed modification level from database
                level = r["modification_level"] or "unchanged"
                if level in functions_by_level:
                    functions_by_level[level].append(fi)
                else:
                    # Fallback to significant if unknown level
                    functions_by_level["significant"].append(fi)

        # Also compute unmatched/unchanged using remaining functions table
        rows = conn.execute("SELECT function_name, binary_version, pseudocode, address, blocks, signature FROM functions").fetchall()
        for row in rows:
            func_name = row["function_name"]
            version = row["binary_version"]
            pseudocode = decompress(row["pseudocode"]) 
            address = row["address"]
            blocks = row["blocks"]
            signature = row["signature"]
            if func_name not in func_dict:
                func_dict[func_name] = {
                    "old": None, "new": None,
                    "old_meta": {"address": None, "blocks": None, "signature": None},
                    "new_meta": {"address": None, "blocks": None, "signature": None},
                }
            if version == "old":
                func_dict[func_name]["old"] = pseudocode
                func_dict[func_name]["old_meta"] = {"address": address, "blocks": blocks, "signature": signature}
            elif version == "new":
                func_dict[func_name]["new"] = pseudocode
                func_dict[func_name]["new_meta"] = {"address": address, "blocks": blocks, "signature": signature}

        for func_name, versions in func_dict.items():
            old_txt = versions["old"]
            new_txt = versions["new"]
            if old_txt is None and new_txt is not None:
                functions_by_level["added"].append(FunctionInfo(func_name, old_txt, new_txt))
            elif old_txt is not None and new_txt is None:
                functions_by_level["removed"].append(FunctionInfo(func_name, old_txt, new_txt))
            elif old_txt is not None and new_txt is not None and old_txt == new_txt:
                fi = FunctionInfo(func_name, old_txt, new_txt)
                fi.old_meta = versions["old_meta"]
                fi.new_meta = versions["new_meta"]
                functions_by_level["unchanged"].append(fi)

        # Attach meta for existing entries already added above
        for level, lst in functions_by_level.items():
            for f in lst:
                if not hasattr(f, 'old_meta'):
                    meta = func_dict.get(f.name, {})
                    f.old_meta = meta.get("old_meta") if isinstance(meta, dict) else None
                    f.new_meta = meta.get("new_meta") if isinstance(meta, dict) else None
        return functions_by_level

    def fetch_binary_metadata(conn: sqlite3.Connection) -> Dict[str, Any]:
        """Return a dict with keys 'old' and 'new' containing decompressed JSON metadata, and stats."""
        rows = conn.execute("SELECT binary_version, address_min, address_max, function_count, metadata_blob FROM binaries").fetchall()
        result: Dict[str, Any] = {"old": None, "new": None}
        for r in rows:
            try:
                data_text = decompress(r["metadata_blob"]) or "{}"
                # metadata_blob stores a JSON string; keep both parsed and raw
                parsed = None
                try:
                    import json
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
        """Returns (old_text, new_text) for a specific function"""
        # For tall schema, fetch both versions separately
        # Now we can safely use fetchone() since duplicates are prevented by UNIQUE constraint
        old_row = conn.execute(
            "SELECT pseudocode FROM functions WHERE function_name = ? AND binary_version = 'old'",
            (func_name,),
        ).fetchone()
        
        new_row = conn.execute(
            "SELECT pseudocode FROM functions WHERE function_name = ? AND binary_version = 'new'",
            (func_name,),
        ).fetchone()
        
        # Log for debugging
        app.logger.debug(f"Function {func_name}: old={old_row is not None}, new={new_row is not None}")
        
        old_text = decompress(old_row["pseudocode"]) if old_row else None
        new_text = decompress(new_row["pseudocode"]) if new_row else None
        
        return old_text, new_text


    def make_dracula_diff_html(file1_text, file2_text, file1_name="OLD", file2_name="NEW"):
        """Generate Dracula-themed diff HTML"""
        a = file1_text.splitlines(keepends=True) if file1_text else []
        b = file2_text.splitlines(keepends=True) if file2_text else []

        # Generate table only
        table = difflib.HtmlDiff().make_table(a, b, fromdesc=file1_name, todesc=file2_name)

        # Strip anchors
        table = re.sub(r"</?a\b[^>]*>", "", table, flags=re.I)

        # Remove nav col
        table = re.sub(r"<th[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</th>", "", table, flags=re.I|re.S)
        table = re.sub(r"<td[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</td>", "", table, flags=re.I|re.S)

        # Dracula theme HTML
        html = f"""
        <!doctype html>
        <html lang="en">
           <head>
              <meta charset="utf-8" />
              <title>Diff Output</title>
              <style>
                 body {{
                 margin:20px;
                 background:#282a36;
                 color:#f8f8f2;
                 font-family: 'Fira Code', Menlo, Consolas, monospace;
                 transition:.2s;
                 }}
                 
                 .header-container {{
                 display: flex;
                 justify-content: space-between;
                 align-items: center;
                 margin-bottom: 32px;
                 }}
                 
                 .controls {{
                 display: flex;
                 gap: 10px;
                 align-items: center;
                 }}
                 
                 .checkbox-container {{
                 display: flex;
                 align-items: center;
                 gap: 5px;
                 background: rgba(68, 71, 90, 0.9);
                 padding: 6px 10px;
                 border-radius: 6px;
                 color: #f8f8f2;
                 font-size: 14px;
                 }}
                 
                 #char-level-toggle {{
                 margin: 0;
                 }}
                 
                 table.diff {{
                 width:100%;
                 border-collapse:collapse;
                 border:1px solid #44475a;
                 font-size:14px;
                 box-shadow:0 2px 6px rgba(0,0,0,.4);
                 }}
                 .diff th {{
                 background:#44475a;
                 color:#f8f8f2;
                 padding:8px;
                 position:sticky;
                 top:0;
                 z-index:10;
                 }}
                 .diff td {{
                 padding:6px 10px;
                 vertical-align:top;
                 white-space:pre-wrap;
                 font-family: 'Fira Code', monospace;
                 }}
                 .diff .diff_header {{
                 background:#6272a4;
                 color:#f8f8f2;
                 font-weight:bold;
                 text-align:center;
                 }}
                 
                 /* Standard difflib highlighting */
                 .diff .diff_add {{
                 background:#244032;
                 color:#50fa7b;
                 }}
                 
                 .diff .diff_chg {{
                 background:#4b3d1f;
                 color:#ffb86c;
                 }}
                 
                 /* Hide character-level highlighting when checkbox is unchecked */
                 body.hide-char-level .diff .diff_chg {{
                 background: transparent !important;
                 color: inherit !important;
                 }}
                 
                 .diff .diff_sub {{
                 background:#4a2c32;
                 color:#ff5555;
                 }}
                 
                 /* Regular hover effects */
                 .diff tr:hover td {{
                 background:#383a59 !important;
                 }}
                 
                 .diff_next {{ display:none !important; }}
                 
                 /* Light mode styles */
                 body.light {{
                 background:#f8f9fa !important;
                 color:#212529 !important;
                 }}
                 body.light table.diff {{
                 border:1px solid #dee2e6;
                 }}
                 body.light .diff th {{
                 background:#e9ecef;
                 color:#495057;
                 position:sticky;
                 top:0;
                 z-index:10;
                 }}
                 body.light .diff .diff_header {{
                 background:#6c757d;
                 color:#fff;
                 }}
                 
                 body.light .checkbox-container {{
                 background: rgba(233, 236, 239, 0.9);
                 color: #495057;
                 }}
                 
                 /* Light mode highlighting */
                 body.light .diff .diff_add {{
                 background:#d4edda;
                 color:#155724;
                 }}
                 body.light .diff .diff_chg {{
                 background:#fff3cd;
                 color:#856404;
                 }}
                 body.light .diff .diff_sub {{
                 background:#f8d7da;
                 color:#721c24;
                 }}
                 
                 /* Light mode: Hide character-level highlighting when checkbox is unchecked */
                 body.light.hide-char-level .diff .diff_chg {{
                 background: transparent !important;
                 color: inherit !important;
                 }}
                 
                 /* Light mode hover effects */
                 body.light .diff tr:hover td {{
                 background:#e2e6ea !important;
                 }}
                 
                 #toggle-dark {{
                 padding:6px 12px; border:0; border-radius:6px;
                 background:#bd93f9; color:#282a36;
                 cursor:pointer; font-size:14px; font-weight:bold;
                 }}
                 #toggle-dark:hover {{
                 background:#ff79c6; color:#f8f8f2;
                 }}
                 body.light #toggle-dark {{
                 background:#007bff; color:#fff;
                 }}
                 body.light #toggle-dark:hover {{
                 background:#0056b3; color:#fff;
                 }}
              </style>
           </head>
           <body>
              <div class="header-container">
                 <div style="display:flex; gap:12px; align-items:center;">
                    <button onclick="goBack()" id="backBtn" style="padding:6px 10px;border:0;border-radius:6px;background:#6272a4;color:#f8f8f2;cursor:pointer;">← Back</button>
                    <h2 style="margin:0;">Diff between <code>{file1_name}</code> and <code>{file2_name}</code></h2>
                 </div>
                 <div class="controls">
                    <div class="checkbox-container">
                       <input type="checkbox" id="char-level-toggle" checked>
                       <label for="char-level-toggle">Character Level Highlight</label>
                    </div>
                    <button id="toggle-dark">🌙 Toggle Light Mode</button>
                 </div>
              </div>
              {table}
              <script>
                 // Initialize theme from localStorage
                 (function(){{
                     try {{
                         const saved = localStorage.getItem('diffrays-theme');
                         if (saved === 'light') {{ 
                             document.body.classList.add('light'); 
                             document.documentElement.setAttribute('data-theme', 'light');
                             // Update button text to reflect current state
                             const btn = document.getElementById('toggle-dark');
                             if (btn) btn.textContent = "🌙 Toggle Dark Mode";
                         }}
                     }} catch(e) {{}}
                 }})();

                 // Back button helper
                 function goBack(){{
                     if (history.length > 1) {{ history.back(); return; }}
                     try {{
                         const ref = document.referrer || '';
                         if (ref.includes('/diffs')) location.href = '/diffs';
                         else if (ref.includes('/unchanged')) location.href = '/unchanged';
                         else if (ref.includes('/unmatched')) location.href = '/unmatched';
                         else location.href = '/';
                     }} catch(e) {{ location.href = '/'; }}
                 }}

                 const btn = document.getElementById('toggle-dark');
                 const charLevelToggle = document.getElementById('char-level-toggle');
                 let light = document.body.classList.contains('light');
                 
                 // Dark/Light mode toggle
                 btn.addEventListener('click', () => {{
                     document.body.classList.toggle('light');
                     light = !light;
                     if(light){{
                       btn.textContent="🌙 Toggle Dark Mode";
                     }} else {{
                       btn.textContent="🌙 Toggle Light Mode";
                     }}
                     try {{ 
                         localStorage.setItem('diffrays-theme', light ? 'light' : 'dark'); 
                         // Also update the documentElement attribute to match main site behavior
                         document.documentElement.setAttribute('data-theme', light ? 'light' : 'dark');
                     }} catch(e) {{}}
                 }});
                 
                 // Character level highlighting toggle
                 charLevelToggle.addEventListener('change', () => {{
                     if (charLevelToggle.checked) {{
                         document.body.classList.remove('hide-char-level');
                     }} else {{
                         document.body.classList.add('hide-char-level');
                     }}
                 }});
              </script>
           </body>
        </html>
        """
        return html

    # -----------------------------
    # Routes
    # -----------------------------

    @app.route("/")
    def dashboard():
        conn = get_conn()
        try:
            categories = get_all_functions_with_scores(conn)
        except Exception as e:
            app.logger.exception("Failed to categorize functions: %s", e)
            abort(500, description="Failed to categorize functions")

        total = sum(len(v) for v in categories.values())
        changed = sum(len(v) for k, v in categories.items() if k in ["minor", "moderate", "significant", "major"])
        unchanged = len(categories["unchanged"]) if "unchanged" in categories else 0
        unmatched = len(categories["added"]) + len(categories["removed"]) if "added" in categories and "removed" in categories else 0

        counts = {
            # Treat everything above moderate threshold as significant (merge previous 'major')
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
            stats={
                "total": total,
                "changed": changed,
                "unchanged": unchanged,
                "unmatched": unmatched
            },
            counts=counts,
            meta=meta
        )

    @app.route("/diffs")
    def diffs_page():
        conn = get_conn()
        categories = get_all_functions_with_scores(conn)
        # Exclude added/removed and unchanged here as per request
        levels = ["significant", "moderate", "minor", "major"]
        filter_level = (request.args.get("level") or "").lower()
        if filter_level in levels:
            if filter_level == "significant":
                # Include both 'significant' and 'major' under significant
                levels = ["significant", "major"]
            else:
                levels = [filter_level]
        items = []
        for lvl in levels:
            for f in categories.get(lvl, []):
                items.append({
                    "id": getattr(f, 'id', None),
                    "name": f.name,
                    "score": f.modification_score,
                    "smart_ratio": f.smart_ratio,
                    "old_addr": (f.old_meta or {}).get("address"),
                    "new_addr": (f.new_meta or {}).get("address"),
                    "old_blocks": (f.old_meta or {}).get("blocks"),
                    "new_blocks": (f.new_meta or {}).get("blocks"),
                    "signature": (f.new_meta or {}).get("signature") or (f.old_meta or {}).get("signature"),
                })

        # Server-side search & pagination
        q = (request.args.get("q") or "").strip()
        q_lower = q.lower()
        if q_lower:
            items = [it for it in items if (it.get("name", "").lower().find(q_lower) != -1) or (str(it.get("signature") or "").lower().find(q_lower) != -1)]

        per_page = 500
        try:
            page = int(request.args.get("page", 1))
        except Exception:
            page = 1
        if page < 1:
            page = 1
        total_items = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        page_items = items[start:end]

        # Preserve extra query params for template links
        from urllib.parse import urlencode
        preserved = {k: v for k, v in request.args.items() if k not in {"page"}}
        base_query = urlencode(preserved)
        page_qs_prefix = ("?" + base_query + ("&" if base_query else ""))

        return render_template(
            "list.html",
            title=(f"Diff Result — {levels[0].title()}" if filter_level else "Diff Result"),
            items=page_items,
            show_score=True,
            show_version=False,
            open_raw=False,
            current_tab='diffs',
            show_diff_columns=True,
            q=q,
            page=page,
            per_page=per_page,
            total_items=total_items,
            page_qs_prefix=page_qs_prefix
        )

    @app.route("/unchanged")
    def unchanged_page():
        conn = get_conn()
        categories = get_all_functions_with_scores(conn)
        items = []
        for f in categories.get("unchanged", []):
            # Prefer the 'old' row id for stable viewing
            row = conn.execute(
                "SELECT id, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'old'",
                (f.name,),
            ).fetchone()
            func_id = row["id"] if row else None
            items.append({
                "id": None,
                "name": f.name,
                "version": "old",
                "old_addr": (getattr(f, 'old_meta', None) or {}).get("address"),
                "new_addr": (getattr(f, 'new_meta', None) or {}).get("address"),
                "signature": (getattr(f, 'new_meta', None) or {}).get("signature") or (getattr(f, 'old_meta', None) or {}).get("signature"),
                "func_id": func_id,
            })
        # Server-side search & pagination
        q = (request.args.get("q") or "").strip()
        q_lower = q.lower()
        if q_lower:
            items = [it for it in items if (it.get("name", "").lower().find(q_lower) != -1) or (str(it.get("signature") or "").lower().find(q_lower) != -1)]

        per_page = 500
        try:
            page = int(request.args.get("page", 1))
        except Exception:
            page = 1
        if page < 1:
            page = 1
        total_items = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        page_items = items[start:end]

        from urllib.parse import urlencode
        preserved = {k: v for k, v in request.args.items() if k not in {"page"}}
        base_query = urlencode(preserved)
        page_qs_prefix = ("?" + base_query + ("&" if base_query else ""))

        return render_template(
            "list.html",
            title="Unchanged",
            items=page_items,
            show_score=False,
            show_version=False,
            open_raw=True,
            current_tab='unchanged',
            show_signature_only=True,
            q=q,
            page=page,
            per_page=per_page,
            total_items=total_items,
            page_qs_prefix=page_qs_prefix
        )

    @app.route("/unmatched")
    def unmatched_page():
        conn = get_conn()
        categories = get_all_functions_with_scores(conn)
        items = []
        for f in categories.get("added", []):
            row = conn.execute(
                "SELECT id, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'new'",
                (f.name,),
            ).fetchone()
            func_id = row["id"] if row else None
            # Prefer metadata attached to f; if missing, fallback to direct row values
            new_meta = getattr(f, 'new_meta', None) or {}
            items.append({
                "id": None,
                "name": f.name,
                "version": "new",
                "old_addr": (getattr(f, 'old_meta', None) or {}).get("address"),
                "new_addr": new_meta.get("address") if new_meta.get("address") is not None else (row["address"] if row else None),
                "old_blocks": (getattr(f, 'old_meta', None) or {}).get("blocks"),
                "new_blocks": new_meta.get("blocks") if new_meta.get("blocks") is not None else (row["blocks"] if row else None),
                "signature": new_meta.get("signature") or ((row["signature"] if row else None) or (getattr(f, 'old_meta', None) or {}).get("signature")),
                "func_id": func_id,
            })
        for f in categories.get("removed", []):
            row = conn.execute(
                "SELECT id, address, blocks, signature FROM functions WHERE function_name = ? AND binary_version = 'old'",
                (f.name,),
            ).fetchone()
            func_id = row["id"] if row else None
            old_meta = getattr(f, 'old_meta', None) or {}
            items.append({
                "id": None,
                "name": f.name,
                "version": "old",
                "old_addr": old_meta.get("address") if old_meta.get("address") is not None else (row["address"] if row else None),
                "new_addr": (getattr(f, 'new_meta', None) or {}).get("address"),
                "old_blocks": old_meta.get("blocks") if old_meta.get("blocks") is not None else (row["blocks"] if row else None),
                "new_blocks": (getattr(f, 'new_meta', None) or {}).get("blocks"),
                "signature": (getattr(f, 'new_meta', None) or {}).get("signature") or (old_meta.get("signature") or (row["signature"] if row else None)),
                "func_id": func_id,
            })
        # Server-side search & pagination
        q = (request.args.get("q") or "").strip()
        q_lower = q.lower()
        if q_lower:
            items = [it for it in items if (it.get("name", "").lower().find(q_lower) != -1) or (str(it.get("signature") or "").lower().find(q_lower) != -1)]

        per_page = 500
        try:
            page = int(request.args.get("page", 1))
        except Exception:
            page = 1
        if page < 1:
            page = 1
        total_items = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        page_items = items[start:end]

        from urllib.parse import urlencode
        preserved = {k: v for k, v in request.args.items() if k not in {"page"}}
        base_query = urlencode(preserved)
        page_qs_prefix = ("?" + base_query + ("&" if base_query else ""))

        return render_template(
            "list.html",
            title="Unmatched",
            items=list(page_items),
            show_score=False,
            show_version=True,
            open_raw=True,
            current_tab='unmatched',
            show_signature_only=True,
            q=q,
            page=page,
            per_page=per_page,
            total_items=total_items,
            page_qs_prefix=page_qs_prefix
        )

    @app.route("/function/<int:item_id>")
    @app.route("/function/<path:name>")
    def function_view(item_id: int | None = None, name: str | None = None):
        conn = get_conn()
        # Detect whether we got item_id or name via Flask routing
        old_text = None
        new_text = None
        if item_id is not None:
            row = conn.execute(
                "SELECT function_name, old_pseudocode, new_pseudocode FROM diff_results WHERE id = ?",
                (item_id,),
            ).fetchone()
            if row:
                name = row["function_name"]
                old_text = decompress(row["old_pseudocode"]) if row["old_pseudocode"] else None
                new_text = decompress(row["new_pseudocode"]) if row["new_pseudocode"] else None
        if name is None:
            # Called via name-based route or id not found; fetch by name from tall schema
            name = name or request.view_args.get('name') or (str(item_id) if item_id is not None else None)
            if not name:
                abort(404)
            old_text, new_text = fetch_function_pair(conn, name)
        has_old = bool(old_text)
        has_new = bool(new_text)

        app.logger.info(f"Function {name}: has_old={has_old}, has_new={has_new}")
        
        # DEBUG: Check if content is actually different
        if has_old and has_new:
            if old_text == new_text:
                app.logger.warning(f"Function {name}: OLD and NEW content are IDENTICAL!")
            else:
                app.logger.info(f"Function {name}: Content differs, diff should show changes")
        
        if not has_old and not has_new:
            return render_template("diff.html", name=name, has_old=False, has_new=False)

        # Get module names from metadata
        meta = fetch_binary_metadata(conn)
        old_module = "OLD"
        new_module = "NEW"
        
        if meta and meta.get("old") and meta["old"].get("metadata") and meta["old"]["metadata"].get("metadata"):
            old_module = meta["old"]["metadata"]["metadata"].get("module", "OLD")
        if meta and meta.get("new") and meta["new"].get("metadata") and meta["new"]["metadata"].get("metadata"):
            new_module = meta["new"]["metadata"]["metadata"].get("module", "NEW")

        # Generate Dracula-themed diff
        diff_html = make_dracula_diff_html(old_text or "", new_text or "", f"{old_module}", f"{new_module}")
        return diff_html
    
    @app.route("/debug/functions")
    def debug_functions():
        conn = get_conn()
        functions = conn.execute(
            "SELECT function_name, binary_version, LENGTH(pseudocode) as size FROM functions ORDER BY function_name, binary_version"
        ).fetchall()
        
        result = "<h1>Database Contents</h1><table border='1'><tr><th>Function Name</th><th>Version</th><th>Size</th></tr>"
        for row in functions:
            result += f"<tr><td>{row['function_name']}</td><td>{row['binary_version']}</td><td>{row['size']}</td></tr>"
        result += "</table>"
        return result

    @app.route("/raw/<int:item_id>")
    @app.route("/raw/<path:name>")
    def raw_view(item_id: int | None = None, name: str | None = None):
        version = (request.args.get("version") or "").lower()
        if version not in {"old", "new"}:
            # Redirect preserving whichever route was used
            if 'name' in request.view_args or name is not None:
                return redirect(url_for("function_view", name=(name or request.view_args.get('name'))))
            return redirect(url_for("function_view", item_id=item_id))
        conn = get_conn()
        if name is not None or 'name' in request.view_args:
            name = name or request.view_args['name']
            old_text, new_text = fetch_function_pair(conn, name)
        else:
            row = conn.execute(
                "SELECT function_name, old_pseudocode, new_pseudocode FROM diff_results WHERE id = ?",
                (item_id,),
            ).fetchone()
            if row:
                name = row["function_name"]
                old_text = decompress(row["old_pseudocode"]) if row["old_pseudocode"] else None
                new_text = decompress(row["new_pseudocode"]) if row["new_pseudocode"] else None
            else:
                # Final fallback: not found
                abort(404)
        text = old_text if version == "old" else new_text
        
        return render_template(
            "raw.html",
            name=name,
            version=version,
            text=text or f"No content available for {version.upper()} version"
        )

    @app.route("/rawf/<int:func_id>")
    def raw_view_func(func_id: int):
        version = (request.args.get("version") or "").lower()
        if version not in {"old", "new"}:
            abort(400)
        conn = get_conn()
        row = conn.execute(
            "SELECT function_name, pseudocode FROM functions WHERE id = ?",
            (func_id,),
        ).fetchone()
        if not row:
            abort(404)
        name = row["function_name"]
        text = decompress(row["pseudocode"]) if row["pseudocode"] else None
        return render_template(
            "raw.html",
            name=name,
            version=version,
            text=text or f"No content available for {version.upper()} version"
        )

    return app


def run_server(db_path: str, host: str = "127.0.0.1", port: int = 5555, log_file: Optional[str] = None, debug_mode=None):
    """
    Convenience runner used by CLI.
    """
    app = create_app(db_path=db_path, host=host, port=port, log_file=log_file, debug_mode=debug_mode)
    app.logger.info("Starting Flask on http://%s:%d (DB: %s)", host, port, db_path)
    app.run(host=host, port=port, debug=False)