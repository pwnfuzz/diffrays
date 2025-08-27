from flask import Flask, render_template_string, request
import difflib
import re

app = Flask(__name__)

# Landing page template
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Diff Tool (Dracula)</title>
  <style>
    body { font-family: Segoe UI,Tahoma,Geneva,Verdana,sans-serif; margin:20px; }
    h1 { text-align:center; }
    form { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-top:20px; }
    textarea { width:100%; height:400px; font-family:Menlo,Consolas,monospace; padding:10px; }
    .submit-row { grid-column:span 2; text-align:center; margin-top:15px; }
    button { padding:10px 20px; font-size:16px; border:0; border-radius:6px; background:#bd93f9; color:#282a36; cursor:pointer; }
    button:hover { background:#ff79c6; color:#f8f8f2; }
  </style>
</head>
<body>
  <h1>Diff Compare Tool (Dracula)</h1>
  <form method="post" action="/compare">
    <div>
      <h3>Old Version</h3>
      <textarea name="old_text" placeholder="Paste original content here..."></textarea>
    </div>
    <div>
      <h3>New Version</h3>
      <textarea name="new_text" placeholder="Paste modified content here..."></textarea>
    </div>
    <div class="submit-row">
      <button type="submit">Compare</button>
    </div>
  </form>
</body>
</html>
"""

def make_dracula_diff_html(file1_text, file2_text, file1_name="Original Code", file2_name="Modified Code"):
    a = file1_text.splitlines(keepends=True)
    b = file2_text.splitlines(keepends=True)

    # Generate table only
    table = difflib.HtmlDiff().make_table(a, b, fromdesc=file1_name, todesc=file2_name)

    # Strip anchors
    table = re.sub(r"</?a\b[^>]*>", "", table, flags=re.I)

    # Remove nav col
    table = re.sub(r"<th[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</th>", "", table, flags=re.I|re.S)
    table = re.sub(r"<td[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</td>", "", table, flags=re.I|re.S)

    # Dracula + Light toggle styling with updated hover and character-level highlighting
    html = f"""
    <!doctype html>
      <html lang="en">
         <head>
            <meta charset="utf-8" />
            <title>Diff Output (Dracula)</title>
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
               margin-bottom: 20px;
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
               
               /* Full line highlighting for additions (green) */
               .diff tr.diff_add td,
               .diff .diff_add {{
               background:#244032 !important;
               color:#50fa7b !important;
               }}
               
               /* Full line highlighting for changes (orange) - controlled by checkbox */
               .diff tr.diff_chg td,
               .diff .diff_chg {{
               background:#4b3d1f !important;
               color:#ffb86c !important;
               }}
               
               /* Hide character-level highlighting when checkbox is unchecked */
               body.hide-char-level .diff tr.diff_chg td,
               body.hide-char-level .diff .diff_chg {{
               background: transparent !important;
               color: inherit !important;
               }}
               
               /* Full line highlighting for deletions (red) */
               .diff tr.diff_sub td,
               .diff .diff_sub {{
               background:#4a2c32 !important;
               color:#ff5555 !important;
               }}
               
               /* Override any inline span highlighting within diff lines */
               .diff_add span,
               .diff_chg span,
               .diff_sub span {{
               background:inherit !important;
               color:inherit !important;
               }}
               
               /* Regular hover for non-addition lines */
               .diff tr:not(.diff_add):hover td {{
               background:#383a59 !important;
               }}
               
               /* NO hover effect for addition lines - keep them green */
               .diff tr.diff_add:hover td {{
               background:#244032 !important;
               color:#50fa7b !important;
               }}
               
               /* Specific override for cells with diff_add content */
               .diff td:has(span.diff_add):hover,
               .diff td.diff_add:hover {{
               background:#244032 !important;
               color:#50fa7b !important;
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
               
               /* Full line highlighting for light mode */
               body.light .diff tr.diff_add td,
               body.light .diff .diff_add {{
               background:#d4edda !important;
               color:#155724 !important;
               }}
               body.light .diff tr.diff_chg td,
               body.light .diff .diff_chg {{
               background:#fff3cd !important;
               color:#856404 !important;
               }}
               body.light .diff tr.diff_sub td,
               body.light .diff .diff_sub {{
               background:#f8d7da !important;
               color:#721c24 !important;
               }}
               
               /* Light mode: Hide character-level highlighting when checkbox is unchecked */
               body.light.hide-char-level .diff tr.diff_chg td,
               body.light.hide-char-level .diff .diff_chg {{
               background: transparent !important;
               color: inherit !important;
               }}
               
               /* Light mode hover effects */
               body.light .diff tr:not(.diff_add):hover td {{
               background:#e2e6ea !important;
               }}
               
               /* Light mode: NO hover effect for addition lines - keep them green */
               body.light .diff tr.diff_add:hover td {{
               background:#d4edda !important;
               color:#155724 !important;
               }}
               
               /* Light mode: Specific override for cells with diff_add content */
               body.light .diff td:has(span.diff_add):hover,
               body.light .diff td.diff_add:hover {{
               background:#d4edda !important;
               color:#155724 !important;
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
               <h2>Diff between <code>{file1_name}</code> and <code>{file2_name}</code></h2>
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
               const btn = document.getElementById('toggle-dark');
               const charLevelToggle = document.getElementById('char-level-toggle');
               let light = false;
               
               // Dark/Light mode toggle
               btn.addEventListener('click', () => {{
                   document.body.classList.toggle('light');
                   light = !light;
                   if(light){{
                     btn.textContent="🌙 Toggle Dark Mode";
                   }} else {{
                     btn.textContent="🌙 Toggle Light Mode";
                   }}
                   // Update addition colors when theme changes
                   updateAdditionColors();
               }});
               
               // Character level highlighting toggle
               charLevelToggle.addEventListener('change', () => {{
                   if (charLevelToggle.checked) {{
                       document.body.classList.remove('hide-char-level');
                   }} else {{
                       document.body.classList.add('hide-char-level');
                   }}
               }});
               
               // Add full-line highlighting and hover protection
               function addFullLineClasses() {{
                   const diffTable = document.querySelector('table.diff');
                   if (diffTable) {{
                       const tds = diffTable.querySelectorAll('td');
                       tds.forEach(td => {{
                           // Highlight full lines for additions (green)
                           if (td.querySelector('span.diff_add')) {{
                               td.style.backgroundColor = '#244032';
                               td.style.color = '#50fa7b';
                               td.classList.add('diff_add');
                               
                               // Add specific hover protection
                               td.addEventListener('mouseenter', function() {{
                                   if (document.body.classList.contains('light')) {{
                                       this.style.backgroundColor = '#d4edda';
                                       this.style.color = '#155724';
                                   }} else {{
                                       this.style.backgroundColor = '#244032';
                                       this.style.color = '#50fa7b';
                                   }}
                               }});
                               
                               td.addEventListener('mouseleave', function() {{
                                   if (document.body.classList.contains('light')) {{
                                       this.style.backgroundColor = '#d4edda';
                                       this.style.color = '#155724';
                                   }} else {{
                                       this.style.backgroundColor = '#244032';
                                       this.style.color = '#50fa7b';
                                   }}
                               }});
                           }}
                       }});
                   }}
               }}
               
               // Update colors when theme changes
               function updateAdditionColors() {{
                   const additionCells = document.querySelectorAll('td.diff_add');
                   additionCells.forEach(td => {{
                       if (document.body.classList.contains('light')) {{
                           td.style.backgroundColor = '#d4edda';
                           td.style.color = '#155724';
                       }} else {{
                           td.style.backgroundColor = '#244032';
                           td.style.color = '#50fa7b';
                       }}
                   }});
               }}
               
               // Run immediately
               addFullLineClasses();
               
               // Also run when DOM is ready
               document.addEventListener('DOMContentLoaded', addFullLineClasses);
            </script>
         </body>
      </html>
    """
    return html


@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)


@app.route("/compare", methods=["POST"])
def compare():
    old_text = request.form.get("old_text", "")
    new_text = request.form.get("new_text", "")
    diff_html = make_dracula_diff_html(old_text, new_text)
    return diff_html


if __name__ == "__main__":
    app.run(debug=True, port=5000)