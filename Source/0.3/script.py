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
      <textarea name="old_text" placeholder="Paste old file content here..."></textarea>
    </div>
    <div>
      <h3>New Version</h3>
      <textarea name="new_text" placeholder="Paste new file content here..."></textarea>
    </div>
    <div class="submit-row">
      <button type="submit">Compare</button>
    </div>
  </form>
</body>
</html>
"""

def make_dracula_diff_html(file1_text, file2_text, file1_name="Old File", file2_name="New File"):
    a = file1_text.splitlines(keepends=True)
    b = file2_text.splitlines(keepends=True)

    # Generate table only
    table = difflib.HtmlDiff().make_table(a, b, fromdesc=file1_name, todesc=file2_name)

    # Strip anchors
    table = re.sub(r"</?a\b[^>]*>", "", table, flags=re.I)

    # Remove nav col
    table = re.sub(r"<th[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</th>", "", table, flags=re.I|re.S)
    table = re.sub(r"<td[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</td>", "", table, flags=re.I|re.S)

    # Dracula + Light toggle styling
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
               .diff .diff_add {{
               background:#244032;
               color:#50fa7b;
               }}
               .diff .diff_chg {{
               background:#4b3d1f;
               color:#ffb86c;
               }}
               .diff .diff_sub {{
               background:#4a2c32;
               color:#ff5555;
               }}
               tr:hover td {{
               background:#383a59 !important;
               }}
               .diff_next {{ display:none !important; }}
               
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
               }}
               body.light .diff .diff_header {{
               background:#6c757d;
               color:#fff;
               }}
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
               body.light tr:hover td {{
               background:#e2e6ea !important;
               }}
               
               #toggle-dark {{
               position:fixed; top:15px; right:20px;
               padding:6px 12px; border:0; border-radius:6px;
               background:#bd93f9; color:#282a36;
               cursor:pointer; font-size:14px; font-weight:bold;
               z-index:1000;
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
            <button id="toggle-dark">🌙 Toggle Light Mode</button>
            <h2>Diff between <code>{file1_name}</code> and <code>{file2_name}</code></h2>
            {table}
            <script>
               const btn = document.getElementById('toggle-dark');
               let light = false;
               btn.addEventListener('click', () => {{
                   document.body.classList.toggle('light');
                   light = !light;
                   if(light){{
                     btn.textContent="🌙 Toggle Dark Mode";
                   }} else {{
                     btn.textContent="🌙 Toggle Light Mode";
                   }}
               }});
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
