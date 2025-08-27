import difflib
import re
import sys

def generate_diff_html(file1_path, file2_path, output_html="diff_output.html"):
    with open(file1_path, encoding="utf-8") as f:
        a = f.readlines()
    with open(file2_path, encoding="utf-8") as f:
        b = f.readlines()

    # Generate only the table (avoids legends/links)
    table = difflib.HtmlDiff().make_table(
        a, b, fromdesc=file1_path, todesc=file2_path
    )

    # Strip anchors
    table = re.sub(r"</?a\b[^>]*>", "", table, flags=re.I)

    # Remove "next change navigation" column
    table = re.sub(r"<th[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</th>", "", table, flags=re.I|re.S)
    table = re.sub(r"<td[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</td>", "", table, flags=re.I|re.S)

    # Dracula-styled HTML with light mode support
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
               /* Safety: remove nav column */
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
            <h2>Diff between <code>{file1_path}</code> and <code>{file2_path}</code></h2>
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

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python diff_wrapper.py file1 file2 [output.html]")
        sys.exit(1)
    out = sys.argv[3] if len(sys.argv) > 3 else "diff_output.html"
    generate_diff_html(sys.argv[1], sys.argv[2], out)