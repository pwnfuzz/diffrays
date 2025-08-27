import difflib
import re
import sys

def generate_diff_html(file1_path, file2_path, output_html="diff_output.html"):
    with open(file1_path, encoding="utf-8") as f:
        a = f.readlines()
    with open(file2_path, encoding="utf-8") as f:
        b = f.readlines()

    # Only the table (avoids extra HTML and the "Links" table)
    table = difflib.HtmlDiff().make_table(
        a, b, fromdesc=file1_path, todesc=file2_path
    )

    # Strip anchors
    table = re.sub(r"</?a\b[^>]*>", "", table, flags=re.I)

    # Remove the nav column entirely (headers + cells)
    table = re.sub(r"<th[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</th>", "", table, flags=re.I|re.S)
    table = re.sub(r"<td[^>]*\bclass=['\"]?diff_next['\"]?[^>]*>.*?</td>", "", table, flags=re.I|re.S)

    # Wrap with modern HTML + dark-mode toggle; keep a CSS fallback to hide any leftover .diff_next
    html = f"""<!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8" />
            <title>Diff Output</title>
            <style>
              :root {{ --bg:#f8f9fa; --fg:#212529; --th:#343a40; --th-fg:#fff; --hover:#f1f3f5; }}
              body.dark {{ --bg:#1e1e1e; --fg:#e9ecef; --th:#495057; --th-fg:#fff; --hover:#2a2a2a; }}
              body {{ margin:20px; background:var(--bg); color:var(--fg); font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif; transition:.2s; }}
              table.diff {{ width:100%; border-collapse:collapse; border:1px solid #dee2e6; box-shadow:0 2px 6px rgba(0,0,0,.1); font-size:14px; }}
              .diff th {{ background:var(--th); color:var(--th-fg); padding:8px; position:sticky; top:0; }}
              .diff td {{ padding:6px 10px; vertical-align:top; white-space:pre-wrap; font-family:Menlo,Consolas,monospace; }}
              .diff .diff_header {{ background:#e9ecef; color:#495057; font-weight:700; text-align:center; }}
              body.dark .diff .diff_header {{ background:#343a40; color:#f8f9fa; }}
              .diff .diff_add {{ background:#d4edda; color:#155724; }}
              .diff .diff_chg {{ background:#fff3cd; color:#856404; }}
              .diff .diff_sub {{ background:#f8d7da; color:#721c24; }}
              tr:hover td {{ background:var(--hover) !important; }}
              /* Safety: if any remain, hide nav column */
              .diff_next {{ display:none !important; }}
              #toggle-dark {{ position:fixed; top:15px; right:20px; padding:6px 12px; border:0; border-radius:6px; background:#343a40; color:#fff; cursor:pointer; z-index:1000; }}
            </style>
            </head>
            <body>
            <button id="toggle-dark">🌙 Toggle Dark Mode</button>
            <h2>Diff between <code>{file1_path}</code> and <code>{file2_path}</code></h2>
            {table}
            <script>
              document.getElementById('toggle-dark').addEventListener('click', ()=>document.body.classList.toggle('dark'));
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
