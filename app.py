"""
Website Security Scanner - web page
Run:  python app.py      (then paste a link in the page that opens)
Needs scanner.py in the same folder. No extra packages besides requests.
"""
 
import html
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
 
import scanner
 
HOST, PORT = "127.0.0.1", 8000  # local only: reachable from your own computer
 
STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#667085;--line:#e4e7ec;
--pass:#12803c;--fail:#c62828;--skip:#8a6d00}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--text:#e8eaee;
--muted:#9aa3b2;--line:#2c323c;--pass:#4cc27a;--fail:#ff7a7a;--skip:#e0b84a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}
main{max-width:760px;margin:0 auto;padding:32px 16px}
h1{font-size:1.5rem;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 24px}
form{display:flex;gap:8px;margin-bottom:24px}
input{flex:1;padding:12px 14px;font-size:1rem;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--text)}
button{padding:12px 20px;font-size:1rem;border:0;border-radius:8px;
background:#2563eb;color:#fff;cursor:pointer}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px;margin-bottom:16px}
.score{display:flex;align-items:center;gap:16px}
.big{font-size:2.6rem;font-weight:700}
.row{padding:12px 0;border-top:1px solid var(--line)}
.row:first-child{border-top:0}
.tag{display:inline-block;min-width:54px;font-weight:700;font-size:.85rem}
.PASS{color:var(--pass)}.FAIL{color:var(--fail)}.SKIP{color:var(--skip)}
.fix{color:var(--muted);font-size:.9rem;margin:4px 0 0 58px}
.error{color:var(--fail)}
.note{color:var(--muted);font-size:.85rem}
"""
 
 
def page(body: str) -> bytes:
    doc = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Website Security Scanner</title>"
        f"<style>{STYLE}</style></head><body><main>"
        "<h1>Website Security Scanner</h1>"
        '<p class="sub">Paste a link to check HTTPS, SSL certificate and security headers.</p>'
        f"{body}"
        '<p class="note">Only public information is read. Scan your own sites or public sites.</p>'
        "</main></body></html>"
    )
    return doc.encode("utf-8")
 
 
def form_html(value: str = "") -> str:
    return (
        '<form method="get" action="/">'
        f'<input name="url" value="{html.escape(value)}" placeholder="example.com" '
        'autofocus autocomplete="off">'
        "<button type=\"submit\">Scan</button></form>"
    )
 
 
def result_html(result: dict) -> str:
    rows = []
    for check in result["checks"]:
        if check["skipped"]:
            label = "SKIP"
        else:
            label = "PASS" if check["passed"] else "FAIL"
        fix = ""
        if check["fix"] and not check["passed"]:
            fix = f'<div class="fix">Fix: {html.escape(check["fix"])}</div>'
        rows.append(
            f'<div class="row"><span class="tag {label}">{label}</span>'
            f'{html.escape(check["message"])}{fix}</div>'
        )
    return (
        '<div class="card score">'
        f'<div class="big">{result["score"]}/100</div>'
        f'<div><strong>Grade {result["grade"]}</strong><br>'
        f'<span class="sub">{html.escape(result["hostname"])}</span></div></div>'
        f'<div class="card">{"".join(rows)}</div>'
    )
 
 
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        url = query.get("url", [""])[0].strip()[:300]
 
        body = form_html(url)
        if url:
            try:
                body += result_html(scanner.scan(url))
            except ValueError as error:
                body += f'<p class="error">{html.escape(str(error))}</p>'
            except Exception:
                body += '<p class="error">Something went wrong while scanning this link.</p>'
 
        data = page(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
 
    def log_message(self, *args):
        pass  # keep the terminal clean
 
 
def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError:
        print(f"Port {PORT} is busy. Close the other program or change PORT in app.py.")
        return
    address = f"http://{HOST}:{PORT}"
    print(f"Scanner is running at {address}  (press Ctrl+C to stop)")
    threading.Timer(0.8, lambda: webbrowser.open(address)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
 
 
if __name__ == "__main__":
    main()
 