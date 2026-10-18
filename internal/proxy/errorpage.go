package proxy

import (
	"html/template"
	"net/http"
	"strings"
)

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Code}} · {{.Title}}</title>
<style>
:root{--bg:#0E0F12;--surface:#16181D;--border:#2A2E37;--text:#E8E9EC;--muted:#8A8F98;--amber:#F5A524}
@media (prefers-color-scheme: light){:root{--bg:#F7F6F3;--surface:#fff;--border:#E4E2DC;--text:#1B1C1F;--muted:#6B6F76}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);
font:15px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
.card{width:min(440px,100%);background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:32px}
.hex{width:36px;height:41px;background:var(--amber);clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);margin-bottom:18px}
.code{font:600 13px "JetBrains Mono",ui-monospace,monospace;color:var(--amber);letter-spacing:.04em}
h1{font-size:21px;margin:6px 0 8px}p{color:var(--muted);margin:0}
</style></head>
<body><main class="card"><div class="hex" aria-hidden="true"></div><div class="code">{{.Code}}</div><h1>{{.Title}}</h1><p>{{.Message}}</p></main></body></html>
`))

// errorPage writes a branded HTML page for browsers and plain text for everything else.
func errorPage(w http.ResponseWriter, r *http.Request, code int, title, message string) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_ = pageTmpl.Execute(w, map[string]any{"Code": code, "Title": title, "Message": message})
		return
	}
	http.Error(w, http.StatusText(code)+": "+message, code)
}
