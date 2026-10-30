package proxy

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"nectar_gateway/internal/store"
)

func TestWebOptions(t *testing.T) {
	ts, st := setup(t)
	host, port := backend(t, "app")
	web := &store.Web{
		Redirects: []store.RedirectRule{
			{From: "/old", To: "/new"},
			{From: "/blog", To: "https://blog.example.com", Prefix: true, Code: 302},
		},
		ResponseHeaders: map[string]string{"X-Frame-Options": "DENY", "X-Test": "1"},
		RequestHeaders:  map[string]string{"X-From-Gateway": "yes"},
		CORS:            &store.CORS{Origins: []string{"https://app.example.com"}, Credentials: true},
		Compress:        true,
	}
	if err := st.Create(&store.Route{Domain: "web.example.com", TargetIP: host, TargetPort: port, Web: web}); err != nil {
		t.Fatal(err)
	}

	r := req(t, ts, "web.example.com", "/old?x=1")
	if r.StatusCode != 301 || r.Header.Get("Location") != "/new?x=1" {
		t.Fatalf("exact redirect: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	r = req(t, ts, "web.example.com", "/blog/2024/post")
	if r.StatusCode != 302 || r.Header.Get("Location") != "https://blog.example.com/2024/post" {
		t.Fatalf("prefix redirect: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r = req(t, ts, "web.example.com", "/oldish"); r.StatusCode != 200 {
		t.Fatalf("/oldish must not match /old: %d", r.StatusCode)
	}

	// headers: set on the response, and on the request to the backend (echo shows the path only, so
	// check through a header-echo route below)
	r = req(t, ts, "web.example.com", "/x")
	if r.Header.Get("X-Frame-Options") != "DENY" || r.Header.Get("X-Test") != "1" {
		t.Fatalf("response headers: %v", r.Header)
	}
	if r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS header without an Origin")
	}

	// CORS
	r = req(t, ts, "web.example.com", "/api", func(q *http.Request) { q.Header.Set("Origin", "https://app.example.com") })
	if r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" || r.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("CORS simple: %v", r.Header)
	}
	r = req(t, ts, "web.example.com", "/api", func(q *http.Request) {
		q.Method = "OPTIONS"
		q.Header.Set("Origin", "https://app.example.com")
		q.Header.Set("Access-Control-Request-Method", "PUT")
		q.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	})
	if r.StatusCode != 204 || !strings.Contains(r.Header.Get("Access-Control-Allow-Methods"), "PUT") ||
		r.Header.Get("Access-Control-Allow-Headers") != "authorization, content-type" || r.Header.Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("preflight: %d %v", r.StatusCode, r.Header)
	}
	r = req(t, ts, "web.example.com", "/api", func(q *http.Request) {
		q.Method = "OPTIONS"
		q.Header.Set("Origin", "https://evil.example.net")
		q.Header.Set("Access-Control-Request-Method", "PUT")
	})
	if r.StatusCode != 403 || r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign preflight: %d %v", r.StatusCode, r.Header)
	}
}

func TestWebAllowlistAndRequestHeaders(t *testing.T) {
	ts, st := setup(t)
	srv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "hdr="+r.Header.Get("X-From-Gateway")+" auth="+r.Header.Get("X-Remove")+" "+strings.Repeat("payload ", 400))
	})
	host, port := serve(t, srv)
	if err := st.Create(&store.Route{Domain: "in.example.com", TargetIP: host, TargetPort: port, Web: &store.Web{
		AllowIPs:       []string{"127.0.0.0/8", "::1"},
		RequestHeaders: map[string]string{"X-From-Gateway": "yes", "X-Remove": ""},
		Compress:       true,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(&store.Route{Domain: "out.example.com", TargetIP: host, TargetPort: port, Web: &store.Web{AllowIPs: []string{"10.0.0.0/8"}}}); err != nil {
		t.Fatal(err)
	}
	if r := req(t, ts, "out.example.com", "/"); r.StatusCode != 403 {
		t.Fatalf("allowlist must refuse 127.0.0.1: %d", r.StatusCode)
	}
	// gzip (the Go client would decompress transparently with its own Accept-Encoding, so ask explicitly)
	r := req(t, ts, "in.example.com", "/", func(q *http.Request) {
		q.Header.Set("Accept-Encoding", "gzip")
		q.Header.Set("X-Remove", "client-value")
	})
	if r.StatusCode != 200 || r.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(r.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("gzip: %d %v", r.StatusCode, r.Header)
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if !strings.HasPrefix(string(b), "hdr=yes auth= payload") {
		t.Fatalf("body: %.60q", b)
	}
	r = req(t, ts, "in.example.com", "/", func(q *http.Request) { q.Header.Set("Accept-Encoding", "identity") })
	if r.Header.Get("Content-Encoding") != "" {
		t.Fatal("compressed for a client without gzip")
	}
}

func TestWebValidation(t *testing.T) {
	_, st := setup(t)
	for i, w := range []*store.Web{
		{Redirects: []store.RedirectRule{{From: "old", To: "/new"}}},
		{Redirects: []store.RedirectRule{{From: "/old", To: "ftp://x"}}},
		{AllowIPs: []string{"not-an-ip"}},
		{ResponseHeaders: map[string]string{"Content-Length": "1"}},
		{ResponseHeaders: map[string]string{"X-A": "a\r\nInjected: 1"}},
		{CORS: &store.CORS{Origins: []string{"*"}, Credentials: true}},
		{CORS: &store.CORS{Origins: []string{"https://a.io/path"}}},
		{HSTS: 300, HSTSPreload: true},
	} {
		if err := st.Create(&store.Route{Domain: "v.example.com", TargetIP: "127.0.0.1", TargetPort: 1, Web: w}); err == nil {
			t.Errorf("case %d accepted: %+v", i, w)
		}
	}
	// omitted web in an update keeps the options; an empty one clears them
	rt := &store.Route{Domain: "keep.example.com", TargetIP: "127.0.0.1", TargetPort: 1, Web: &store.Web{HSTS: 3600}}
	if err := st.Create(rt); err != nil {
		t.Fatal(err)
	}
	upd := store.Route{ID: rt.ID, Domain: rt.Domain, TargetIP: rt.TargetIP, TargetPort: 2}
	if err := st.Update(&upd); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(rt.ID); got.Web == nil || got.Web.HSTS != 3600 {
		t.Fatalf("web lost on update: %+v", got.Web)
	}
	upd.Web = &store.Web{}
	if err := st.Update(&upd); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(rt.ID); got.Web != nil {
		t.Fatalf("web not cleared: %+v", got.Web)
	}
}

// serve runs h as a backend and returns its host and port.
func serve(t *testing.T, h http.Handler) (string, int) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

func TestWebHSTSOnlyOverTLS(t *testing.T) {
	web := &store.Web{HSTS: 31536000, HSTSSubdomains: true, HSTSPreload: true}
	for _, tlsOn := range []bool{false, true} {
		r := httptest.NewRequest("GET", "https://x.example.com/", nil)
		if !tlsOn {
			r.TLS = nil
		}
		rec := httptest.NewRecorder()
		w, done := wrapWeb(rec, r, web, "")
		w.Write([]byte("hi"))
		done()
		got := rec.Header().Get("Strict-Transport-Security")
		if tlsOn && got != "max-age=31536000; includeSubDomains; preload" || !tlsOn && got != "" {
			t.Errorf("tls=%v: %q", tlsOn, got)
		}
	}
}
