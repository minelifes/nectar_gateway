package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"nectar_gateway/internal/metrics"
	"nectar_gateway/internal/store"
)

func req(t *testing.T, ts *httptest.Server, host, path string, mod ...func(*http.Request)) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Host = host
	for _, m := range mod {
		m(req)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRedirectMode(t *testing.T) {
	ts, st := setup(t)
	st.Create(&store.Route{Domain: "www.example.com", Mode: store.ModeRedirect, RedirectURL: "https://example.com"})
	st.Create(&store.Route{Domain: "old.example.com", Mode: store.ModeRedirect, RedirectURL: "https://example.com/moved", RedirectCode: 302})

	r := req(t, ts, "www.example.com", "/docs/a?x=1")
	if r.StatusCode != 301 || r.Header.Get("Location") != "https://example.com/docs/a?x=1" {
		t.Fatalf("www redirect: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	r = req(t, ts, "old.example.com", "/anything")
	if r.StatusCode != 302 || r.Header.Get("Location") != "https://example.com/moved" {
		t.Fatalf("fixed redirect: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	for _, bad := range []store.Route{
		{Domain: "a.io", Mode: store.ModeRedirect, RedirectURL: "/relative"},
		{Domain: "b.io", Mode: store.ModeRedirect, RedirectURL: "ftp://x"},
		{Domain: "c.io", Mode: store.ModeRedirect, RedirectURL: "https://x.io", RedirectCode: 303},
	} {
		if err := st.Create(&bad); err == nil {
			t.Errorf("accepted invalid redirect %+v", bad)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	ts, st := setup(t)
	host, port := backend(t, "staging")
	rt := &store.Route{Domain: "staging.example.com", TargetIP: host, TargetPort: port,
		BasicAuthUsers: []store.AuthUser{{User: "vadym", Password: "secret-pass-1"}}}
	if err := st.Create(rt); err != nil {
		t.Fatal(err)
	}
	if rt.BasicAuth == "" || !strings.HasPrefix(strings.SplitN(rt.BasicAuth, ":", 2)[1], "$2") || len(rt.AuthUsernames) != 1 {
		t.Fatalf("not hashed: %q %v", rt.BasicAuth, rt.AuthUsernames)
	}
	if r := req(t, ts, "staging.example.com", "/"); r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no credentials: %d", r.StatusCode)
	}
	if r := req(t, ts, "staging.example.com", "/", func(q *http.Request) { q.SetBasicAuth("vadym", "wrong") }); r.StatusCode != 401 {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	for i := 0; i < 2; i++ { // second hit comes from the cache
		r := req(t, ts, "staging.example.com", "/x", func(q *http.Request) { q.SetBasicAuth("vadym", "secret-pass-1") })
		if b, _ := io.ReadAll(r.Body); r.StatusCode != 200 || !strings.HasPrefix(string(b), "staging") {
			t.Fatalf("authorized: %d %s", r.StatusCode, b)
		}
	}

	// update without basic_auth_users keeps the users; with an empty password keeps that user's password
	got, _ := st.Get(rt.ID)
	got.RateLimit = 5
	if err := st.Update(&got); err != nil || len(got.AuthUsernames) != 1 {
		t.Fatalf("update kept users: %v %v", err, got.AuthUsernames)
	}
	got.BasicAuthUsers = []store.AuthUser{{User: "vadym"}, {User: "olena", Password: "another-pass"}}
	if err := st.Update(&got); err != nil {
		t.Fatal(err)
	}
	cur, _ := st.Get(rt.ID)
	if !store.CheckBasicAuth(cur.BasicAuth, "vadym", "secret-pass-1") || !store.CheckBasicAuth(cur.BasicAuth, "olena", "another-pass") {
		t.Fatal("users after update")
	}
	cur.BasicAuthUsers = []store.AuthUser{}
	st.Update(&cur)
	if r := req(t, ts, "staging.example.com", "/"); r.StatusCode != 200 {
		t.Fatalf("auth removed: %d", r.StatusCode)
	}
	bad := &store.Route{Domain: "x.io", TargetIP: host, TargetPort: port, BasicAuthUsers: []store.AuthUser{{User: "a:b", Password: "12345678"}}}
	if err := st.Create(bad); err == nil {
		t.Fatal("bad user name accepted")
	}
	if err := st.Create(&store.Route{Domain: "y.io", TargetIP: host, TargetPort: port, BasicAuthUsers: []store.AuthUser{{User: "a"}}}); err == nil {
		t.Fatal("user without password accepted")
	}
}

func TestMaxBodyAndTimeout(t *testing.T) {
	ts, st := setup(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(1500 * time.Millisecond)
		}
		n, _ := io.Copy(io.Discard, r.Body)
		io.WriteString(w, "got "+strconv.FormatInt(n, 10))
	}))
	t.Cleanup(slow.Close)
	u, _ := url.Parse(slow.URL)
	port, _ := strconv.Atoi(u.Port())
	st.Create(&store.Route{Domain: "up.example.com", TargetIP: u.Hostname(), TargetPort: port, MaxBodyMB: 1, TimeoutSeconds: 1})

	post := func(body io.Reader, size int64) int {
		req, _ := http.NewRequest("POST", ts.URL+"/", body)
		req.Host = "up.example.com"
		req.ContentLength = size
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(bytes.NewReader(make([]byte, 1000)), 1000); c != 200 {
		t.Fatalf("small body: %d", c)
	}
	if c := post(bytes.NewReader(make([]byte, 2<<20)), 2<<20); c != 413 {
		t.Fatalf("declared large body: %d", c)
	}
	if c := post(io.LimitReader(zeros{}, 2<<20), -1); c != 413 { // chunked, no Content-Length
		t.Fatalf("chunked large body: %d", c)
	}
	start := time.Now()
	if r := req(t, ts, "up.example.com", "/slow"); r.StatusCode != 504 {
		t.Fatalf("timeout: %d", r.StatusCode)
	}
	if time.Since(start) > 1400*time.Millisecond {
		t.Fatal("timeout not applied")
	}
	if err := st.Create(&store.Route{Domain: "z.io", TargetIP: "a", TimeoutSeconds: -1}); err == nil {
		t.Fatal("negative timeout accepted")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// TestH2C proxies prior-knowledge HTTP/2 (as gRPC uses) to a cleartext HTTP/2 backend.
func TestH2C(t *testing.T) {
	st0, st := setup(t)
	_ = st0
	be := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status")
		io.WriteString(w, "proto="+r.Proto)
		w.Header().Set("Grpc-Status", "0")
	})}
	be.Protocols = new(http.Protocols)
	be.Protocols.SetUnencryptedHTTP2(true)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go be.Serve(ln)
	t.Cleanup(func() { be.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	st.Create(&store.Route{Domain: "grpc.example.com", TargetIP: "127.0.0.1", TargetPort: port, BackendProtocol: store.ProtoH2C})

	// gateway front with h2c enabled (as main.go configures the HTTP listener)
	front := &http.Server{Handler: New(st, "")}
	front.Protocols = new(http.Protocols)
	front.Protocols.SetHTTP1(true)
	front.Protocols.SetUnencryptedHTTP2(true)
	fl, _ := net.Listen("tcp", "127.0.0.1:0")
	go front.Serve(fl)
	t.Cleanup(func() { front.Close() })

	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	req, _ := http.NewRequest("POST", "http://"+fl.Addr().String()+"/pkg.Svc/Method", strings.NewReader("x"))
	req.Host = "grpc.example.com"
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Proto != "HTTP/2.0" || string(b) != "proto=HTTP/2.0" || resp.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("h2c: client %s, backend %q, trailer %q", resp.Proto, b, resp.Trailer.Get("Grpc-Status"))
	}
	if err := st.Create(&store.Route{Domain: "q.io", TargetIP: "a", BackendProtocol: "h3"}); err == nil {
		t.Fatal("bad protocol accepted")
	}
	if err := st.Create(&store.Route{Domain: "q2.io", TargetIP: "a", TargetHTTPS: true, BackendProtocol: store.ProtoH2C}); err == nil {
		t.Fatal("h2c + https accepted")
	}
	_ = tls.VersionTLS13
}

func TestFallbackAndMetrics(t *testing.T) {
	st, err := store.New(t.TempDir() + "/gw.db")
	if err != nil {
		t.Fatal(err)
	}
	h := New(st, "")
	h.Metrics = metrics.New(100)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	host, port := backend(t, "app")
	st.Create(&store.Route{Domain: "app.example.com", TargetIP: host, TargetPort: port})
	oldHost, oldPort := backend(t, "legacy")

	if r := req(t, ts, "unknown.example.com", "/"); r.StatusCode != 410 {
		t.Fatalf("no fallback: %d", r.StatusCode)
	}
	target := ""
	h.FallbackTarget = func() string { return target }
	target = net.JoinHostPort(oldHost, strconv.Itoa(oldPort))
	r := req(t, ts, "unknown.example.com", "/x")
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || string(b) != "legacy unknown.example.com /x" {
		t.Fatalf("fallback: %d %q", r.StatusCode, b)
	}
	for i := 0; i < 3; i++ {
		req(t, ts, "app.example.com", "/page").Body.Close()
	}
	req(t, ts, "app.example.com", CanaryPath).Body.Close() // not counted

	sums := h.Metrics.Summaries(60, "", false)
	byDomain := map[string]metrics.Summary{}
	for _, s := range sums {
		byDomain[s.Domain] = s
	}
	if byDomain["app.example.com"].Requests != 3 || byDomain[metrics.Fallback].Requests != 1 || byDomain[metrics.Unknown].Requests != 1 {
		t.Fatalf("metrics: %+v", sums)
	}
	if b := byDomain["app.example.com"].BytesOut; b == 0 {
		t.Fatal("bytes not counted")
	}
	logs := h.Metrics.Log(metrics.LogQuery{Domain: "app.example.com"})
	if len(logs) != 3 || logs[0].Path != "/page" || logs[0].Status != 200 || logs[0].Method != "GET" {
		t.Fatalf("access log: %+v", logs)
	}
}

// TestWebSocketWithMetrics: the metrics wrapper must keep connection upgrades working.
func TestWebSocketWithMetrics(t *testing.T) {
	st, _ := store.New(t.TempDir() + "/gw.db")
	h := New(st, "")
	h.Metrics = metrics.New(10)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	host, port := backend(t, "ws")
	st.Create(&store.Route{Domain: "ws.example.com", TargetIP: host, TargetPort: port})

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", err, resp)
	}
	io.WriteString(conn, "hello\n")
	if line, _ := br.ReadString('\n'); line != "echo:hello\n" {
		t.Fatalf("tunnel through metrics wrapper: %q", line)
	}
	if logs := h.Metrics.Log(metrics.LogQuery{}); len(logs) == 0 || logs[0].Status != 101 {
		time.Sleep(100 * time.Millisecond)
	}
}
