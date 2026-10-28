package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nectar_gateway/internal/store"
)

func backend(t *testing.T, name string) (host string, port int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" { // minimal upgrade echo
			hj, _ := w.(http.Hijacker)
			conn, buf, _ := hj.Hijack()
			buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			buf.Flush()
			line, _ := buf.ReadString('\n')
			conn.Write([]byte("echo:" + line))
			conn.Close()
			return
		}
		io.WriteString(w, name+" "+r.Host+" "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

func setup(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := New(st, "")
	h.Challenge = func(token string) (string, bool) { return "keyauth-" + token, token == "tok" }
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, st
}

func get(t *testing.T, ts *httptest.Server, host, path string, hdr ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Host = host
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPathRoutingErrorsCanaryChallenge(t *testing.T) {
	ts, st := setup(t)
	wh, wp := backend(t, "web")
	ah, ap := backend(t, "api")
	st.Create(&store.Route{Domain: "shop.example.com", TargetIP: wh, TargetPort: wp})
	st.Create(&store.Route{Domain: "shop.example.com", PathPrefix: "/api", TargetIP: ah, TargetPort: ap})

	if code, body := get(t, ts, "shop.example.com", "/"); code != 200 || !strings.HasPrefix(body, "web shop.example.com /") {
		t.Fatalf("web: %d %q", code, body)
	}
	if code, body := get(t, ts, "shop.example.com", "/api/orders"); code != 200 || body != "api shop.example.com /api/orders" {
		t.Fatalf("api (path kept, host preserved): %d %q", code, body)
	}
	// unknown host → branded 410 for browsers, text otherwise
	if code, body := get(t, ts, "nope.example.com", "/", "Accept", "text/html"); code != 410 || !strings.Contains(body, "No app here") || !strings.Contains(body, "<html") {
		t.Fatalf("unknown host html: %d %q", code, body)
	}
	if code, body := get(t, ts, "nope.example.com", "/"); code != 410 || strings.Contains(body, "<html") {
		t.Fatalf("unknown host text: %d %q", code, body)
	}
	// backend down → branded 502
	st.Create(&store.Route{Domain: "down.example.com", TargetIP: "127.0.0.1", TargetPort: 1})
	if code, body := get(t, ts, "down.example.com", "/", "Accept", "text/html"); code != 502 || !strings.Contains(body, "not responding") {
		t.Fatalf("down: %d %q", code, body)
	}
	// maintenance mode
	m := store.Route{Domain: "maint.example.com", TargetIP: wh, TargetPort: wp, Maintenance: true}
	st.Create(&m)
	if code, _ := get(t, ts, "maint.example.com", "/"); code != 503 {
		t.Fatalf("maintenance: %d", code)
	}
	// canary answers for any host; ACME tokens come from the issuer
	if code, body := get(t, ts, "anything.example.com", CanaryPath); code != 200 || body != "ok\n" {
		t.Fatalf("canary: %d %q", code, body)
	}
	if code, body := get(t, ts, "shop.example.com", "/.well-known/acme-challenge/tok"); code != 200 || body != "keyauth-tok" {
		t.Fatalf("acme challenge: %d %q", code, body)
	}
}

func TestUnknownAcmeTokenIsProxiedToBackend(t *testing.T) {
	_, st := setup(t)
	root := t.TempDir()
	dir := filepath.Join(root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "known"), []byte("webroot-answer"), 0o644)
	h := New(st, root)
	h.Challenge = func(string) (string, bool) { return "", false }
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	bh, bp := backend(t, "app")
	st.Create(&store.Route{Domain: "shop.example.com", TargetIP: bh, TargetPort: bp})

	if code, body := get(t, srv, "shop.example.com", "/.well-known/acme-challenge/known"); code != 200 || body != "webroot-answer" {
		t.Fatalf("webroot token: %d %q", code, body)
	}
	if code, body := get(t, srv, "shop.example.com", "/.well-known/acme-challenge/other"); code != 200 || !strings.HasPrefix(body, "app ") {
		t.Fatalf("unknown token should reach the backend: %d %q", code, body)
	}
	if code, _ := get(t, srv, "nobody.example.com", "/.well-known/acme-challenge/other"); code != 410 {
		t.Fatalf("unknown domain: %d", code)
	}
}

func TestWebSocketUpgradePassesThrough(t *testing.T) {
	ts, st := setup(t)
	h, p := backend(t, "ws")
	st.Create(&store.Route{Domain: "ws.example.com", TargetIP: h, TargetPort: p})

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", err, resp)
	}
	io.WriteString(conn, "hello\n")
	line, _ := br.ReadString('\n')
	if line != "echo:hello\n" {
		t.Fatalf("tunnel: %q", line)
	}
}

func TestCertificateFromDatabase(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := New(st, "")
	r := store.Route{Domain: "secure.example.com", TargetIP: "x"}
	st.Create(&r)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "secure.example.com"},
		DNSNames: []string{"secure.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	if _, err := st.SetCert(r.ID, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})), "upload"); err != nil {
		t.Fatal(err)
	}
	cert, err := h.GetCertificate(&tls.ClientHelloInfo{ServerName: "secure.example.com"})
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if _, err := h.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err == nil {
		t.Fatal("certificate for an unknown host")
	}
}
