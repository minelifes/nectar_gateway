package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"nectar_gateway/internal/store"
)

// Over a route's rate limit a client gets 429 (not a block); only sustained abuse blocks it, for the
// configured time, and 0 never blocks.
func TestRateLimitAnswers429(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	host, ps, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(ps)

	for _, block := range []time.Duration{0, 5 * time.Minute} {
		st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
		if err != nil {
			t.Fatal(err)
		}
		h := New(st, "")
		h.RateLimitBlock = func() time.Duration { return block }
		ts := httptest.NewServer(h)
		st.Create(&store.Route{Domain: "api.example.com", TargetIP: host, TargetPort: port, RateLimit: 2})
		st.Create(&store.Route{Domain: "other.example.com", TargetIP: host, TargetPort: port})

		// a burst: the first two pass, the rest get 429 with Retry-After; nobody is blocked
		codes := map[int]int{}
		for i := 0; i < 10; i++ {
			r := req(t, ts, "api.example.com", "/")
			codes[r.StatusCode]++
			if r.StatusCode == 429 && r.Header.Get("Retry-After") != "1" {
				t.Fatal("429 without Retry-After")
			}
		}
		if codes[200] != 2 || codes[429] != 8 || st.IsBlocked("127.0.0.1") {
			t.Fatalf("block=%s burst: %v blocked=%v", block, codes, st.IsBlocked("127.0.0.1"))
		}
		if r := req(t, ts, "other.example.com", "/"); r.StatusCode != 200 {
			t.Fatalf("other domains are not affected: %d", r.StatusCode)
		}
		// a few busy page loads are not abuse
		for i := 0; i < 30; i++ {
			req(t, ts, "api.example.com", "/")
		}
		if st.IsBlocked("127.0.0.1") {
			t.Fatalf("block=%s: blocked after 40 requests", block)
		}
		// sustained abuse: more than 60 × limit rejected within a minute
		for i := 0; i < 100; i++ {
			req(t, ts, "api.example.com", "/")
		}
		if got := st.IsBlocked("127.0.0.1"); got != (block > 0) {
			t.Fatalf("block=%s after sustained abuse: blocked=%v", block, got)
		}
		if block > 0 {
			bl := st.ListBlocked()
			if len(bl) != 1 || bl[0].ExpiresAt.Sub(bl[0].BlockedAt) != block {
				t.Fatalf("block duration %+v", bl)
			}
		}
		ts.Close()
	}
}

// The allowlist is never rate limited or blocked (an old block is ignored); a trusted address (someone
// signed in to the panel) still gets 429 but is never blocked, also not by the scanner detection.
func TestAllowlistAndTrustedIPs(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	host, ps, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(ps)
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := New(st, "")
	h.RateLimitBlock = func() time.Duration { return 5 * time.Minute }
	allow := false
	h.Exempt = func(ip string) bool { return allow && ip == "127.0.0.1" }
	ts := httptest.NewServer(h)
	defer ts.Close()
	st.Create(&store.Route{Domain: "api.example.com", TargetIP: host, TargetPort: port, RateLimit: 2})
	flood := func(n int) map[int]int {
		codes := map[int]int{}
		for i := 0; i < n; i++ {
			codes[req(t, ts, "api.example.com", "/").StatusCode]++
		}
		return codes
	}

	// trusted: limited (429) but never blocked, whatever it does
	st.Trust("127.0.0.1", time.Hour)
	if codes := flood(200); codes[429] < 150 || st.IsBlocked("127.0.0.1") {
		t.Fatalf("trusted: %v blocked=%v", codes, st.IsBlocked("127.0.0.1"))
	}
	if r := req(t, ts, "api.example.com", "/wp-login.php"); r.StatusCode == 403 || st.IsBlocked("127.0.0.1") {
		t.Fatalf("trusted client blocked by a scanner path: %d", r.StatusCode)
	}
	if r := req(t, ts, "nobody.example.com", "/"); r.StatusCode != 410 {
		t.Fatalf("unknown host: %d", r.StatusCode)
	}
	if len(st.Trusted()) != 1 {
		t.Fatalf("trusted list: %v", st.Trusted())
	}

	// an address blocked earlier works again once it is on the allowlist, without any limit
	st.Trust("127.0.0.1", -time.Second)
	st.Block("127.0.0.1", "test", time.Hour)
	if r := req(t, ts, "api.example.com", "/"); r.StatusCode != 403 {
		t.Fatalf("blocked client: %d", r.StatusCode)
	}
	allow = true
	if codes := flood(300); codes[200] != 300 {
		t.Fatalf("allowlisted: %v", codes)
	}
	if r := req(t, ts, "api.example.com", "/.env"); r.StatusCode == 403 {
		t.Fatalf("allowlisted client refused on a scanner path: %d", r.StatusCode)
	}
}

// A route whose app really serves /wp-admin & co. can switch the scanner-path blocking off for itself.
func TestAllowScannerPathsPerRoute(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	host, ps, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(ps)
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(st, ""))
	defer ts.Close()
	st.Create(&store.Route{Domain: "blog.example.com", TargetIP: host, TargetPort: port, Web: &store.Web{AllowScannerPaths: true}})
	st.Create(&store.Route{Domain: "api.example.com", TargetIP: host, TargetPort: port})
	for _, p := range []string{"/wp-login.php", "/wp-admin/index.php", "/xmlrpc.php"} {
		if r := req(t, ts, "blog.example.com", p); r.StatusCode != 200 {
			t.Fatalf("%s on the WordPress route: %d", p, r.StatusCode)
		}
	}
	if st.IsBlocked("127.0.0.1") {
		t.Fatal("blocked on a route that allows these paths")
	}
	// other routes still block, and then the client is blocked everywhere
	if r := req(t, ts, "api.example.com", "/wp-login.php"); r.StatusCode != 403 || !st.IsBlocked("127.0.0.1") {
		t.Fatalf("other route: %d blocked=%v", r.StatusCode, st.IsBlocked("127.0.0.1"))
	}
	if r := req(t, ts, "blog.example.com", "/"); r.StatusCode != 403 {
		t.Fatalf("a blocked client on the WordPress route: %d", r.StatusCode)
	}
}

// HTTP → HTTPS redirects also work for hosts served by a wildcard certificate.
func TestForceSSLWithWildcard(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(st, ""))
	defer ts.Close()
	certPEM, keyPEM := testCertPair(t, "*.apps.example.com")
	if err := st.CreateCertificate(&store.Certificate{Domain: "*.apps.example.com", CertPEM: certPEM, KeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(&store.Route{Domain: "web.apps.example.com", TargetIP: "10.0.0.1", ForceSSL: true}); err != nil {
		t.Fatal(err)
	}
	r := req(t, ts, "web.apps.example.com", "/x")
	if r.StatusCode != http.StatusMovedPermanently || r.Header.Get("Location") != "https://web.apps.example.com/x" {
		t.Fatalf("redirect: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
}

func testCertPair(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}
