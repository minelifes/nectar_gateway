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
		// sustained abuse: more than 10 × limit rejected within a minute
		for i := 0; i < 30; i++ {
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
