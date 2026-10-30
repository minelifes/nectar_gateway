package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/settings"
	"nectar_gateway/internal/store"
)

// fakeIssuer records certificate orders.
type fakeIssuer struct {
	mu     sync.Mutex
	dns    bool
	issued []int64
	done   chan struct{}
}

func (f *fakeIssuer) Issue(context.Context, string) (string, string, error) { return "", "", nil }
func (f *fakeIssuer) HasDNS() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dns
}
func (f *fakeIssuer) IssueCertificate(_ context.Context, id int64) error {
	f.mu.Lock()
	f.issued = append(f.issued, id)
	f.mu.Unlock()
	f.done <- struct{}{}
	return nil
}

func getList(t *testing.T, ts *httptest.Server, path string) []map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+svcToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestCertificatesAPIAndDNSSettings(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := settings.Load(st, settings.Values{})
	iss := &fakeIssuer{done: make(chan struct{}, 4)}
	srv := New(st, "", "", nil, certbot.Config{}, health.New(st, ""), Options{APIToken: svcToken, Settings: cfg, Issuer: iss, Version: "1.4.0"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// features tell controllers what this build can do
	_, v := call(t, ts, "GET", "/api/version", "", nil)
	if f, _ := json.Marshal(v["features"]); string(f) != `["certificates","acme"]` {
		t.Fatalf("features %s", f)
	}
	// a wildcard needs the DNS provider first
	code, v := call(t, ts, "POST", "/api/certificates", svcToken, map[string]any{"domain": "*.apps.example.com", "include_apex": true})
	if code != 409 || !strings.Contains(v["error"].(string), "DNS provider") {
		t.Fatalf("wildcard without dns: %d %v", code, v)
	}
	// the DNS token is write-only
	if code, v := call(t, ts, "PUT", "/api/settings", svcToken, map[string]string{"dns_provider": "cloudflare"}); code != 400 || !strings.Contains(v["error"].(string), "dns_api_token") {
		t.Fatalf("provider without token: %d %v", code, v)
	}
	if code, v := call(t, ts, "PUT", "/api/settings", svcToken, map[string]string{"dns_provider": "godaddy", "dns_api_token": "x"}); code != 400 {
		t.Fatalf("unknown provider: %d %v", code, v)
	}
	code, v = call(t, ts, "PUT", "/api/settings", svcToken, map[string]string{"dns_provider": "cloudflare", "dns_api_token": "cf-secret"})
	if code != 200 || v["dns_token_set"] != true || v["dns_api_token"] != nil || v["dns_provider"] != "cloudflare" {
		t.Fatalf("dns settings: %d %v", code, v)
	}
	if _, v := call(t, ts, "GET", "/api/settings", svcToken, nil); v["dns_api_token"] != nil || v["dns_token_set"] != true {
		t.Fatalf("token leaked: %v", v)
	}
	// other settings changes keep the token
	call(t, ts, "PUT", "/api/settings", svcToken, map[string]string{"acme_email": "ops@example.com"})
	if cfg.Get().DNSAPIToken != "cf-secret" {
		t.Fatal("token lost on an unrelated change")
	}
	iss.mu.Lock()
	iss.dns = true
	iss.mu.Unlock()

	code, v = call(t, ts, "POST", "/api/certificates", svcToken, map[string]any{"domain": "*.apps.example.com", "include_apex": true, "managed_by": "nectar-apps", "owner": "base-domain"})
	if code != 201 || v["status"] != "pending" || v["acme"] != true {
		t.Fatalf("create: %d %v", code, v)
	}
	id := int64(v["id"].(float64))
	select {
	case <-iss.done:
	case <-time.After(2 * time.Second):
		t.Fatal("order not started")
	}
	if names, _ := json.Marshal(v["names"]); string(names) != `["*.apps.example.com","apps.example.com"]` {
		t.Fatalf("names %s", names)
	}
	if code, _ := call(t, ts, "POST", "/api/certificates", svcToken, map[string]any{"domain": "*.apps.example.com"}); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/api/certificates", svcToken, map[string]any{"domain": "x.example.com", "acme": false}); code != 400 {
		t.Fatalf("neither acme nor a pair: %d", code)
	}

	// once issued it serves routes, shown in both lists
	certPEM, keyPEM := testPair(t, "*.apps.example.com", "apps.example.com")
	if _, err := st.SetCertificatePair(id, certPEM, keyPEM, "acme"); err != nil {
		t.Fatal(err)
	}
	if code, v := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{"domain": "web-shop.apps.example.com", "target_ip": "10.0.0.1", "force_ssl": true}); code != 201 {
		t.Fatalf("route on a covered host: %d %v", code, v)
	}
	routes := getList(t, ts, "/api/routes")
	if len(routes) != 1 || routes[0]["covered_by"] != "*.apps.example.com" {
		t.Fatalf("routes %v", routes)
	}
	certs := getList(t, ts, "/api/certificates")
	if len(certs) != 1 || certs[0]["status"] != "valid" || certs[0]["cert_pem"] != nil || certs[0]["key_pem"] != nil {
		t.Fatalf("certs %v", certs)
	}
	if serves, _ := json.Marshal(certs[0]["serves"]); string(serves) != `["web-shop.apps.example.com"]` {
		t.Fatalf("serves %s", serves)
	}
	// managed certificates: read-only without the service token is tested via the token-only server;
	// renew and delete with the service token
	if code, _ := call(t, ts, "POST", "/api/certificates/"+itoa(id)+"/renew", svcToken, nil); code != 202 {
		t.Fatalf("renew: %d", code)
	}
	<-iss.done
	if code, _ := call(t, ts, "DELETE", "/api/certificates/"+itoa(id), svcToken, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call(t, ts, "DELETE", "/api/certificates/"+itoa(id), svcToken, nil); code != 404 {
		t.Fatalf("delete again: %d", code)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func testPair(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}
