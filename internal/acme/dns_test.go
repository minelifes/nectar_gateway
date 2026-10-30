package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"nectar_gateway/internal/store"
)

// fakeDNS is a DNSProvider and TXTLookup backed by a map.
type fakeDNS struct {
	mu      sync.Mutex
	txt     map[string][]string
	created []string
	fail    error
}

func (f *fakeDNS) Present(_ context.Context, fqdn, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.txt[fqdn] = append(f.txt[fqdn], value)
	f.created = append(f.created, fqdn)
	return nil
}

func (f *fakeDNS) CleanUp(_ context.Context, fqdn, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keep []string
	for _, v := range f.txt[fqdn] {
		if v != value {
			keep = append(keep, v)
		}
	}
	f.txt[fqdn] = keep
	return nil
}

func (f *fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.txt[name]...), nil
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// dnsCA is a test CA that validates dns-01 by looking at the fake DNS: the TXT value must be the
// base64url SHA-256 of "token.<account key thumbprint>" (RFC 8555 §8.4).
func dnsCA(t *testing.T, st *store.Store, dns *fakeDNS) *testCA {
	ca := newTestCA(t).ChallengeTypes("http-01", "dns-01")
	ca.verifyDNS = func(domain, token string) error {
		raw, _ := st.GetKV(accountKeyKV)
		block, _ := pem.Decode(raw)
		if block == nil {
			return errors.New("no account key")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		tp, err := xacme.JWKThumbprint(key.Public().(crypto.PublicKey))
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(token + "." + tp))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		txt, _ := dns.lookup(context.Background(), "_acme-challenge."+domain)
		for _, v := range txt {
			if v == want {
				return nil
			}
		}
		return fmt.Errorf("TXT _acme-challenge.%s = %v, want %s", domain, txt, want)
	}
	return ca.Start()
}

func TestWildcardCertificateOverDNS01(t *testing.T) {
	st := openStore(t)
	dns := &fakeDNS{txt: map[string][]string{}}
	ca := dnsCA(t, st, dns)
	is := New(st, "ops@example.com", ca.URL()+"/")
	ctx := context.Background()

	c := store.Certificate{Domain: "*.apps.example.com", IncludeApex: true, ACME: true}
	if err := st.CreateCertificate(&c); err != nil {
		t.Fatal(err)
	}
	// without a DNS provider a wildcard cannot be issued; the reason is kept on the certificate
	if err := is.IssueCertificate(ctx, c.ID); !errors.Is(err, ErrNoDNS) {
		t.Fatalf("no provider: %v", err)
	}
	if got, _ := st.Certificate(c.ID); got.LastError == "" || got.LastAttempt == 0 {
		t.Fatalf("error not recorded: %+v", got)
	}

	is.SetDNSProvider(dns, dns.lookup, time.Second)
	if !is.HasDNS() {
		t.Fatal("HasDNS")
	}
	if err := is.IssueCertificate(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Certificate(c.ID)
	if got.Source != "acme" || got.LastError != "" || got.NotAfter < time.Now().Add(80*24*time.Hour).Unix() {
		t.Fatalf("issued: %+v", got)
	}
	_, names, err := store.ParseCertPair(got.CertPEM, got.KeyPEM)
	if err != nil || strings.Join(names, ",") != "*.apps.example.com,apps.example.com" {
		t.Fatalf("names %v %v", names, err)
	}
	// both authorizations used the same record name; the records are gone again
	if len(dns.created) != 2 || dns.created[0] != "_acme-challenge.apps.example.com" || len(dns.txt["_acme-challenge.apps.example.com"]) != 0 {
		t.Fatalf("dns records: created %v, left %v", dns.created, dns.txt)
	}
	// it now serves hosts one level below the wildcard (and the apex), not deeper ones
	for host, want := range map[string]bool{"api-shop.apps.example.com": true, "apps.example.com": true, "a.b.apps.example.com": false, "example.com": false} {
		if _, ok := st.CoveringCertificate(host); ok != want {
			t.Errorf("covers %s = %v", host, ok)
		}
	}

	// a route of a covered host gets no HTTP-01 order of its own during renewals
	rt := store.Route{Domain: "api-shop.apps.example.com", TargetIP: "10.0.0.1", TargetPort: 80, ACME: true, ForceSSL: true}
	if err := st.Create(&rt); err != nil {
		t.Fatalf("force_ssl on a host covered by the wildcard: %v", err)
	}
	is.renewOnce(ctx)
	if r, _ := st.Get(rt.ID); r.CertPEM != "" {
		t.Fatal("covered route got its own certificate")
	}
	if rs := st.WithCoverage([]store.Route{rt}); rs[0].CoveredBy != "*.apps.example.com" || rs[0].CoveredUntil != got.NotAfter {
		t.Fatalf("coverage: %+v", rs[0])
	}
}

func TestDNSProviderFailureIsReported(t *testing.T) {
	st := openStore(t)
	dns := &fakeDNS{txt: map[string][]string{}, fail: errors.New("cloudflare: Authentication error (10000)")}
	ca := dnsCA(t, st, dns)
	is := New(st, "", ca.URL()+"/")
	is.SetDNSProvider(dns, dns.lookup, time.Second)
	c := store.Certificate{Domain: "*.example.org", ACME: true}
	if err := st.CreateCertificate(&c); err != nil {
		t.Fatal(err)
	}
	err := is.IssueCertificate(context.Background(), c.ID)
	if err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("err %v", err)
	}
	// renewals do not hammer the CA after a failure (retried after an hour)
	is.renewOnce(context.Background())
	if len(dns.created) != 0 {
		t.Fatal("retried too early")
	}
}

func TestCloudflare(t *testing.T) {
	var mu sync.Mutex
	records := map[string]map[string]string{} // zone → id → content
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth = append(auth, r.Header.Get("Authorization"))
		ok := func(v any) { json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v}) }
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.com" {
				ok([]map[string]string{{"id": "z1", "name": "example.com"}})
				return
			}
			ok([]any{})
		case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			if in["type"] != "TXT" || in["name"] != "_acme-challenge.apps.example.com" {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 1, "message": "bad record"}}})
				return
			}
			if records["z1"] == nil {
				records["z1"] = map[string]string{}
			}
			id := fmt.Sprintf("r%d", len(records["z1"])+1)
			records["z1"][id] = in["content"].(string)
			ok(map[string]string{"id": id})
		case r.Method == "GET" && r.URL.Path == "/zones/z1/dns_records":
			var out []map[string]string
			for id, c := range records["z1"] {
				out = append(out, map[string]string{"id": id, "content": c})
			}
			ok(out)
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			delete(records["z1"], strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/"))
			ok(map[string]string{})
		case r.URL.Path == "/zones/z9/dns_records":
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "Authentication error"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cf := &Cloudflare{Token: "tok", API: srv.URL}
	ctx := context.Background()
	if err := cf.Present(ctx, "_acme-challenge.apps.example.com", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := cf.Present(ctx, "_acme-challenge.apps.example.com", "v2"); err != nil {
		t.Fatal(err)
	}
	if err := cf.CleanUp(ctx, "_acme-challenge.apps.example.com", "v1"); err != nil {
		t.Fatal(err)
	}
	if len(records["z1"]) != 1 || records["z1"]["r2"] != "v2" {
		t.Fatalf("records %v", records)
	}
	if auth[0] != "Bearer tok" {
		t.Fatalf("auth %q", auth[0])
	}
	if err := cf.Present(ctx, "_acme-challenge.other.net", "x"); err == nil || !strings.Contains(err.Error(), "no zone") {
		t.Fatalf("unknown zone: %v", err)
	}
	if p, err := NewDNSProvider("cloudflare", ""); err == nil || p != nil {
		t.Fatal("token required")
	}
	if _, err := NewDNSProvider("route53", "x"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestWaitTXT(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{}}
	go func() {
		time.Sleep(30 * time.Millisecond)
		dns.Present(context.Background(), "_acme-challenge.x.test", "v")
	}()
	if !waitTXT(context.Background(), dns.lookup, "_acme-challenge.x.test", "v", time.Second, 10*time.Millisecond) {
		t.Fatal("not seen")
	}
	if waitTXT(context.Background(), dns.lookup, "_acme-challenge.y.test", "v", 50*time.Millisecond, 10*time.Millisecond) {
		t.Fatal("seen without a record")
	}
}
