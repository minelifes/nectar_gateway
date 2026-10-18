package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// SelfSigned returns a PEM certificate + key for names (test helper).
func selfSigned(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

func TestMigrateFromV0KeepsRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open(driverName(), path)
	if err != nil {
		t.Fatal(err)
	}
	// the original schema: UNIQUE(domain), no path/managed columns, some columns missing
	for _, q := range []string{
		`CREATE TABLE routes (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, target_ip TEXT NOT NULL DEFAULT '', target_port INTEGER NOT NULL DEFAULT 80)`,
		`INSERT INTO routes (domain, target_ip, target_port) VALUES ('old.example.com', '10.0.0.9', 8080)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := s.Lookup("old.example.com", "/anything")
	if !ok || r.TargetIP != "10.0.0.9" || r.TargetPort != 8080 || r.PathPrefix != "/" || r.Mode != ModeProxy {
		t.Fatalf("migrated route: %+v %v", r, ok)
	}
	// the new unique key allows a second route on the same host with another path
	if err := s.Create(&Route{Domain: "old.example.com", PathPrefix: "/api", TargetIP: "10.0.0.10", TargetPort: 9000}); err != nil {
		t.Fatal(err)
	}
	// reopening an up-to-date database is a no-op
	s2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if all, _ := s2.List(); len(all) != 2 {
		t.Fatalf("routes after reopen: %d", len(all))
	}
}

func TestPathAndWildcardLookup(t *testing.T) {
	s := newStore(t)
	for _, r := range []Route{
		{Domain: "shop.example.com", TargetIP: "web", TargetPort: 80},
		{Domain: "shop.example.com", PathPrefix: "/api/", TargetIP: "api", TargetPort: 8080},
		{Domain: "shop.example.com", PathPrefix: "/api/v2", TargetIP: "api2", TargetPort: 8080},
		{Domain: "*.apps.example.com", TargetIP: "catchall", TargetPort: 80},
		{Domain: "docs.apps.example.com", TargetIP: "docs", TargetPort: 80},
	} {
		r := r
		if err := s.Create(&r); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[[2]string]string{
		{"shop.example.com", "/"}:           "web",
		{"shop.example.com", "/apix"}:       "web", // prefix match is per path segment
		{"shop.example.com", "/api"}:        "api",
		{"shop.example.com", "/api/orders"}: "api",
		{"shop.example.com", "/api/v2/x"}:   "api2",
		{"SHOP.example.com", "/"}:           "web",
		{"x.apps.example.com", "/"}:         "catchall",
		{"docs.apps.example.com", "/"}:      "docs", // exact beats wildcard
		{"a.b.apps.example.com", "/"}:       "",     // wildcard covers one label only
		{"apps.example.com", "/"}:           "",
		{"unknown.example.com", "/"}:        "",
	}
	for in, want := range cases {
		r, ok := s.Lookup(in[0], in[1])
		if got := r.TargetIP; (want == "" && ok) || (want != "" && got != want) {
			t.Errorf("Lookup(%s, %s) = %q, want %q", in[0], in[1], got, want)
		}
	}
	if err := s.Create(&Route{Domain: "shop.example.com", PathPrefix: "/api", TargetIP: "dup"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate host+path: %v", err)
	}
	if err := s.Create(&Route{Domain: "bad*.example.com", TargetIP: "x"}); err == nil {
		t.Fatal("invalid wildcard accepted")
	}
}

func TestStoredCertificates(t *testing.T) {
	s := newStore(t)
	a := Route{Domain: "shop.example.com", TargetIP: "web"}
	b := Route{Domain: "shop.example.com", PathPrefix: "/api", TargetIP: "api"}
	s.Create(&a)
	s.Create(&b)

	certPEM, keyPEM := selfSigned(t, "other.example.com")
	if _, err := s.SetCert(a.ID, certPEM, keyPEM, "upload"); err == nil {
		t.Fatal("certificate for another name accepted")
	}
	certPEM, keyPEM = selfSigned(t, "shop.example.com")
	r, err := s.SetCert(a.ID, certPEM, keyPEM, "upload")
	if err != nil || r.CertSource != "upload" || r.CertNotAfter == 0 {
		t.Fatalf("SetCert = %+v, %v", r, err)
	}
	// TLS is per host: the /api route got the certificate too
	if rb, _ := s.Get(b.ID); !rb.HasSSL() {
		t.Fatal("certificate not shared across the host's routes")
	}
	// updating a route through the API (no PEMs in JSON) keeps the stored certificate
	upd := a
	upd.CertPEM, upd.KeyPEM, upd.TargetPort = "", "", 9090
	if err := s.Update(&upd); err != nil {
		t.Fatal(err)
	}
	if ra, _ := s.Get(a.ID); !ra.HasSSL() || ra.TargetPort != 9090 {
		t.Fatalf("update lost the certificate: %+v", ra)
	}
	// wildcard certificate covers one label
	wc, wk := selfSigned(t, "*.apps.example.com")
	w := Route{Domain: "x.apps.example.com", TargetIP: "w"}
	s.Create(&w)
	if _, err := s.SetCert(w.ID, wc, wk, "upload"); err != nil {
		t.Fatalf("wildcard cert: %v", err)
	}
	if err := s.ClearCert(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.CertRoute("shop.example.com"); ok {
		t.Fatal("certificate not cleared")
	}
}

func TestFilters(t *testing.T) {
	s := newStore(t)
	s.Create(&Route{Domain: "a.example.com", TargetIP: "x"})
	s.Create(&Route{Domain: "b.example.com", TargetIP: "x", ManagedBy: "nectar-apps", Owner: "prj-shop/api/1"})
	m := "nectar-apps"
	if rs, _ := s.List(Filter{ManagedBy: &m}); len(rs) != 1 || rs[0].Owner != "prj-shop/api/1" {
		t.Fatalf("managed filter: %+v", rs)
	}
	none := ""
	if rs, _ := s.List(Filter{ManagedBy: &none}); len(rs) != 1 || rs[0].Domain != "a.example.com" {
		t.Fatalf("unmanaged filter: %+v", rs)
	}
}

func TestMigrateFromV2AddsColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(&Route{Domain: "keep.example.com", TargetIP: "10.0.0.1", TargetPort: 80}); err != nil {
		t.Fatal(err)
	}
	// turn it back into a v2 database: drop the v3 columns
	for _, c := range []string{"backend_protocol", "timeout_seconds", "max_body_mb", "redirect_url", "redirect_code", "basic_auth"} {
		if _, err := s.db.Exec(`ALTER TABLE routes DROP COLUMN ` + c); err != nil {
			t.Fatal(err)
		}
	}
	s.db.Exec(`PRAGMA user_version = 2`)
	s.db.Close()

	s, err = New(path)
	if err != nil {
		t.Fatalf("migrate v2→v3: %v", err)
	}
	r, ok := s.Lookup("keep.example.com", "/")
	if !ok || r.BackendProtocol != ProtoHTTP1 || r.TargetIP != "10.0.0.1" {
		t.Fatalf("route after migration: %+v %v", r, ok)
	}
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != schemaVersion {
		t.Fatalf("user_version = %d", v)
	}
}
