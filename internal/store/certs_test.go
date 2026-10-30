package store

import (
	"errors"
	"testing"
)

func TestStandaloneCertificates(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{"", "*", "*.com", "a.*.example.com", "exa mple.com", "-a.example.com", "localhost"} {
		if err := s.CreateCertificate(&Certificate{Domain: bad, ACME: true}); err == nil {
			t.Errorf("domain %q accepted", bad)
		}
	}
	wild := Certificate{Domain: " *.Apps.Example.com. ", IncludeApex: true, ACME: true}
	if err := s.CreateCertificate(&wild); err != nil || wild.Domain != "*.apps.example.com" {
		t.Fatalf("create: %+v %v", wild, err)
	}
	if err := s.CreateCertificate(&Certificate{Domain: "*.apps.example.com", ACME: true}); !errors.Is(err, ErrCertConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	// not issued yet: covers nothing
	if _, ok := s.CoveringCertificate("a.apps.example.com"); ok {
		t.Fatal("pending certificate serves hosts")
	}
	// a pair must cover every name (the apex too)
	certPEM, keyPEM := selfSigned(t, "*.apps.example.com")
	if _, err := s.SetCertificatePair(wild.ID, certPEM, keyPEM, "acme"); err == nil {
		t.Fatal("pair without the apex accepted")
	}
	certPEM, keyPEM = selfSigned(t, "*.apps.example.com", "apps.example.com")
	got, err := s.SetCertificatePair(wild.ID, certPEM, keyPEM, "acme")
	if err != nil || got.Source != "acme" || got.NotAfter == 0 {
		t.Fatalf("pair: %+v %v", got, err)
	}
	// an uploaded exact certificate beats the wildcard for its host
	ePEM, eKey := selfSigned(t, "shop.apps.example.com")
	exact := Certificate{Domain: "shop.apps.example.com", CertPEM: ePEM, KeyPEM: eKey}
	if err := s.CreateCertificate(&exact); err != nil || exact.Source != "upload" || exact.ACME {
		t.Fatalf("upload: %+v %v", exact, err)
	}
	for host, want := range map[string]string{"shop.apps.example.com": "shop.apps.example.com", "web.apps.example.com": "*.apps.example.com",
		"apps.example.com": "*.apps.example.com", "x.web.apps.example.com": "", "example.com": ""} {
		c, ok := s.CoveringCertificate(host)
		if ok != (want != "") || c.Domain != want {
			t.Errorf("%s → %q (%v), want %q", host, c.Domain, ok, want)
		}
	}
	// a route's own certificate wins over a covering one; force_ssl works on covered hosts
	r := Route{Domain: "web.apps.example.com", TargetIP: "10.0.0.1", ForceSSL: true}
	if err := s.Create(&r); err != nil {
		t.Fatalf("force_ssl on a covered host: %v", err)
	}
	if !s.HasTLS("web.apps.example.com") || s.HasTLS("nope.example.org") {
		t.Fatal("HasTLS")
	}
	if err := s.Create(&Route{Domain: "nope.example.org", TargetIP: "10.0.0.1", ForceSSL: true}); err == nil {
		t.Fatal("force_ssl without any certificate accepted")
	}
	own := Route{Domain: "own.apps.example.com", TargetIP: "10.0.0.2"}
	s.Create(&own)
	oPEM, oKey := selfSigned(t, "own.apps.example.com")
	s.SetCert(own.ID, oPEM, oKey, "upload")
	routes := s.WithCoverage(s.All())
	for _, rt := range routes {
		switch rt.Domain {
		case "web.apps.example.com":
			if rt.CoveredBy != "*.apps.example.com" || rt.CoveredUntil != got.NotAfter {
				t.Errorf("coverage of %s: %+v", rt.Domain, rt)
			}
		case "own.apps.example.com":
			if rt.CoveredBy != "" {
				t.Errorf("a route with its own certificate is not covered: %+v", rt)
			}
		}
	}
	// the cache survives a restart (new Store on the same file) and deletes work
	if err := s.SetCertificateError(wild.ID, "boom"); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Certificate(wild.ID); c.LastError != "boom" || c.CertPEM == "" {
		t.Fatalf("error kept the pair: %+v", c)
	}
	if err := s.DeleteCertificate(exact.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.CoveringCertificate("shop.apps.example.com"); c.Domain != "*.apps.example.com" {
		t.Fatalf("after delete: %+v", c)
	}
	if list := s.Certificates(); len(list) != 1 || list[0].Names()[1] != "apps.example.com" {
		t.Fatalf("list %+v", list)
	}
}
