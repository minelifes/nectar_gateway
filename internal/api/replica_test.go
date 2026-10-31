package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/replica"
	"nectar_gateway/internal/settings"
	"nectar_gateway/internal/store"
)

func TestEdgeReplica(t *testing.T) {
	pst, err := store.New(filepath.Join(t.TempDir(), "primary.db"))
	if err != nil {
		t.Fatal(err)
	}
	pcfg, _ := settings.Load(pst, settings.Values{})
	primary := New(pst, "", "", nil, certbot.Config{}, health.New(pst, ""), Options{APIToken: svcToken, Settings: pcfg,
		Challenge: func(tok string) (string, bool) { return tok + ".key-auth", tok == "tok1" }})
	pts := httptest.NewServer(primary.Handler())
	t.Cleanup(pts.Close)

	rst, err := store.New(filepath.Join(t.TempDir(), "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	rcfg, _ := settings.Load(rst, settings.Values{})
	f := &replica.Follower{Primary: pts.URL, Token: svcToken, Node: "edge-2", Version: "1.4.0", Store: rst, Settings: rcfg}
	rsrv := New(rst, "", "", nil, certbot.Config{}, health.New(rst, ""), Options{APIToken: svcToken, Settings: rcfg, Follower: f})
	rts := httptest.NewServer(rsrv.Handler())
	t.Cleanup(rts.Close)

	if resp, _ := http.Get(rts.URL + "/readyz"); resp.StatusCode != 503 {
		t.Fatalf("replica ready before its first sync: %d", resp.StatusCode)
	}

	// state on the primary
	r := store.Route{Domain: "shop.example.com", PathPrefix: "/", Mode: store.ModeProxy, TargetIP: "10.0.0.5", TargetPort: 8080, RateLimit: 20}
	if err := pst.Create(&r); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := testPair(t, "shop.example.com")
	if _, err := pst.SetCert(r.ID, certPEM, keyPEM, "acme"); err != nil {
		t.Fatal(err)
	}
	pst.Block("203.0.113.9", "manual", time.Hour)
	if err := pcfg.Set(settings.Values{FallbackHTTP: "old-proxy:80", RateLimitBlockMinutes: 5, DNSProvider: "cloudflare", DNSAPIToken: "cf-secret"}); err != nil {
		t.Fatal(err)
	}
	rst.Block("198.51.100.1", "rate limit", time.Hour) // the replica's own block

	ctx := context.Background()
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := rst.Lookup("shop.example.com", "/cart")
	if !ok || got.TargetIP != "10.0.0.5" || got.RateLimit != 20 || got.KeyPEM != keyPEM {
		t.Fatalf("route on the replica: %v %+v", ok, got)
	}
	if !rst.IsBlocked("203.0.113.9") || !rst.IsBlocked("198.51.100.1") {
		t.Fatal("blocks after sync")
	}
	if v := rcfg.Get(); v.FallbackHTTP != "old-proxy:80" || v.RateLimitBlockMinutes != 5 || v.DNSAPIToken != "" {
		t.Fatalf("settings on the replica: %+v", v)
	}
	if resp, _ := http.Get(rts.URL + "/readyz"); resp.StatusCode != 200 {
		t.Fatalf("replica not ready after sync: %d", resp.StatusCode)
	}

	// unchanged → 304, the primary lists the replica
	etag := f.Status().ETag
	if err := f.Sync(ctx); err != nil || f.Status().ETag != etag {
		t.Fatalf("second sync: %v", err)
	}
	_, v := call(t, pts, "GET", "/api/replicas", svcToken, nil)
	list, _ := v["replicas"].([]any)
	if v["role"] != "primary" || len(list) != 1 || list[0].(map[string]any)["node"] != "edge-2" {
		t.Fatalf("replicas: %v", v)
	}

	// changes on the primary arrive: route deleted, block lifted (the replica's own stays)
	pst.Delete(r.ID)
	pst.Unblock("203.0.113.9")
	if err := f.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := rst.Lookup("shop.example.com", "/"); ok {
		t.Fatal("deleted route still on the replica")
	}
	if rst.IsBlocked("203.0.113.9") || !rst.IsBlocked("198.51.100.1") {
		t.Fatal("blocks after unblock")
	}

	// ACME HTTP-01 answers come from the primary
	if resp, ok := f.Challenge("tok1"); !ok || resp != "tok1.key-auth" {
		t.Fatalf("challenge: %q %v", resp, ok)
	}
	if _, ok := f.Challenge("other"); ok {
		t.Fatal("unknown challenge answered")
	}
	// a replica is read-only; the snapshot needs the service token
	if code, _ := call(t, rts, "POST", "/api/routes", svcToken, map[string]any{"domain": "x.io"}); code != 409 {
		t.Fatalf("write on replica: %d", code)
	}
	if code, _ := call(t, pts, "GET", "/api/replica/snapshot", "", nil); code != 401 {
		t.Fatalf("snapshot without token: %d", code)
	}
	_, v = call(t, rts, "GET", "/api/replicas", svcToken, nil)
	if v["role"] != "replica" {
		t.Fatalf("replica status: %v", v)
	}
}
