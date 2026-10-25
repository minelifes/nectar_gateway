package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/metrics"
	"nectar_gateway/internal/settings"
	"nectar_gateway/internal/store"

	"golang.org/x/crypto/bcrypt"
)

func TestSettingsMetricsAndRouteOptions(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := settings.Load(st, settings.Values{FallbackHTTP: "env-default:80"})
	if err != nil {
		t.Fatal(err)
	}
	rec := metrics.New(10)
	rec.Record(metrics.Entry{Domain: "a.io", Host: "a.io", Status: 200, MS: 4, Path: "/"})
	srv := New(st, "", "", nil, certbot.Config{}, health.New(st, ""), Options{APIToken: svcToken, Metrics: rec, Settings: cfg})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if code, _ := call(t, ts, "GET", "/api/settings", "", nil); code != 401 {
		t.Fatalf("settings without token: %d", code)
	}
	code, v := call(t, ts, "GET", "/api/settings", svcToken, nil)
	if code != 200 || v["fallback_http"] != "env-default:80" {
		t.Fatalf("settings default: %d %v", code, v)
	}
	if code, _ := call(t, ts, "PUT", "/api/settings", svcToken, map[string]string{"fallback_tls": "http://bad"}); code != 400 {
		t.Fatalf("bad fallback accepted: %d", code)
	}
	code, v = call(t, ts, "PUT", "/api/settings", svcToken, map[string]string{"fallback_tls": "traefik.kube-system.svc.cluster.local:443"})
	if code != 200 || v["fallback_http"] != "env-default:80" || v["fallback_tls"] != "traefik.kube-system.svc.cluster.local:443" {
		t.Fatalf("settings put (merge): %d %v", code, v)
	}
	// persisted: a reload keeps the API value over a different env default
	cfg2, _ := settings.Load(st, settings.Values{FallbackTLS: "other:443"})
	if cfg2.Get().FallbackTLS != "traefik.kube-system.svc.cluster.local:443" {
		t.Fatalf("settings not persisted: %+v", cfg2.Get())
	}

	code, v = call(t, ts, "GET", "/api/metrics?minutes=5", svcToken, nil)
	doms, _ := v["domains"].([]any)
	if code != 200 || len(doms) != 1 || doms[0].(map[string]any)["domain"] != "a.io" {
		t.Fatalf("metrics: %d %v", code, v)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/access-log?status=2xx", nil)
	req.Header.Set("Authorization", "Bearer "+svcToken)
	resp, _ := http.DefaultClient.Do(req)
	var logs []map[string]any
	json.NewDecoder(resp.Body).Decode(&logs)
	resp.Body.Close()
	if len(logs) != 1 || logs[0]["path"] != "/" {
		t.Fatalf("access log: %v", logs)
	}

	// route options round-trip through the API; basic-auth hashes never leave the gateway
	code, rt := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{
		"domain": "staging.a.io", "target_ip": "10.0.0.1", "target_port": 80, "backend_protocol": "h2c",
		"timeout_seconds": 120, "max_body_mb": 50, "basic_auth_users": []map[string]string{{"user": "qa", "password": "qa-password"}},
	})
	if code != 201 || rt["backend_protocol"] != "h2c" || rt["timeout_seconds"].(float64) != 120 || rt["max_body_mb"].(float64) != 50 {
		t.Fatalf("route options: %d %v", code, rt)
	}
	if rt["basic_auth"] != nil || rt["basic_auth_users"] != nil || rt["auth_usernames"].([]any)[0] != "qa" {
		t.Fatalf("basic auth leaked or missing: %v", rt)
	}
	code, rd := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{"domain": "www.a.io", "mode": "redirect", "redirect_url": "https://a.io"})
	if code != 201 || rd["redirect_code"].(float64) != 301 {
		t.Fatalf("redirect route: %d %v", code, rd)
	}
}

func TestHtpasswdInputAndFingerprint(t *testing.T) {
	ts, _ := newAPI(t, true)
	// bcrypt hash of "pw-123456" (cost 4) — produced once with x/crypto/bcrypt
	hash := mustBcrypt(t, "pw-123456")
	code, rt := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{
		"domain": "qa.example.com", "target_ip": "10.0.0.1", "managed_by": "nectar-apps",
		"basic_auth_htpasswd": "qa:" + hash + "\n",
	})
	if code != 201 || rt["auth_fingerprint"] != store.AuthFingerprint("qa:"+hash) || rt["auth_usernames"].([]any)[0] != "qa" {
		t.Fatalf("htpasswd route: %d %v", code, rt)
	}
	if code, _ := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{"domain": "q2.example.com", "target_ip": "x", "basic_auth_htpasswd": "qa:plain"}); code != 400 {
		t.Fatalf("non-bcrypt accepted: %d", code)
	}
}

func mustBcrypt(t *testing.T, pw string) string {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 4)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBlockAndFallbackHitsAPI(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	rec := metrics.New(10)
	rec.RecordFallback("old.example.com", metrics.FallbackKindTLS)
	srv := New(st, "", "", nil, certbot.Config{}, health.New(st, ""), Options{APIToken: svcToken, Metrics: rec})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	if code, _ := call(t, ts, "POST", "/api/blocked", svcToken, map[string]any{"ip": "nope"}); code != 400 {
		t.Fatalf("bad ip accepted: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/api/blocked", "", map[string]any{"ip": "9.9.9.9"}); code != 401 {
		t.Fatalf("anonymous block: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/api/blocked", svcToken, map[string]any{"ip": "9.9.9.9", "reason": "imported"}); code != 204 {
		t.Fatalf("block: %d", code)
	}
	if !st.IsBlocked("9.9.9.9") {
		t.Fatal("not blocked")
	}
	code, v := call(t, ts, "GET", "/api/fallback-hits", svcToken, nil)
	hosts, _ := v["hosts"].([]any)
	if code != 200 || len(hosts) != 1 || hosts[0].(map[string]any)["tls"].(float64) != 1 {
		t.Fatalf("fallback hits: %d %v", code, v)
	}
	if code, _ := call(t, ts, "DELETE", "/api/fallback-hits", svcToken, nil); code != 204 || len(rec.FallbackHits()) != 0 {
		t.Fatalf("reset: %d", code)
	}
}
