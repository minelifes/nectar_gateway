package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"

	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/store"
)

const svcToken = "service-token-0123456789abcdef"

func newAPI(t *testing.T, headless bool) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	var ui fs.FS
	if !headless {
		ui = fstest.MapFS{"index.html": {Data: []byte("<html>ui</html>")}}
	}
	srv := New(st, "admin", "secret", ui, certbot.Config{}, health.New(st, ""), Options{APIToken: svcToken, Version: "1.2.3"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func call(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, ts.URL+path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestServiceTokenAndManagedRoutes(t *testing.T) {
	ts, _ := newAPI(t, true)

	if code, _ := call(t, ts, "GET", "/api/routes", "", nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := call(t, ts, "GET", "/api/routes", "wrong-token", nil); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	code, rt := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{
		"domain": "api-shop.apps.example.com", "target_ip": "api.prj-shop.svc.cluster.local", "target_port": 8080,
		"managed_by": "nectar-apps", "owner": "prj-shop/api/1"})
	if code != 201 || rt["managed_by"] != "nectar-apps" || rt["path_prefix"] != "/" {
		t.Fatalf("service create: %d %v", code, rt)
	}
	id := strconv.Itoa(int(rt["id"].(float64)))

	// a human (mobile token) cannot change or delete a managed route
	access := loginMobile(t, ts)
	if code, _ := call(t, ts, "PUT", "/api/routes/"+id, access, map[string]any{"domain": "x.example.com", "target_ip": "1.2.3.4"}); code != 409 {
		t.Fatalf("human update of managed route: %d", code)
	}
	if code, _ := call(t, ts, "DELETE", "/api/routes/"+id, access, nil); code != 409 {
		t.Fatalf("human delete of managed route: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/api/routes", access, map[string]any{"domain": "y.example.com", "target_ip": "1.2.3.4", "managed_by": "me"}); code != 403 {
		t.Fatalf("human created a managed route: %d", code)
	}
	// filtered listing
	req, _ := http.NewRequest("GET", ts.URL+"/api/routes?managed_by=nectar-apps", nil)
	req.Header.Set("Authorization", "Bearer "+svcToken)
	resp, _ := http.DefaultClient.Do(req)
	var list []map[string]any
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("filtered list: %v", list)
	}
	// duplicate host+path → 409
	if code, _ := call(t, ts, "POST", "/api/routes", svcToken, map[string]any{"domain": "api-shop.apps.example.com", "target_ip": "z"}); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	// the controller can delete it
	if code, _ := call(t, ts, "DELETE", "/api/routes/"+id, svcToken, nil); code != 204 {
		t.Fatalf("service delete: %d", code)
	}
}

func loginMobile(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	code, out := call(t, ts, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "secret"})
	if code != 200 {
		t.Fatalf("mobile login: %d %v", code, out)
	}
	return out["access_token"].(string)
}

func TestProbesVersionHeadless(t *testing.T) {
	ts, _ := newAPI(t, true)
	for _, p := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %d", p, err, resp.StatusCode)
		}
	}
	code, v := call(t, ts, "GET", "/api/version", "", nil)
	if code != 200 || v["version"] != "1.2.3" || v["api_version"].(float64) != 1 || v["headless"] != true {
		t.Fatalf("version: %d %v", code, v)
	}
	if code, _ := call(t, ts, "GET", "/", "", nil); code != 404 {
		t.Fatalf("headless UI: %d", code)
	}

	withUI, _ := newAPI(t, false)
	resp, _ := http.Get(withUI.URL + "/")
	if resp.StatusCode != 200 {
		t.Fatalf("UI: %d", resp.StatusCode)
	}
}

func TestHeadlessWithoutAdminUserOnlyAcceptsToken(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(st, "", "", nil, certbot.Config{}, health.New(st, ""), Options{APIToken: svcToken}).Handler())
	defer ts.Close()
	if code, _ := call(t, ts, "GET", "/api/routes", "", nil); code != 401 {
		t.Fatalf("no admin user + token configured must not be open: %d", code)
	}
	if code, _ := call(t, ts, "POST", "/api/auth/login", "", map[string]string{"username": "", "password": ""}); code != 401 {
		t.Fatalf("empty login accepted: %d", code)
	}
	if code, _ := call(t, ts, "GET", "/api/routes", svcToken, nil); code != 200 {
		t.Fatalf("service token: %d", code)
	}
}
