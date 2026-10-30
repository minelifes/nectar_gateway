package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCF is a tiny Cloudflare API: one zone example.com with address records.
type fakeCF struct {
	mu   sync.Mutex
	recs map[string]cfRecord
	n    int
}

func (f *fakeCF) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(v any) { json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v}) }
	switch {
	case r.Method == "GET" && r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			ok([]map[string]string{{"id": "z1", "name": "example.com"}})
			return
		}
		ok([]any{})
	case r.Method == "GET" && r.URL.Path == "/zones/z1/dns_records":
		out := []cfRecord{}
		for _, rec := range f.recs {
			if rec.Name == r.URL.Query().Get("name") {
				out = append(out, rec)
			}
		}
		ok(out)
	case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
		var rec cfRecord
		json.NewDecoder(r.Body).Decode(&rec)
		f.n++
		rec.ID = fmt.Sprintf("r%d", f.n)
		f.recs[rec.ID] = rec
		ok(rec)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
		delete(f.recs, strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/"))
		ok(map[string]string{})
	default:
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 7003, "message": "not found"}}})
	}
}

func TestCloudflareAddresses(t *testing.T) {
	f := &fakeCF{recs: map[string]cfRecord{}}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	cf := &Cloudflare{Token: "t", API: srv.URL}
	ctx := context.Background()

	res, err := cf.EnsureAddresses(ctx, "shop.example.com", []string{"203.0.113.5", "2001:db8::5"})
	if err != nil || res.Created != 2 || res.Zone != "z1" || res.Conflict != "" {
		t.Fatalf("create: %+v %v", res, err)
	}
	// same again: nothing changes
	if res, err = cf.EnsureAddresses(ctx, "shop.example.com", []string{"2001:db8::5", "203.0.113.5"}); err != nil || res.Created+res.Deleted != 0 || len(res.Records) != 2 {
		t.Fatalf("idempotent: %+v %v", res, err)
	}
	// server moved: the stale A record is replaced, AAAA removed
	if res, err = cf.EnsureAddresses(ctx, "shop.example.com", []string{"198.51.100.7"}); err != nil || res.Created != 1 || res.Deleted != 2 {
		t.Fatalf("move: %+v %v", res, err)
	}
	// someone else's record: left alone, conflict reported
	f.recs["mine"] = cfRecord{ID: "mine", Type: "CNAME", Name: "blog.example.com", Content: "ghs.example.net"}
	if res, err = cf.EnsureAddresses(ctx, "blog.example.com", []string{"198.51.100.7"}); err != nil || res.Conflict == "" || res.Created != 0 {
		t.Fatalf("conflict: %+v %v", res, err)
	}
	if _, ok := f.recs["mine"]; !ok {
		t.Fatal("foreign record deleted")
	}
	_, list, err := cf.ListAddresses(ctx, "shop.example.com")
	if err != nil || len(list) != 1 || !list[0].Managed || list[0].Content != "198.51.100.7" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if n, err := cf.DeleteAddresses(ctx, "shop.example.com"); err != nil || n != 1 {
		t.Fatalf("delete: %d %v", n, err)
	}
	if n, _ := cf.DeleteAddresses(ctx, "blog.example.com"); n != 0 {
		t.Fatal("deleted a foreign record")
	}
	if _, err := cf.EnsureAddresses(ctx, "x.other.org", []string{"198.51.100.7"}); err == nil {
		t.Fatal("name outside the zones accepted")
	}
}
