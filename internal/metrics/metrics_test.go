package metrics

import (
	"fmt"
	"testing"
	"time"
)

func TestSummariesAndPercentiles(t *testing.T) {
	r := New(50)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }

	// 100 requests to app.io: 90 fast (≤10ms), 10 slow (~800ms → 1000ms bucket); 5 are 500s
	for i := 0; i < 100; i++ {
		ms, status := int64(8), 200
		if i >= 90 {
			ms = 800
		}
		if i%20 == 0 {
			status = 502
		}
		r.Record(Entry{Domain: "app.io", Host: "app.io", Status: status, MS: ms, BytesOut: 100, BytesIn: 10, IP: "1.2.3.4", Path: "/"})
	}
	r.Record(Entry{Host: "random.io", Status: 410, MS: 1})

	sums := r.Summaries(60, "", false)
	if len(sums) != 2 || sums[0].Domain != "app.io" || sums[1].Domain != Unknown {
		t.Fatalf("summaries: %+v", sums)
	}
	s := sums[0]
	if s.Requests != 100 || s.Status.S5xx != 5 || s.Status.S2xx != 95 || s.BytesOut != 10000 || s.ErrorRate != 0.05 {
		t.Fatalf("totals: %+v", s)
	}
	if s.P50MS != 10 || s.P95MS != 1000 {
		t.Fatalf("p50=%d p95=%d", s.P50MS, s.P95MS)
	}

	// next minute: series has two points, old data stays inside the window
	now = now.Add(time.Minute)
	r.Record(Entry{Domain: "app.io", Status: 200, MS: 3})
	one := r.Summaries(2, "app.io", true)[0]
	if len(one.Series) != 2 || one.Series[0].Requests != 100 || one.Series[1].Requests != 1 || one.Requests != 101 {
		t.Fatalf("series: %+v", one.Series)
	}
	// an hour later everything has aged out
	now = now.Add(61 * time.Minute)
	if got := r.Summaries(60, "", false); len(got) != 0 {
		t.Fatalf("aged out: %+v", got)
	}
}

func TestAccessLogRing(t *testing.T) {
	r := New(5)
	for i := 0; i < 8; i++ {
		r.Record(Entry{Domain: "a.io", Host: "a.io", Status: 200 + i%2*300, Path: fmt.Sprintf("/%d", i), IP: "9.9.9.9"})
	}
	all := r.Log(LogQuery{Limit: 100})
	if len(all) != 5 || all[0].Path != "/7" || all[4].Path != "/3" {
		t.Fatalf("ring: %+v", all)
	}
	if errs := r.Log(LogQuery{Status: 5}); len(errs) != 3 { // the last five are /3../7; odd ones are 500s
		t.Fatalf("5xx filter: %d", len(errs))
	}
	if got := r.Log(LogQuery{Domain: "b.io"}); len(got) != 0 {
		t.Fatal("domain filter")
	}
	var nilRec *Recorder
	nilRec.Record(Entry{})
	if nilRec.Summaries(1, "", false) != nil || nilRec.Log(LogQuery{}) != nil {
		t.Fatal("nil recorder")
	}
}

func TestFallbackHits(t *testing.T) {
	r := New(10)
	r.Record(Entry{Domain: Fallback, Host: "old.example.com:80", Status: 200})
	r.Record(Entry{Domain: Fallback, Host: "old.example.com", Status: 404})
	r.RecordFallback("Legacy.Example.com.", FallbackKindTLS)
	r.Record(Entry{Domain: "app.io", Host: "app.io", Status: 200})
	hits := r.FallbackHits()
	if len(hits) != 2 {
		t.Fatalf("hits: %+v", hits)
	}
	by := map[string]FallbackHit{}
	for _, h := range hits {
		by[h.Host] = h
	}
	if by["old.example.com"].HTTP != 2 || by["legacy.example.com"].TLS != 1 || by["old.example.com"].FirstSeen.IsZero() {
		t.Fatalf("counts: %+v", by)
	}
	snap := r.FallbackSnapshot()
	if snap == nil || r.FallbackSnapshot() != nil {
		t.Fatal("snapshot must be returned once per change")
	}
	r2 := New(10)
	if err := r2.RestoreFallback(snap); err != nil || len(r2.FallbackHits()) != 2 {
		t.Fatalf("restore: %v %+v", err, r2.FallbackHits())
	}
	r2.ResetFallbackHits()
	if len(r2.FallbackHits()) != 0 || r2.FallbackSnapshot() == nil {
		t.Fatal("reset")
	}
}
