package metrics

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"
)

// FallbackHit counts the requests of one host that were passed to the fallback upstream (the previous
// proxy during a migration). Unlike the per-minute statistics these totals are long-lived and persisted,
// so the panel can tell after days of soaking which hosts still depend on the old proxy.
type FallbackHit struct {
	Host      string    `json:"host"`
	HTTP      int64     `json:"http"`       // plain HTTP requests forwarded to fallback_http
	TLS       int64     `json:"tls"`        // TLS connections passed through to fallback_tls (SNI)
	FirstSeen time.Time `json:"first_seen"` // UTC
	LastSeen  time.Time `json:"last_seen"`  // UTC
}

const maxFallbackHosts = 10000

// FallbackKindHTTP and FallbackKindTLS are the kinds accepted by RecordFallback.
const (
	FallbackKindHTTP = "http"
	FallbackKindTLS  = "tls"
)

// RecordFallback counts one fallback request (kind "http") or passed-through TLS connection (kind "tls").
func (r *Recorder) RecordFallback(host, kind string) {
	if r == nil {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordFallbackLocked(host, kind, now)
}

func (r *Recorder) recordFallbackLocked(host, kind string, now time.Time) {
	now = now.UTC()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		host = "(no sni)"
	}
	if len(host) > 253 {
		host = host[:253]
	}
	if r.fallback == nil {
		r.fallback = map[string]*FallbackHit{}
	}
	h, ok := r.fallback[host]
	if !ok {
		if len(r.fallback) >= maxFallbackHosts {
			r.evictFallbackLocked()
		}
		h = &FallbackHit{Host: host, FirstSeen: now}
		r.fallback[host] = h
	}
	if kind == FallbackKindTLS {
		h.TLS++
	} else {
		h.HTTP++
	}
	h.LastSeen = now
	r.fallbackDirty = true
}

func (r *Recorder) evictFallbackLocked() {
	var oldest string
	var at time.Time
	for k, h := range r.fallback {
		if oldest == "" || h.LastSeen.Before(at) {
			oldest, at = k, h.LastSeen
		}
	}
	delete(r.fallback, oldest)
}

// FallbackHits returns the counters, most recently used hosts first.
func (r *Recorder) FallbackHits() []FallbackHit {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]FallbackHit, 0, len(r.fallback))
	for _, h := range r.fallback {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// ResetFallbackHits clears the counters (e.g. after fixing the routes of the listed hosts).
func (r *Recorder) ResetFallbackHits() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.fallback = map[string]*FallbackHit{}
	r.fallbackDirty = true
	r.mu.Unlock()
}

// FallbackSnapshot returns the counters as JSON when they changed since the last snapshot (nil otherwise).
func (r *Recorder) FallbackSnapshot() []byte {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	dirty := r.fallbackDirty
	r.fallbackDirty = false
	r.mu.Unlock()
	if !dirty {
		return nil
	}
	b, _ := json.Marshal(r.FallbackHits())
	return b
}

// RestoreFallback loads counters saved by FallbackSnapshot (call once at startup).
func (r *Recorder) RestoreFallback(b []byte) error {
	if r == nil || len(b) == 0 {
		return nil
	}
	var hits []FallbackHit
	if err := json.Unmarshal(b, &hits); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fallback == nil {
		r.fallback = map[string]*FallbackHit{}
	}
	for i := range hits {
		h := hits[i]
		if h.Host != "" {
			r.fallback[h.Host] = &h
		}
	}
	return nil
}
