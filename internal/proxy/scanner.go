package proxy

import (
	"strings"
	"sync"
	"time"
)

// BlockTTL is how long a detected scanner stays blocked.
const BlockTTL = 24 * time.Hour

// Paths that only vulnerability scanners request. A single hit blocks the IP.
var scannerPaths = []string{
	"/.env",
	"/.git",
	"/.aws",
	"/.ssh",
	"/.vscode",
	"/.DS_Store",
	"/etc/passwd",
	"/wp-login.php",
	"/wp-admin",
	"/xmlrpc.php",
	"/phpmyadmin",
	"/vendor/phpunit",
	"/cgi-bin/",
	"/HNAP1",
	"/GponForm",
	"/boaform",
	"/shell.php",
	"/backup.sql",
	"/dump.sql",
	"/db.sql",
	"/manager/html", // tomcat
	"/owa/auth",     // exchange
	"/autodiscover/autodiscover",
}

func isScannerPath(p string) bool {
	p = strings.ToLower(p)
	for _, s := range scannerPaths {
		if strings.HasPrefix(p, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// hitTracker counts hits per key within a sliding window. Used for
// unknown-domain scanning detection and per-domain rate limiting.
type hitTracker struct {
	mu     sync.Mutex
	hits   map[string]*hitWindow
	window time.Duration
}

type hitWindow struct {
	count int
	start time.Time
}

func newHitTracker(window time.Duration) *hitTracker {
	return &hitTracker{hits: map[string]*hitWindow{}, window: window}
}

// note registers a hit for key and reports whether it crossed limit
// within the current window.
func (t *hitTracker) note(key string, limit int) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	// opportunistic cleanup so the map cannot grow unbounded
	if len(t.hits) > 10000 {
		for k, h := range t.hits {
			if now.Sub(h.start) > t.window {
				delete(t.hits, k)
			}
		}
	}

	h := t.hits[key]
	if h == nil || now.Sub(h.start) > t.window {
		t.hits[key] = &hitWindow{count: 1, start: now}
		return limit <= 1
	}
	h.count++
	if h.count >= limit {
		delete(t.hits, key)
		return true
	}
	return false
}

// allow is a fixed-window rate limiter: up to limit hits per window and key pass, the rest are
// rejected until the window ends.
func (t *hitTracker) allow(key string, limit int) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.hits) > 10000 {
		for k, h := range t.hits {
			if now.Sub(h.start) > t.window {
				delete(t.hits, k)
			}
		}
	}
	h := t.hits[key]
	if h == nil || now.Sub(h.start) > t.window {
		t.hits[key] = &hitWindow{count: 1, start: now}
		return limit >= 1
	}
	h.count++
	return h.count <= limit
}
