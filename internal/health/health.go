// Package health periodically probes backends and sends push
// notifications (ntfy-compatible webhook) on down/recovery transitions.
package health

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nectar_gateway/internal/store"
)

const downAfterFails = 2 // consecutive failures before "down" + notification

type Status struct {
	Up        *bool     `json:"up"` // nil until first check completes
	LastError string    `json:"last_error"`
	LastCheck time.Time `json:"last_check"`
	fails     int
	notified  bool // "down" notification already sent
}

type Checker struct {
	store     *store.Store
	notifyURL string
	client    *http.Client

	mu       sync.Mutex
	states   map[int64]*Status
	inflight map[int64]bool
	lastRun  map[int64]time.Time
}

func New(st *store.Store, notifyURL string) *Checker {
	return &Checker{
		store:     st,
		notifyURL: notifyURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    16,
			},
		},
		states:   map[int64]*Status{},
		inflight: map[int64]bool{},
		lastRun:  map[int64]time.Time{},
	}
}

// Run schedules checks until ctx is cancelled.
func (c *Checker) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			routes, err := c.store.List()
			if err != nil {
				continue
			}
			now := time.Now()
			for _, r := range routes {
				if !r.HCEnabled || r.Mode != store.ModeProxy {
					continue
				}
				c.mu.Lock()
				due := now.Sub(c.lastRun[r.ID]) >= time.Duration(r.HCInterval)*time.Second && !c.inflight[r.ID]
				if due {
					c.lastRun[r.ID] = now
					c.inflight[r.ID] = true
				}
				c.mu.Unlock()
				if due {
					go c.check(r)
				}
			}
		}
	}
}

// Snapshot returns the current status per route id.
func (c *Checker) Snapshot() map[string]Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Status, len(c.states))
	for id, s := range c.states {
		out[strconv.FormatInt(id, 10)] = *s
	}
	return out
}

func (c *Checker) check(r store.Route) {
	defer func() {
		c.mu.Lock()
		delete(c.inflight, r.ID)
		c.mu.Unlock()
	}()

	err := c.probe(r)

	c.mu.Lock()
	s := c.states[r.ID]
	if s == nil {
		s = &Status{}
		c.states[r.ID] = s
	}
	s.LastCheck = time.Now()
	var notifyMsg, notifyTitle string
	if err != nil {
		s.fails++
		s.LastError = err.Error()
		if s.fails >= downAfterFails && !s.notified {
			down := false
			s.Up = &down
			s.notified = true
			notifyTitle = "🔴 " + r.Domain + " is DOWN"
			notifyMsg = fmt.Sprintf("Health check failed for %s (backend %s:%d): %v", r.Domain, r.TargetIP, r.TargetPort, err)
		}
	} else {
		wasDown := s.notified
		up := true
		s.Up = &up
		s.fails = 0
		s.LastError = ""
		s.notified = false
		if wasDown {
			notifyTitle = "🟢 " + r.Domain + " recovered"
			notifyMsg = fmt.Sprintf("%s (backend %s:%d) is healthy again", r.Domain, r.TargetIP, r.TargetPort)
		}
	}
	c.mu.Unlock()

	if notifyMsg != "" {
		log.Printf("health: %s", notifyMsg)
		c.notify(notifyTitle, notifyMsg)
	}
}

// probe performs one health check according to the route's config.
func (c *Checker) probe(r store.Route) error {
	scheme := "http"
	if r.TargetHTTPS {
		scheme = "https"
	}
	u := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(r.TargetIP, fmt.Sprint(r.TargetPort)), r.HCPath)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Host = r.Domain // backends often route/validate by Host header
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch r.HCType {
	case "contains":
		if resp.StatusCode >= 400 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), r.HCExpect) {
			return fmt.Errorf("body does not contain %q", r.HCExpect)
		}
	case "json":
		if resp.StatusCode >= 400 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		field, want, ok := strings.Cut(r.HCExpect, "=")
		if !ok {
			return fmt.Errorf("invalid json expectation %q (use field.path=value)", r.HCExpect)
		}
		var data any
		if err := json.Unmarshal(body, &data); err != nil {
			return fmt.Errorf("invalid JSON response: %v", err)
		}
		got, err := jsonPath(data, strings.TrimSpace(field))
		if err != nil {
			return err
		}
		if fmt.Sprint(got) != strings.TrimSpace(want) {
			return fmt.Errorf("%s = %q, expected %q", field, fmt.Sprint(got), want)
		}
	default: // "status"
		if want := strings.TrimSpace(r.HCExpect); want != "" {
			code, err := strconv.Atoi(want)
			if err != nil {
				return fmt.Errorf("invalid expected status %q", want)
			}
			if resp.StatusCode != code {
				return fmt.Errorf("status %d, expected %d", resp.StatusCode, code)
			}
		} else if resp.StatusCode >= 400 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
	}
	return nil
}

// jsonPath walks dot-separated keys (arrays via numeric index): "checks.0.status"
func jsonPath(data any, path string) (any, error) {
	cur := data
	for _, part := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			var ok bool
			cur, ok = v[part]
			if !ok {
				return nil, fmt.Errorf("field %q not found", path)
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil, fmt.Errorf("index %q invalid in %q", part, path)
			}
			cur = v[i]
		default:
			return nil, fmt.Errorf("field %q not found", path)
		}
	}
	return cur, nil
}

// notify POSTs to an ntfy-compatible endpoint (plain text body, Title header).
func (c *Checker) notify(title, msg string) {
	if c.notifyURL == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, c.notifyURL, strings.NewReader(msg))
	if err != nil {
		return
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "high")
	resp, err := c.client.Do(req)
	if err != nil {
		log.Printf("health: notification failed: %v", err)
		return
	}
	resp.Body.Close()
}
