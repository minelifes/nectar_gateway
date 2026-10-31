// Package replica runs nectar-gateway on several edge nodes. One gateway is the primary: the controller
// (nectar-apps) talks to it, and it issues and renews certificates. Replicas (PRIMARY_URL set) copy the
// primary's routes, certificates, IP blocks and settings every few seconds and answer ACME HTTP-01
// challenges by asking the primary, so a challenge request may land on any edge node.
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"nectar_gateway/internal/settings"
	"nectar_gateway/internal/store"
)

// Headers a replica sends with each pull.
const (
	HeaderNode    = "X-Replica-Node"
	HeaderVersion = "X-Replica-Version"
	HeaderError   = "X-Replica-Error" // the replica's last sync error ("" = fine)
)

// Follower keeps a replica in step with the primary.
type Follower struct {
	Primary  string // admin URL of the primary, e.g. http://nectar-gateway-admin.nectar-system.svc:8081
	Token    string // GATEWAY_API_TOKEN (the same on every gateway)
	Node     string // this node's name (shown in the panel)
	Version  string
	Store    *store.Store
	Settings *settings.Settings
	HTTP     *http.Client
	Interval time.Duration // default 5 s

	mu       sync.Mutex
	etag     string
	blocked  []store.BlockedIP // the primary's blocks in the last snapshot
	lastSync time.Time
	lastErr  string
	chal     map[string]chalEntry
}

type chalEntry struct {
	resp string
	at   time.Time
}

func (f *Follower) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Status is the replica's sync state (GET /api/replica/status on the replica).
type Status struct {
	Primary  string    `json:"primary"`
	LastSync time.Time `json:"last_sync"`
	Error    string    `json:"error,omitempty"`
	ETag     string    `json:"etag"`
}

// Status returns the sync state.
func (f *Follower) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{Primary: f.Primary, LastSync: f.lastSync, Error: f.lastErr, ETag: f.etag}
}

// Synced reports whether the replica has copied the primary at least once (readiness: a replica
// without routes must not take traffic).
func (f *Follower) Synced() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.lastSync.IsZero()
}

// Run pulls until ctx ends.
func (f *Follower) Run(ctx context.Context) {
	every := f.Interval
	if every <= 0 {
		every = 5 * time.Second
	}
	for {
		err := f.Sync(ctx)
		f.mu.Lock()
		prev := f.lastErr
		if err != nil {
			f.lastErr = err.Error()
		} else {
			f.lastErr = ""
		}
		f.mu.Unlock()
		if err != nil && err.Error() != prev {
			log.Printf("replica: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Sync pulls the snapshot once and applies it when it changed.
func (f *Follower) Sync(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(f.Primary, "/")+"/api/replica/snapshot", nil)
	if err != nil {
		return err
	}
	f.mu.Lock()
	etag := f.etag
	f.mu.Unlock()
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set(HeaderNode, f.Node)
	req.Header.Set(HeaderVersion, f.Version)
	f.mu.Lock()
	lastErr := f.lastErr
	f.mu.Unlock()
	if lastErr != "" {
		req.Header.Set(HeaderError, strings.Map(func(r rune) rune {
			if r < 32 || r > 126 {
				return ' '
			}
			return r
		}, lastErr))
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return fmt.Errorf("primary unreachable: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		f.mu.Lock()
		f.lastSync = time.Now()
		f.mu.Unlock()
		return nil
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("primary answered %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 256<<20))
	dec.UseNumber()
	var snap store.Snapshot
	if err := dec.Decode(&snap); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	f.mu.Lock()
	prevBlocked := f.blocked
	f.mu.Unlock()
	if err := f.Store.ImportSnapshot(snap, prevBlocked); err != nil {
		return err
	}
	if len(snap.Settings) > 0 && f.Settings != nil {
		var v settings.Values
		if err := json.Unmarshal(snap.Settings, &v); err == nil {
			// replicas never talk to the DNS provider or ACME: the primary does
			cur := f.Settings.Get()
			v.DNSProvider, v.DNSAPIToken = cur.DNSProvider, cur.DNSAPIToken
			if v != cur {
				if err := f.Settings.Set(v); err != nil {
					log.Printf("replica: settings: %v", err)
				}
			}
		}
	}
	f.mu.Lock()
	f.etag, f.blocked, f.lastSync = resp.Header.Get("ETag"), snap.Blocked, time.Now()
	f.mu.Unlock()
	return nil
}

// Challenge answers an ACME HTTP-01 token by asking the primary (cached briefly).
func (f *Follower) Challenge(token string) (string, bool) {
	if token == "" || strings.ContainsAny(token, "/?#") {
		return "", false
	}
	f.mu.Lock()
	if e, ok := f.chal[token]; ok && time.Since(e.at) < time.Minute {
		f.mu.Unlock()
		return e.resp, true
	}
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(f.Primary, "/")+"/api/replica/challenge/"+url.PathEscape(token), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	resp, err := f.client().Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", false
	}
	f.mu.Lock()
	if f.chal == nil {
		f.chal = map[string]chalEntry{}
	}
	for k, e := range f.chal {
		if time.Since(e.at) > time.Minute {
			delete(f.chal, k)
		}
	}
	f.chal[token] = chalEntry{string(b), time.Now()}
	f.mu.Unlock()
	return string(b), true
}

// Registry is the primary's list of replicas (from their pulls).
type Registry struct {
	mu    sync.Mutex
	nodes map[string]*Info
}

// Info is one replica as the primary saw it.
type Info struct {
	Node     string    `json:"node"`
	Address  string    `json:"address"`
	Version  string    `json:"version"`
	LastSeen time.Time `json:"last_seen"`
	Error    string    `json:"error,omitempty"` // the replica's last sync error
}

// Seen records a pull.
func (r *Registry) Seen(node, addr, version, errMsg string) {
	if node == "" {
		node = addr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nodes == nil {
		r.nodes = map[string]*Info{}
	}
	r.nodes[node] = &Info{Node: node, Address: addr, Version: version, LastSeen: time.Now().UTC(), Error: errMsg}
}

// List returns replicas seen in the last hour, by node name.
func (r *Registry) List() []Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Info{}
	for k, i := range r.nodes {
		if time.Since(i.LastSeen) > time.Hour {
			delete(r.nodes, k)
			continue
		}
		out = append(out, *i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Node < out[b].Node })
	return out
}

// ErrReplica refuses changes on a replica.
var ErrReplica = errors.New("this gateway is an edge replica: change routes and settings on the primary (nectar-apps does)")
