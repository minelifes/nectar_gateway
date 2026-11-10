package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"nectar_gateway/internal/store"
)

// Scale to zero: a route with web.wake may point at a backend that has no running instance. Before
// proxying, the gateway checks that the backend accepts connections (cached for a few seconds). If it
// does not, it calls the wake URL (once per wakeEvery) and holds the request until the backend accepts
// connections or the wake timeout passes; then it answers 503 "starting" with Retry-After.

const (
	upFor      = 5 * time.Second        // a backend that accepted a connection is trusted this long
	wakeEvery  = 15 * time.Second       // the wake URL is called at most this often per backend
	probeEvery = 400 * time.Millisecond // how often a held request checks the backend
	dialProbe  = 300 * time.Millisecond
)

type waker struct {
	mu     sync.Mutex
	up     map[string]time.Time // backend → trusted until
	called map[string]time.Time // backend → last wake call
	// dial and call are replaceable in tests.
	dial func(ctx context.Context, addr string) error
	call func(ctx context.Context, url string) error
}

func newWaker() *waker {
	return &waker{up: map[string]time.Time{}, called: map[string]time.Time{},
		dial: func(ctx context.Context, addr string) error {
			ctx, cancel := context.WithTimeout(ctx, dialProbe)
			defer cancel()
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err == nil {
				c.Close()
			}
			return err
		},
		call: func(ctx context.Context, url string) error {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
			if err != nil {
				return err
			}
			req.Header.Set("User-Agent", "nectar-gateway/wake")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 {
				return fmt.Errorf("wake answered %s", resp.Status)
			}
			return nil
		}}
}

// ready waits until the route's backend accepts connections, waking it when needed. False when it did
// not come up within the route's wake timeout (or the client left).
func (k *waker) ready(ctx context.Context, route store.Route) bool {
	addr := net.JoinHostPort(route.TargetIP, strconv.Itoa(route.TargetPort))
	now := time.Now()
	k.mu.Lock()
	until := k.up[addr]
	k.mu.Unlock()
	if now.Before(until) {
		return true
	}
	if k.dial(ctx, addr) == nil {
		k.markUp(addr)
		return true
	}
	k.wake(route.Web.Wake.URL, addr)
	deadline := now.Add(time.Duration(route.Web.Wake.Timeout) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(probeEvery):
		}
		k.mu.Lock()
		until := k.up[addr] // another request saw it come up
		k.mu.Unlock()
		if time.Now().Before(until) || k.dial(ctx, addr) == nil {
			k.markUp(addr)
			return true
		}
		k.wake(route.Web.Wake.URL, addr) // again after wakeEvery (a lost call, a panel restart)
	}
	return false
}

func (k *waker) markUp(addr string) {
	k.mu.Lock()
	k.up[addr] = time.Now().Add(upFor)
	k.mu.Unlock()
}

// wake calls the wake URL in the background, at most once per wakeEvery per backend.
func (k *waker) wake(url, addr string) {
	k.mu.Lock()
	if time.Since(k.called[addr]) < wakeEvery {
		k.mu.Unlock()
		return
	}
	k.called[addr] = time.Now()
	k.mu.Unlock()
	go func() {
		if err := k.call(context.Background(), url); err != nil {
			log.Printf("wake %s: %v", addr, err)
		}
	}()
}
