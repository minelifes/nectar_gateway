package proxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"nectar_gateway/internal/store"
)

func wakeRoute(timeout int) store.Route {
	return store.Route{TargetIP: "10.43.0.9", TargetPort: 8080,
		Web: &store.Web{Wake: &store.Wake{URL: "http://panel/internal/wake/7?sig=x", Timeout: timeout}}}
}

// A sleeping backend: the wake URL is called once, the request is held until the backend accepts
// connections, then later requests pass straight through (cached).
func TestWakeHoldsUntilTheBackendIsUp(t *testing.T) {
	k := newWaker()
	var dials, calls atomic.Int32
	k.dial = func(context.Context, string) error {
		if dials.Add(1) < 4 {
			return errors.New("connection refused")
		}
		return nil
	}
	called := make(chan string, 4)
	k.call = func(_ context.Context, url string) error { calls.Add(1); called <- url; return nil }

	start := time.Now()
	if !k.ready(context.Background(), wakeRoute(10)) {
		t.Fatal("not ready")
	}
	if time.Since(start) < 2*probeEvery {
		t.Fatal("did not wait for the backend")
	}
	if got := <-called; got != "http://panel/internal/wake/7?sig=x" || calls.Load() != 1 {
		t.Fatalf("wake calls: %d %s", calls.Load(), got)
	}
	n := dials.Load()
	if !k.ready(context.Background(), wakeRoute(10)) || dials.Load() != n {
		t.Fatal("the up state was not cached")
	}
}

func TestWakeGivesUp(t *testing.T) {
	k := newWaker()
	k.dial = func(context.Context, string) error { return errors.New("refused") }
	k.call = func(context.Context, string) error { return nil }
	r := wakeRoute(1)
	start := time.Now()
	if k.ready(context.Background(), r) {
		t.Fatal("ready although the backend never came up")
	}
	if d := time.Since(start); d < time.Second || d > 3*time.Second {
		t.Fatalf("waited %v", d)
	}
	// the client leaving stops the wait at once
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if k.ready(ctx, wakeRoute(60)) {
		t.Fatal("ready after the client left")
	}
}

func TestWakeOptionValidation(t *testing.T) {
	w := &store.Web{Wake: &store.Wake{URL: "http://panel/x"}}
	if err := w.Normalize(); err != nil || w.Wake.Timeout != 60 {
		t.Fatalf("default timeout: %v %+v", err, w.Wake)
	}
	for _, bad := range []*store.Wake{{URL: "ftp://x"}, {URL: "http://x", Timeout: 1000}, {URL: ""}} {
		if (&store.Web{Wake: bad}).Normalize() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if (&store.Web{Wake: &store.Wake{URL: "http://x"}}).IsZero() {
		t.Fatal("wake alone counts as an option")
	}
}
