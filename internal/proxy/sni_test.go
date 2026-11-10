package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"nectar_gateway/internal/store"
)

// An HTTPS backend serving several sites (like nginx with vhosts) picks the site by the TLS server name:
// the gateway sends the site's host there (not the backend's IP), and web.backend_host replaces both the
// Host header and the server name.
func TestHTTPSBackendGetsTheSiteName(t *testing.T) {
	ts, st := setup(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "sni="+r.TLS.ServerName+" host="+r.Host)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	st.Create(&store.Route{Domain: "site.example.com", TargetIP: "127.0.0.1", TargetPort: port, TargetHTTPS: true})
	st.Create(&store.Route{Domain: "other.example.com", TargetIP: "127.0.0.1", TargetPort: port, TargetHTTPS: true})
	st.Create(&store.Route{Domain: "alias.example.com", TargetIP: "127.0.0.1", TargetPort: port, TargetHTTPS: true,
		Web: &store.Web{BackendHost: "Real.Example.org"}})
	st.Create(&store.Route{Domain: "plain.example.com", TargetIP: "127.0.0.1", TargetPort: port, TargetHTTPS: true,
		Web: &store.Web{BackendHost: "127.0.0.1:8443"}})

	for host, want := range map[string]string{
		"site.example.com":  "sni=site.example.com host=site.example.com",
		"other.example.com": "sni=other.example.com host=other.example.com", // its own transport, not site's
		"alias.example.com": "sni=real.example.org host=real.example.org",
		"plain.example.com": "sni= host=127.0.0.1:8443", // an IP: no server name
	} {
		if code, body := get(t, ts, host, "/"); code != 200 || body != want {
			t.Errorf("%s: %d %q, want %q", host, code, body, want)
		}
	}
	if code, body := get(t, ts, "site.example.com", "/"); code != 200 || !strings.HasPrefix(body, "sni=site.example.com") {
		t.Fatalf("again (cached transport): %d %q", code, body)
	}
}

func TestBackendHostValidation(t *testing.T) {
	for _, bad := range []string{"http://x", "a b", "-x.com", "x..com"} {
		w := store.Web{BackendHost: bad}
		if err := w.Normalize(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	w := store.Web{BackendHost: " Site.Example.com:8443 "}
	if err := w.Normalize(); err != nil || w.BackendHost != "site.example.com:8443" {
		t.Fatalf("%v %q", err, w.BackendHost)
	}
}
