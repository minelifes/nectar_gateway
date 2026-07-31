package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nectar_gateway/internal/store"
)

type cachedCert struct {
	cert     *tls.Certificate
	certPath string
	loadedAt time.Time
	modTime  time.Time
}

type Handler struct {
	store       *store.Store
	rp          *httputil.ReverseProxy
	acmeWebroot string // dir served at /.well-known/acme-challenge/ over HTTP
	certMu      sync.Mutex
	certs       map[string]*cachedCert // domain -> cert
}

func New(s *store.Store, acmeWebroot string) *Handler {
	h := &Handler{store: s, acmeWebroot: acmeWebroot, certs: map[string]*cachedCert{}}
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   1024, // default is 2 — far too low under load
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// backends are addressed by IP and often use self-signed certs
		// (equivalent of nginx's default proxy_ssl_verify off)
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		WriteBufferSize:       64 << 10, // fewer syscalls on large bodies
		ReadBufferSize:        64 << 10,
	}
	h.rp = &httputil.ReverseProxy{
		Transport: transport,
		// reuse copy buffers instead of allocating 32KB per request
		BufferPool: &bufferPool{pool: sync.Pool{
			New: func() any { b := make([]byte, 64<<10); return &b },
		}},
		Rewrite: func(pr *httputil.ProxyRequest) {
			route := pr.In.Context().Value(routeKey{}).(store.Route)
			scheme := "http"
			if route.TargetHTTPS {
				scheme = "https"
			}
			target := &url.URL{
				Scheme: scheme,
				Host:   net.JoinHostPort(route.TargetIP, fmt.Sprint(route.TargetPort)),
			}
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host        // preserve original Host header
			pr.SetXForwarded()              // X-Forwarded-For / -Host / -Proto
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return // client went away; nothing to write
			}
			http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
		},
	}
	return h
}

type bufferPool struct{ pool sync.Pool }

func (b *bufferPool) Get() []byte  { return *b.pool.Get().(*[]byte) }
func (b *bufferPool) Put(bb []byte) { b.pool.Put(&bb) }

type routeKey struct{}

func withRoute(ctx context.Context, r store.Route) context.Context {
	return context.WithValue(ctx, routeKey{}, r)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Let's Encrypt HTTP-01 challenges: always served over HTTP for any
	// domain, before routing and before any HTTPS redirect.
	if h.acmeWebroot != "" && r.TLS == nil &&
		strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		h.serveStatic(w, r, h.acmeWebroot)
		return
	}

	host := r.Host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	route, ok := h.store.Lookup(strings.ToLower(host))
	if !ok {
		http.Error(w, "410 Gone: no route for domain "+host, http.StatusGone)
		return
	}
	if r.TLS == nil && route.ForceSSL && route.HasSSL() {
		u := *r.URL
		u.Scheme = "https"
		u.Host = host
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
		return
	}
	if route.Mode == store.ModeStatic {
		h.serveStatic(w, r, route.StaticDir)
		return
	}
	ctx := withRoute(r.Context(), route)
	h.rp.ServeHTTP(w, r.WithContext(ctx))
}

// GetCertificate implements tls.Config.GetCertificate: it picks the
// certificate for the requested SNI domain. Certs are cached and reloaded
// when the file on disk changes (checked at most every 30s).
func (h *Handler) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(hello.ServerName)
	route, ok := h.store.Lookup(domain)
	if !ok || !route.HasSSL() {
		return nil, fmt.Errorf("no certificate for %q", domain)
	}

	h.certMu.Lock()
	defer h.certMu.Unlock()
	c := h.certs[domain]
	if c != nil && c.certPath == route.CertFile && time.Since(c.loadedAt) < 30*time.Second {
		return c.cert, nil
	}
	if c != nil && c.certPath == route.CertFile {
		if info, err := os.Stat(route.CertFile); err == nil && info.ModTime().Equal(c.modTime) {
			c.loadedAt = time.Now()
			return c.cert, nil
		}
	}
	cert, err := tls.LoadX509KeyPair(route.CertFile, route.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading certificate for %q: %w", domain, err)
	}
	modTime := time.Time{}
	if info, err := os.Stat(route.CertFile); err == nil {
		modTime = info.ModTime()
	}
	h.certs[domain] = &cachedCert{cert: &cert, certPath: route.CertFile, loadedAt: time.Now(), modTime: modTime}
	return &cert, nil
}

// serveStatic serves files from root like nginx: index.html for directories,
// no directory listing, 404 when the file doesn't exist.
func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request, root string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clean := path.Clean("/" + r.URL.Path) // prevents ../ traversal
	full := filepath.Join(root, filepath.FromSlash(clean))
	info, err := os.Stat(full)
	if err == nil && info.IsDir() {
		full = filepath.Join(full, "index.html")
		info, err = os.Stat(full)
	}
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, full)
}
