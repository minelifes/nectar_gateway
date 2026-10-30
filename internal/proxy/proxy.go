package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
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

	"nectar_gateway/internal/metrics"
	"nectar_gateway/internal/store"
)

type cachedCert struct {
	cert     *tls.Certificate
	certPath string // file-based certs: path, PEM certs: "pem:<route id>:<updated_at>"
	loadedAt time.Time
	modTime  time.Time
}

type Handler struct {
	store       *store.Store
	base        *http.Transport                     // template for per-route transports
	proxiesMu   sync.Mutex                          // guards proxies
	proxies     map[proxyKey]*httputil.ReverseProxy // one reverse proxy per (protocol, timeout)
	auth        *authCache                          // verified basic-auth credentials (bcrypt is slow)
	acmeWebroot string                              // dir served at /.well-known/acme-challenge/ over HTTP
	certMu      sync.Mutex
	certs       map[string]*cachedCert // domain -> cert
	unknown     *hitTracker            // scanner detection on unknown domains
	rate        *hitTracker            // per-domain per-IP rate limiting
	abuse       *hitTracker            // rejected requests per minute (sustained abuse → block)
	// RateLimitBlock is how long a client that keeps exceeding a rate limit is blocked (nil or 0 = never;
	// over the limit it gets 429 either way).
	RateLimitBlock func() time.Duration
	// Challenge answers ACME HTTP-01 tokens from the built-in issuer (nil = webroot only).
	Challenge func(token string) (string, bool)
	// Metrics records per-domain statistics and the access log (nil = off).
	Metrics *metrics.Recorder
	// FallbackTarget returns "host:port" of an upstream for hosts without a route (e.g. the previous
	// ingress controller during a migration); nil or "" = answer 410.
	FallbackTarget func() string
}

// proxyKey selects a transport: backend protocol and response-header timeout.
type proxyKey struct {
	proto   string
	timeout time.Duration
}

// DefaultTimeout is the response-header timeout for routes without timeout_seconds (like nginx's 60s).
const DefaultTimeout = 60 * time.Second

// abuseFactor: a client blocked for RateLimitBlock had more than abuseFactor × limit requests rejected
// within one minute (e.g. limit 10 req/s → more than 100 rejected in a minute).
const abuseFactor = 10

func (h *Handler) rateLimitBlock() time.Duration {
	if h.RateLimitBlock == nil {
		return 0
	}
	return h.RateLimitBlock()
}

func New(s *store.Store, acmeWebroot string) *Handler {
	h := &Handler{
		store: s, acmeWebroot: acmeWebroot, certs: map[string]*cachedCert{},
		unknown: newHitTracker(10 * time.Minute),
		rate:    newHitTracker(time.Second),
		abuse:   newHitTracker(time.Minute),
		proxies: map[proxyKey]*httputil.ReverseProxy{},
		auth:    newAuthCache(),
	}
	h.base = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 1024, // default is 2 — far too low under load
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// backends are addressed by IP and often use self-signed certs
		// (equivalent of nginx's default proxy_ssl_verify off)
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		WriteBufferSize:       64 << 10, // fewer syscalls on large bodies
		ReadBufferSize:        64 << 10,
	}
	return h
}

// proxyFor returns the reverse proxy for a route's protocol and timeout (created once, then cached).
func (h *Handler) proxyFor(route store.Route) *httputil.ReverseProxy {
	key := proxyKey{proto: route.BackendProtocol, timeout: DefaultTimeout}
	if key.proto == "" {
		key.proto = store.ProtoHTTP1
	}
	if route.TimeoutSeconds > 0 {
		key.timeout = time.Duration(route.TimeoutSeconds) * time.Second
	}
	h.proxiesMu.Lock()
	defer h.proxiesMu.Unlock()
	if rp, ok := h.proxies[key]; ok {
		return rp
	}
	t := h.base.Clone()
	t.ResponseHeaderTimeout = key.timeout
	if key.proto == store.ProtoH2C {
		// prior-knowledge HTTP/2 over plain TCP (gRPC backends)
		t.Protocols = new(http.Protocols)
		t.Protocols.SetUnencryptedHTTP2(true)
	}
	rp := h.newReverseProxy(t)
	h.proxies[key] = rp
	return rp
}

func (h *Handler) newReverseProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
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
			pr.Out.Host = pr.In.Host // preserve original Host header
			pr.SetXForwarded()       // X-Forwarded-For / -Host / -Proto
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return // client went away; nothing to write
			}
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				errorPage(w, r, http.StatusRequestEntityTooLarge, "Request too large",
					fmt.Sprintf("This app accepts uploads up to %d MB.", tooBig.Limit>>20))
				return
			}
			log.Printf("upstream %s%s: %v", r.Host, r.URL.Path, err)
			if isTimeout(err) {
				errorPage(w, r, http.StatusGatewayTimeout, "This app is taking too long",
					"The app did not answer in time. Try again in a moment.")
				return
			}
			errorPage(w, r, http.StatusBadGateway, "This app is not responding",
				"The app behind this address is starting, restarting or down. Try again in a moment.")
		},
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || strings.Contains(err.Error(), "timeout awaiting response headers")
}

type bufferPool struct{ pool sync.Pool }

func (b *bufferPool) Get() []byte   { return *b.pool.Get().(*[]byte) }
func (b *bufferPool) Put(bb []byte) { b.pool.Put(&bb) }

func clientIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

// CanaryPath is answered with 200 by the gateway itself (used by update health gates).
const CanaryPath = "/__nectar/canary"

type routeKey struct{}

func withRoute(ctx context.Context, r store.Route) context.Context {
	return context.WithValue(ctx, routeKey{}, r)
}

// recorder captures status and size for metrics while keeping Flush/Hijack (via Unwrap) working.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (rw *recorder) WriteHeader(code int) {
	if rw.status == 0 {
		rw.status = code
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *recorder) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}

func (rw *recorder) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

// countingBody counts request body bytes read by the backend.
type countingBody struct {
	io.ReadCloser
	n int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}

// skipMetrics marks requests that are not counted (ACME challenges, canary).
const skipMetrics = "\x00skip"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Metrics == nil {
		h.serve(w, r, new(string))
		return
	}
	start := time.Now()
	rw := &recorder{ResponseWriter: w}
	var body *countingBody
	if r.Body != nil && r.Body != http.NoBody {
		body = &countingBody{ReadCloser: r.Body}
		r.Body = body
	}
	domain := ""
	h.serve(rw, r, &domain)
	if domain == skipMetrics {
		return
	}
	status := rw.status
	if status == 0 {
		status = http.StatusOK
	}
	var in int64
	if body != nil {
		in = body.n
	}
	host := r.Host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	h.Metrics.Record(metrics.Entry{
		Time: start.UTC(), IP: clientIP(r), Method: r.Method, Host: strings.ToLower(host), Path: r.URL.Path,
		Status: status, BytesOut: rw.bytes, BytesIn: in, MS: time.Since(start).Milliseconds(),
		UserAgent: r.UserAgent(), Domain: domain,
	})
}

// acmeFileExists reports whether urlPath (under /.well-known/acme-challenge/)
// is a regular file in the certbot webroot.
func acmeFileExists(root, urlPath string) bool {
	clean := path.Clean("/" + urlPath)
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean)))
	return err == nil && info.Mode().IsRegular()
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, matched *string) {
	// Let's Encrypt HTTP-01 challenges: always served over HTTP for any
	// domain, before routing and before any HTTPS redirect.
	if r.TLS == nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		*matched = skipMetrics
		if h.Challenge != nil {
			if resp, ok := h.Challenge(strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")); ok {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(resp))
				return
			}
		}
		if h.acmeWebroot != "" && acmeFileExists(h.acmeWebroot, r.URL.Path) {
			h.serveStatic(w, r, h.acmeWebroot)
			return
		}
		// Not a token this gateway issued (built-in issuer / certbot webroot):
		// it may belong to an ACME client behind the proxy, so route it to the
		// domain's backend like any other request.
		*matched = ""
	}

	// Canary for health gates during updates: answered by the gateway itself, for any host.
	if r.URL.Path == CanaryPath {
		*matched = skipMetrics
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte("ok\n"))
		return
	}

	ip := clientIP(r)
	if h.store.IsBlocked(ip) {
		errorPage(w, r, http.StatusForbidden, "Access blocked", "Your IP address is temporarily blocked.")
		return
	}
	if isScannerPath(r.URL.Path) {
		if err := h.store.Block(ip, "scanner path: "+r.URL.Path, BlockTTL); err == nil {
			log.Printf("blocked %s for 24h: scanner path %s", ip, r.URL.Path)
		}
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	host := r.Host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	host = strings.ToLower(host)
	route, ok := h.store.Lookup(host, r.URL.Path)
	if !ok {
		if h.store.KnownHost(host) { // host exists, but no path prefix matches
			*matched = host
			errorPage(w, r, http.StatusNotFound, "Not found", "Nothing is served at this path.")
			return
		}
		if h.FallbackTarget != nil {
			if target := h.FallbackTarget(); target != "" {
				*matched = metrics.Fallback
				fb := store.Route{Domain: host, TargetIP: target, BackendProtocol: store.ProtoHTTP1}
				if hp, port, err := net.SplitHostPort(target); err == nil {
					fb.TargetIP = hp
					fmt.Sscan(port, &fb.TargetPort)
				}
				h.proxyFor(fb).ServeHTTP(w, r.WithContext(withRoute(r.Context(), fb)))
				return
			}
		}
		if h.unknown.note(ip, 30) {
			if err := h.store.Block(ip, "domain scanning: repeated requests for unknown domains", BlockTTL); err == nil {
				log.Printf("blocked %s for 24h: unknown-domain scanning", ip)
			}
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		errorPage(w, r, http.StatusGone, "No app here", "No app is configured for "+host+".")
		return
	}
	*matched = route.Domain
	if route.RateLimit > 0 && !h.rate.allow(ip+"|"+route.Domain, route.RateLimit) {
		// over the limit: 429, the client may retry in a second. Only sustained abuse (more than ten
		// times the limit rejected within a minute) blocks the IP, for RateLimitBlock.
		if d := h.rateLimitBlock(); d > 0 && h.abuse.note(ip+"|"+route.Domain, abuseFactor*route.RateLimit) {
			if err := h.store.Block(ip, fmt.Sprintf("rate limit: kept exceeding %d req/s on %s", route.RateLimit, route.Domain), d); err == nil {
				log.Printf("blocked %s for %s: kept exceeding the rate limit on %s", ip, d, route.Domain)
			}
		}
		w.Header().Set("Retry-After", "1")
		errorPage(w, r, http.StatusTooManyRequests, "Too many requests", "Slow down a little and try again in a moment.")
		return
	}
	if r.TLS == nil && route.ForceSSL {
		if hasCert := h.store.HasTLS(host); hasCert { // own certificate or a covering wildcard
			u := *r.URL
			u.Scheme = "https"
			u.Host = host
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
			return
		}
	}
	if route.Mode == store.ModeRedirect {
		http.Redirect(w, r, redirectTarget(route, r), route.RedirectCode)
		return
	}
	if route.BasicAuth != "" {
		user, pass, ok := r.BasicAuth()
		if !ok || !h.auth.check(route, user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+strings.ReplaceAll(route.Domain, `"`, "")+`", charset="UTF-8"`)
			errorPage(w, r, http.StatusUnauthorized, "Sign in required", "This site is protected. Enter the user name and password you were given.")
			return
		}
	}
	if route.MaxBodyMB > 0 {
		limit := int64(route.MaxBodyMB) << 20
		if r.ContentLength > limit {
			errorPage(w, r, http.StatusRequestEntityTooLarge, "Request too large",
				fmt.Sprintf("This app accepts uploads up to %d MB.", route.MaxBodyMB))
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
	}
	if route.Maintenance {
		w.Header().Set("Retry-After", "120")
		errorPage(w, r, http.StatusServiceUnavailable, "Down for maintenance", "This app is being updated. Please check back in a few minutes.")
		return
	}
	if route.Mode == store.ModeStatic {
		h.serveStatic(w, r, route.StaticDir)
		return
	}
	ctx := withRoute(r.Context(), route)
	h.proxyFor(route).ServeHTTP(w, r.WithContext(ctx))
}

// redirectTarget appends the request path and query to the route's redirect URL, unless the
// redirect URL has its own path (then it is used as-is: "send everything to this page").
func redirectTarget(route store.Route, r *http.Request) string {
	u, err := url.Parse(route.RedirectURL)
	if err != nil {
		return route.RedirectURL
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = r.URL.Path
		if u.RawQuery == "" {
			u.RawQuery = r.URL.RawQuery
		}
	}
	return u.String()
}

// GetCertificate implements tls.Config.GetCertificate: it picks the
// certificate for the requested SNI domain. Certs are cached and reloaded
// when the file on disk changes (checked at most every 30s).
func (h *Handler) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(hello.ServerName)
	route, ok := h.store.CertRoute(domain)
	if !ok {
		// no certificate on the host's routes: a standalone (e.g. wildcard) certificate that covers it
		sc, ok := h.store.CoveringCertificate(domain)
		if !ok {
			return nil, fmt.Errorf("no certificate for %q", domain)
		}
		return h.standaloneCert(sc)
	}

	h.certMu.Lock()
	defer h.certMu.Unlock()
	c := h.certs[domain]
	if route.CertPEM != "" { // stored in the database (uploaded or issued by ACME)
		key := fmt.Sprintf("pem:%d:%d", route.ID, route.UpdatedAt)
		if c != nil && c.certPath == key {
			return c.cert, nil
		}
		cert, err := tls.X509KeyPair([]byte(route.CertPEM), []byte(route.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("stored certificate for %q: %w", domain, err)
		}
		h.certs[domain] = &cachedCert{cert: &cert, certPath: key, loadedAt: time.Now()}
		return &cert, nil
	}
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

// standaloneCert parses a standalone certificate once per version (cached by id and update time).
func (h *Handler) standaloneCert(sc store.Certificate) (*tls.Certificate, error) {
	key := fmt.Sprintf("cert:%d:%d", sc.ID, sc.UpdatedAt)
	h.certMu.Lock()
	defer h.certMu.Unlock()
	if c := h.certs[key]; c != nil {
		return c.cert, nil
	}
	cert, err := tls.X509KeyPair([]byte(sc.CertPEM), []byte(sc.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate %s: %w", sc.Domain, err)
	}
	for k := range h.certs { // drop older versions of this certificate
		if strings.HasPrefix(k, fmt.Sprintf("cert:%d:", sc.ID)) {
			delete(h.certs, k)
		}
	}
	h.certs[key] = &cachedCert{cert: &cert, certPath: key, loadedAt: time.Now()}
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
