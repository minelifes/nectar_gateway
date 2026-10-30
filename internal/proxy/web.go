package proxy

import (
	"bufio"
	"compress/gzip"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"nectar_gateway/internal/store"
)

// webWriter applies a route's response options (headers, CORS, HSTS, gzip) when the response starts,
// so they win over the backend's own headers. Flush and Hijack keep working (Unwrap / Hijack).
type webWriter struct {
	http.ResponseWriter
	r       *http.Request
	web     *store.Web
	origin  string // allowed CORS origin of this request ("" = none)
	started bool
	gz      *gzip.Writer
}

var gzipPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(nil, gzip.DefaultCompression); return w }}

// wrapWeb returns the writer to use for a route, and a function to call when the handler is done.
func wrapWeb(w http.ResponseWriter, r *http.Request, web *store.Web, origin string) (http.ResponseWriter, func()) {
	if web == nil {
		return w, func() {}
	}
	ww := &webWriter{ResponseWriter: w, r: r, web: web, origin: origin}
	return ww, ww.finish
}

func (w *webWriter) start(status int) {
	if w.started {
		return
	}
	w.started = true
	h := w.Header()
	for k, v := range w.web.ResponseHeaders {
		if v == "" {
			h.Del(k)
		} else {
			h.Set(k, v)
		}
	}
	if w.web.HSTS > 0 && w.r.TLS != nil {
		v := "max-age=" + strconv.Itoa(w.web.HSTS)
		if w.web.HSTSSubdomains {
			v += "; includeSubDomains"
		}
		if w.web.HSTSPreload {
			v += "; preload"
		}
		h.Set("Strict-Transport-Security", v)
	}
	if c := w.web.CORS; c != nil {
		h.Add("Vary", "Origin")
		if w.origin != "" {
			corsAllowHeaders(h, c, w.origin)
			if len(c.Expose) > 0 {
				h.Set("Access-Control-Expose-Headers", strings.Join(c.Expose, ", "))
			}
		}
	}
	if w.web.Compress && compressible(w.r, h, status) {
		h.Del("Content-Length")
		h.Del("Accept-Ranges")
		h.Set("Content-Encoding", "gzip")
		h.Add("Vary", "Accept-Encoding")
		if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
			h.Set("ETag", "W/"+et) // the body differs from the backend's
		}
		gz := gzipPool.Get().(*gzip.Writer)
		gz.Reset(w.ResponseWriter)
		w.gz = gz
	}
}

func (w *webWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code) // informational (103 Early Hints): headers come again later
		return
	}
	w.start(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *webWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	if w.gz != nil {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush flushes the gzip buffer too (streaming responses, server-sent events).
func (w *webWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Hijack is needed for WebSocket upgrades through the proxy.
func (w *webWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *webWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *webWriter) finish() {
	if w.gz != nil {
		_ = w.gz.Close()
		w.gz.Reset(nil)
		gzipPool.Put(w.gz)
		w.gz = nil
	}
}

// compressible: the client accepts gzip, the response is text and not already encoded.
func compressible(r *http.Request, h http.Header, status int) bool {
	if r.Method == http.MethodHead || status < 200 || status == http.StatusNoContent || status == http.StatusNotModified ||
		status == http.StatusPartialContent || h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" {
		return false
	}
	if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
		return false
	}
	if n, err := strconv.Atoi(h.Get("Content-Length")); err == nil && n < 1024 {
		return false // not worth it
	}
	ct := strings.ToLower(h.Get("Content-Type"))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case ct == "":
		return false
	case strings.HasPrefix(ct, "text/") && ct != "text/event-stream":
		return true
	}
	return slices.Contains([]string{
		"application/json", "application/javascript", "application/x-javascript", "application/xml",
		"application/rss+xml", "application/atom+xml", "application/manifest+json", "application/ld+json",
		"application/wasm", "image/svg+xml", "application/xhtml+xml", "application/graphql-response+json",
	}, ct) || strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

func acceptsGzip(ae string) bool {
	for _, part := range strings.Split(ae, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") || strings.TrimSpace(name) == "*" {
			params = strings.ReplaceAll(params, " ", "")
			return params != "q=0" && params != "q=0.0" && params != "q=0.00" && params != "q=0.000"
		}
	}
	return false
}

// corsOrigin returns the request's Origin when the route's CORS options allow it.
func corsOrigin(c *store.CORS, r *http.Request) string {
	if c == nil {
		return ""
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return ""
	}
	for _, allowed := range c.Origins {
		if allowed == "*" || strings.EqualFold(allowed, o) {
			return o
		}
	}
	return ""
}

func corsAllowHeaders(h http.Header, c *store.CORS, origin string) {
	if slices.Contains(c.Origins, "*") && !c.Credentials {
		h.Set("Access-Control-Allow-Origin", "*")
	} else {
		h.Set("Access-Control-Allow-Origin", origin)
	}
	if c.Credentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
}

// corsPreflight answers an OPTIONS preflight for an allowed origin itself (204), without the backend.
func corsPreflight(w http.ResponseWriter, r *http.Request, c *store.CORS, origin string) bool {
	if r.Method != http.MethodOptions || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	h := w.Header()
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	if origin == "" {
		w.WriteHeader(http.StatusForbidden) // not an allowed origin: the browser blocks the request
		return true
	}
	corsAllowHeaders(h, c, origin)
	methods := c.Methods
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	h.Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
	if len(c.Headers) > 0 {
		h.Set("Access-Control-Allow-Headers", strings.Join(c.Headers, ", "))
	} else if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
		h.Set("Access-Control-Allow-Headers", req)
	}
	maxAge := c.MaxAge
	if maxAge == 0 {
		maxAge = 600
	}
	h.Set("Access-Control-Max-Age", strconv.Itoa(maxAge))
	w.WriteHeader(http.StatusNoContent)
	return true
}

// applyRequestHeaders sets the route's request headers on the outgoing request.
func applyRequestHeaders(out *http.Request, web *store.Web) {
	if web == nil {
		return
	}
	for k, v := range web.RequestHeaders {
		if v == "" {
			out.Header.Del(k)
		} else {
			out.Header.Set(k, v)
		}
	}
}
