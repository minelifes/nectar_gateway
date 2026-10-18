package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nectar_gateway/internal/acme"
	"nectar_gateway/internal/api"
	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/health"
	"nectar_gateway/internal/metrics"
	"nectar_gateway/internal/passthrough"
	"nectar_gateway/internal/proxy"
	"nectar_gateway/internal/settings"
	"nectar_gateway/internal/store"
)

//go:embed all:ui/dist
var uiFS embed.FS

// version is set at build time: -ldflags "-X main.version=1.2.3"
var version = "dev"

// tlsNoiseFilter drops "TLS handshake error" log lines — internet scanners
// hitting :443 without SNI produce them constantly and they carry no signal.
type tlsNoiseFilter struct{ w io.Writer }

func (f tlsNoiseFilter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		return len(p), nil
	}
	return f.w.Write(p)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}

func main() {
	proxyAddr := env("PROXY_ADDR", ":8080")
	httpsAddr := env("HTTPS_ADDR", ":8443")
	adminAddr := env("ADMIN_ADDR", ":8081")
	dbPath := env("DB_PATH", "nectar.db")
	headless := env("ADMIN_UI", "true") == "false"
	// In headless mode (inside Kubernetes, controlled by nectar-apps) password login is off unless
	// ADMIN_USER/ADMIN_PASS are set explicitly: the admin port must not accept admin/admin.
	defUser, defPass := "admin", "admin"
	if headless {
		defUser, defPass = "", ""
	}
	adminUser := env("ADMIN_USER", defUser)
	adminPass := env("ADMIN_PASS", defPass)
	if adminUser != "" && adminPass == "" {
		log.Fatalf("ADMIN_PASS is required when ADMIN_USER is set")
	}
	cb := certbot.Config{
		Bin:     env("CERTBOT_BIN", "certbot"),
		Webroot: env("CERTBOT_WEBROOT", "/var/www/certbot"),
		Email:   os.Getenv("CERTBOT_EMAIL"),
		LiveDir: env("CERTBOT_LIVE_DIR", "/etc/letsencrypt/live"),
	}

	st, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	// FALLBACK_HTTP / FALLBACK_TLS are defaults; values set through PUT /api/settings win.
	cfg, err := settings.Load(st, settings.Values{FallbackHTTP: os.Getenv("FALLBACK_HTTP"), FallbackTLS: os.Getenv("FALLBACK_TLS")})
	if err != nil {
		log.Fatalf("settings: %v", err)
	}
	rec := metrics.New(envInt("ACCESS_LOG_SIZE", 2000))

	var ui fs.FS
	if !headless {
		if ui, err = fs.Sub(uiFS, "ui/dist"); err != nil {
			log.Fatalf("ui fs: %v", err)
		}
	} else {
		log.Printf("headless mode: admin UI disabled (ADMIN_UI=false), API only")
	}

	// Built-in Let's Encrypt (replaces certbot) when ACME_EMAIL is set.
	var issuer *acme.Issuer
	if email := os.Getenv("ACME_EMAIL"); email != "" || os.Getenv("ACME") == "true" {
		issuer = acme.New(st, email, os.Getenv("ACME_DIRECTORY"))
		go issuer.RunRenewals(context.Background(), 12*time.Hour)
		log.Printf("acme: built-in Let's Encrypt client enabled (%s)", env("ACME_DIRECTORY", acme.LetsEncrypt))
	}
	apiToken := os.Getenv("GATEWAY_API_TOKEN")
	if apiToken != "" && len(apiToken) < 24 {
		log.Fatalf("GATEWAY_API_TOKEN must be at least 24 characters")
	}

	hc := health.New(st, os.Getenv("NOTIFY_URL"))
	hcCtx, hcCancel := context.WithCancel(context.Background())
	defer hcCancel()
	go hc.Run(hcCtx)

	adminSrv := &http.Server{
		Addr:    adminAddr,
		Handler: api.New(st, adminUser, adminPass, ui, cb, hc, api.Options{APIToken: apiToken, Version: version, Issuer: issuerOrNil(issuer), Metrics: rec, Settings: cfg}).Handler(),
	}
	go func() {
		if adminUser == "" {
			log.Printf("admin API listening on %s (password login disabled; service token only)", adminAddr)
		} else {
			log.Printf("admin UI listening on %s (user: %s)", adminAddr, adminUser)
		}
		for {
			err := adminSrv.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				return
			}
			// never take the proxy down because the admin port failed
			log.Printf("admin: %v (retrying in 5s)", err)
			time.Sleep(5 * time.Second)
		}
	}()

	p := proxy.New(st, cb.Webroot)
	if issuer != nil {
		p.Challenge = issuer.ChallengeResponse
	}
	p.Metrics = rec
	p.FallbackTarget = func() string { return cfg.Get().FallbackHTTP }
	// SNI passthrough: TLS for hosts without a certificate here goes to FALLBACK_TLS untouched.
	decide := func(sni string) string {
		target := cfg.Get().FallbackTLS
		if target == "" {
			return ""
		}
		if _, ok := st.CertRoute(strings.ToLower(sni)); ok {
			return ""
		}
		return target
	}

	// Timeouts protect against slow/idle clients exhausting connections.
	newServer := func(addr string, tlsCfg *tls.Config) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           p,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          log.New(tlsNoiseFilter{log.Default().Writer()}, "", log.LstdFlags),
		}
	}

	// One accept loop per core (kernel load-balances via SO_REUSEPORT).
	nListeners := envInt("NUM_LISTENERS", runtime.NumCPU())

	httpsSrv := newServer(httpsAddr, &tls.Config{GetCertificate: p.GetCertificate})
	httpsLs, err := reuseportListeners(httpsAddr, nListeners)
	if err != nil {
		log.Printf("https proxy: %v", err)
	} else {
		for i, l := range httpsLs {
			httpsLs[i] = passthrough.Wrap(l, decide)
		}
		log.Printf("https proxy listening on %s (%d listeners)", httpsAddr, len(httpsLs))
		for _, l := range httpsLs {
			go func(l net.Listener) {
				if err := httpsSrv.ServeTLS(l, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Printf("https proxy: %v", err)
				}
			}(l)
		}
	}

	httpSrv := newServer(proxyAddr, nil)
	// accept prior-knowledge HTTP/2 over plain HTTP too (gRPC clients without TLS)
	httpSrv.Protocols = new(http.Protocols)
	httpSrv.Protocols.SetHTTP1(true)
	httpSrv.Protocols.SetUnencryptedHTTP2(true)
	httpLs, err := reuseportListeners(proxyAddr, nListeners)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	log.Printf("proxy listening on %s (%d listeners)", proxyAddr, len(httpLs))
	for _, l := range httpLs {
		go func(l net.Listener) {
			if err := httpSrv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("proxy: %v", err)
			}
		}(l)
	}

	// Graceful shutdown: on SIGTERM/SIGINT stop accepting new connections
	// and give in-flight requests up to 30s to finish.
	done := make(chan struct{})
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		log.Printf("shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		_ = httpsSrv.Shutdown(ctx)
		_ = adminSrv.Shutdown(ctx)
		close(done)
	}()

	// Block until shutdown. A single listener error must not kill the
	// process — the remaining listeners keep serving.
	<-done
	log.Printf("shutdown complete")
}

// issuerOrNil avoids a typed-nil interface when ACME is disabled.
func issuerOrNil(i *acme.Issuer) api.CertIssuer {
	if i == nil {
		return nil
	}
	return i
}
