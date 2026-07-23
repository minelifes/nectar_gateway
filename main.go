package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"nectar_gateway/internal/api"
	"nectar_gateway/internal/certbot"
	"nectar_gateway/internal/proxy"
	"nectar_gateway/internal/store"
)

//go:embed all:ui/dist
var uiFS embed.FS

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
	adminUser := env("ADMIN_USER", "admin")
	adminPass := env("ADMIN_PASS", "admin")
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

	ui, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		log.Fatalf("ui fs: %v", err)
	}

	adminSrv := &http.Server{
		Addr:    adminAddr,
		Handler: api.New(st, adminUser, adminPass, ui, cb).Handler(),
	}
	go func() {
		log.Printf("admin UI listening on %s (user: %s)", adminAddr, adminUser)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("admin: %v", err)
		}
	}()

	p := proxy.New(st, cb.Webroot)

	// Timeouts protect against slow/idle clients exhausting connections.
	newServer := func(addr string, tlsCfg *tls.Config) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           p,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
	}

	// One accept loop per core (kernel load-balances via SO_REUSEPORT).
	nListeners := envInt("NUM_LISTENERS", runtime.NumCPU())

	httpsSrv := newServer(httpsAddr, &tls.Config{GetCertificate: p.GetCertificate})
	httpsLs, err := reuseportListeners(httpsAddr, nListeners)
	if err != nil {
		log.Printf("https proxy: %v", err)
	} else {
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
	httpLs, err := reuseportListeners(proxyAddr, nListeners)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	log.Printf("proxy listening on %s (%d listeners)", proxyAddr, len(httpLs))
	for _, l := range httpLs[1:] {
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

	if err := httpSrv.Serve(httpLs[0]); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("proxy: %v", err)
	}
	<-done
	log.Printf("shutdown complete")
}
