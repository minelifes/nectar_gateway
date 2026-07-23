// Package certbot shells out to certbot to obtain Let's Encrypt
// certificates using the webroot (HTTP-01) challenge.
package certbot

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Bin     string // e.g. "certbot" or "sudo -n certbot"
	Webroot string // directory served at /.well-known/acme-challenge/
	Email   string // registration email (optional)
	LiveDir string // usually /etc/letsencrypt/live
}

// Obtain runs certbot for the domain and returns the cert/key paths.
func (c Config) Obtain(ctx context.Context, domain string) (certFile, keyFile string, err error) {
	if err := os.MkdirAll(filepath.Join(c.Webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return "", "", fmt.Errorf("webroot: %w", err)
	}

	parts := strings.Fields(c.Bin)
	if len(parts) == 0 {
		parts = []string{"certbot"}
	}
	args := append(parts[1:],
		"certonly", "--webroot",
		"-w", c.Webroot,
		"-d", domain,
		"--cert-name", domain,
		"--non-interactive", "--agree-tos", "--keep-until-expiring",
	)
	if c.Email != "" {
		args = append(args, "-m", c.Email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, parts[0], args...).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("certbot failed: %v: %s", err, tail(string(out), 800))
	}

	live := c.LiveDir
	if live == "" {
		live = "/etc/letsencrypt/live"
	}
	certFile = filepath.Join(live, domain, "fullchain.pem")
	keyFile = filepath.Join(live, domain, "privkey.pem")
	return certFile, keyFile, nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
