# Nectar Gateway

NGINX-like reverse proxy in Go with a React + Material UI admin panel.
Add a domain → requests to that domain are proxied (all headers preserved) to the IP:port you set. Unknown domain → **410 Gone**.

## Release
```bash
git commit --allow-empty -m "chore: release 1.2.0" -m "Release-As: 1.2.0"
git push       
```

## Build & run

```bash
cd ui && npm install && npm run build && cd ..
go mod tidy
go build -o nectar_gateway .
./nectar_gateway
```

- Proxy: `:8080` — point your domains' DNS/hosts here
- Admin UI: `http://localhost:8081` — login `admin` / `admin`
  - **Domains:** proxy, static files or redirect; health check, rate limit, maintenance page, backend protocol
    (HTTP/1.1 or h2c for gRPC), timeout, body size limit, basic-auth users, Let's Encrypt (one-off or renewed
    automatically) or certificate files.
  - **Certificates:** wildcard and shared certificates (Let's Encrypt over DNS-01, or uploaded PEM files), with
    the hosts each one serves; renew, replace, delete.
  - **Blocked IPs**, and **Settings:** ACME email, DNS provider + token, rate-limit blocking, fallbacks for unknown hosts.

## Config (env vars)

| Var | Default | |
|---|---|---|
| `PROXY_ADDR` | `:8080` | HTTP proxy listen address (use `:80` in prod) |
| `HTTPS_ADDR` | `:8443` | HTTPS proxy listen address (use `:443` in prod); serves domains that have cert/key configured (SNI) |
| `ADMIN_ADDR` | `:8081` | admin UI/API address |
| `ADMIN_USER` / `ADMIN_PASS` | `admin` / `admin` | basic auth (empty `ADMIN_USER` disables auth) |
| `DB_PATH` | `nectar.db` | SQLite database file |

## SERVER CONFIG
```bash
sudo useradd -r -s /usr/sbin/nologin nectar
sudo mkdir -p /opt/nectar_gateway && sudo chown nectar:nectar /opt/nectar_gateway
sudo cp nectar_gateway.service /etc/systemd/system/   # edit ADMIN_PASS first
sudo systemctl daemon-reload && sudo systemctl enable nectar_gateway
# let the deploy user restart without a password prompt:
echo "$USER ALL=NOPASSWD: /usr/bin/install -m 755 /tmp/nectar_gateway.new /opt/nectar_gateway/nectar_gateway, /usr/bin/systemctl restart nectar_gateway" | sudo tee /etc/sudoers.d/nectar-deploy
```

## Let's Encrypt (certbot)

The lock-plus button next to a domain runs certbot (HTTP-01 webroot challenge) and saves the cert paths on the route. Requirements: `certbot` installed, `PROXY_ADDR=:80` reachable from the internet, DNS pointing at the server. The proxy serves `/.well-known/acme-challenge/` automatically (before any HTTPS redirect).

Env vars: `CERTBOT_BIN` (default `certbot`, use `sudo -n certbot` when running as a non-root service), `CERTBOT_WEBROOT` (default `/var/www/certbot`), `CERTBOT_EMAIL`, `CERTBOT_LIVE_DIR` (default `/etc/letsencrypt/live`).

Non-root service setup:

```bash
sudo mkdir -p /var/www/certbot && sudo chown nectar:nectar /var/www/certbot
echo "nectar ALL=NOPASSWD: /usr/bin/certbot" | sudo tee /etc/sudoers.d/nectar-certbot
# let the service read the certs:
sudo chgrp -R nectar /etc/letsencrypt/live /etc/letsencrypt/archive && sudo chmod -R g+rx /etc/letsencrypt/live /etc/letsencrypt/archive
```

Renewal: certbot's standard systemd timer (`certbot renew`) keeps working — nectar reloads changed cert files automatically, no restart needed.

## Health checks & push notifications

Enable per domain in its settings (proxy mode): path, interval, and check type — HTTP status code, body-contains-text, or JSON field (`status=ok`, nested paths like `checks.db=up`). Two consecutive failures mark the backend DOWN and send a push; recovery sends another. Status dots show in the domain list.

Push setup (ntfy, free): install the ntfy app ([Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy)/[iOS](https://apps.apple.com/us/app/ntfy/id1625396347)), subscribe to a topic with a hard-to-guess name (e.g. `nectar-a8f3k2`), then set `NOTIFY_URL=https://ntfy.sh/nectar-a8f3k2` in the service. Any webhook that accepts a plain-text POST (with `Title` header) works too.

## Mobile app

`mobile/` contains a Flutter app (Android + iOS) with live status and outage notifications — see [mobile/README.md](mobile/README.md). It authenticates with token endpoints on the admin port: `POST /api/auth/login` (`{username, password}` → `access_token` 15 min + `refresh_token` 30 days, sliding), `POST /api/auth/refresh`, `POST /api/auth/logout`; API calls then use `Authorization: Bearer <access_token>`. Refresh tokens are stored hashed in SQLite; failed logins are rate-limited (10 per 15 min per IP) on both the web and mobile login.

## API

`GET/POST /api/routes`, `PUT/DELETE /api/routes/{id}` — JSON `{domain, path_prefix, target_ip, target_port, …}`.

- **Path routing:** several routes can share a domain with different `path_prefix` values (`/`, `/api`, …); the longest matching prefix wins (matched per path segment, the path is passed through unchanged).
- **Wildcard hosts:** `*.apps.example.com` serves any single-label subdomain; an exact route for a host always wins.
- **Certificates:** `PUT /api/routes/{id}/cert` `{cert_pem, key_pem}` uploads a certificate (stored in the database, applied to every route of that host); `DELETE` removes it. `POST /api/routes/{id}/cert` issues one from Let's Encrypt. `acme: true` on a route issues and renews automatically.
- **Managed routes:** routes with `managed_by` (e.g. `nectar-apps`) can only be changed with the service token; the UI shows them read-only. `GET /api/routes?managed_by=nectar-apps&owner=…` filters.
- **Maintenance:** `maintenance: true` serves a branded "down for maintenance" page (503).
- **Redirects:** `mode: "redirect"` + `redirect_url` (`https://example.com`) answers with a redirect (`redirect_code` 301 default, 302/307/308); path and query are kept unless the URL has its own path — e.g. `www.example.com → https://example.com`.
- **Basic auth:** `basic_auth_users: [{user, password}]` protects a route (bcrypt; an empty password keeps that user's current one, `[]` removes basic auth). Controllers may send `basic_auth_htpasswd` (`user:<bcrypt>` lines) instead. Hashes are never returned — only `auth_usernames` and an `auth_fingerprint`.
- **gRPC / HTTP/2:** `backend_protocol: "h2c"` talks cleartext HTTP/2 to the backend (gRPC). Clients get HTTP/2 over TLS automatically, and the plain HTTP port also accepts prior-knowledge HTTP/2. WebSockets work with the default `http1`.
- **Limits:** `timeout_seconds` (time to response headers, default 60 s → 504) and `max_body_mb` (→ 413) per route.
- **Metrics & access log:** `GET /api/metrics?minutes=60&domain=&series=1` — per-domain requests, RPS, status classes, bytes, p50/p95/p99 latency, per-minute series (in memory, last 60 minutes). `GET /api/access-log?domain=&status=5xx&ip=&limit=` — the last `ACCESS_LOG_SIZE` (2000) requests, newest first.
- **Fallback & TLS passthrough (migrations):** `PUT /api/settings {fallback_http, fallback_tls}` (`host:port`). Requests for hosts without a route go to `fallback_http` instead of 410; HTTPS connections whose host has no certificate here are forwarded untouched (SNI passthrough) to `fallback_tls`, so a previous proxy keeps serving its own certificates. `FALLBACK_HTTP` / `FALLBACK_TLS` env vars are the defaults.
- **Let's Encrypt email at runtime:** `PUT /api/settings {"acme_email": "ops@example.com"}` sets the ACME account contact (default: `ACME_EMAIL`); a registered account is updated at Let's Encrypt. The built-in issuer runs when `ACME=true` or an email is set.
- **Wildcard certificates (DNS-01):** set a DNS provider once — `PUT /api/settings {"dns_provider": "cloudflare", "dns_api_token": "…"}` (a Cloudflare API token with Zone:Read and DNS:Edit; the token is write-only, `GET` shows `dns_token_set`). Then `POST /api/certificates {"domain": "*.apps.example.com", "include_apex": true}` orders a certificate over DNS-01 in the background. `GET /api/certificates` shows each certificate's `status` (pending, valid, expiring, expired, failed), `last_error` and the hosts it `serves`; `POST /api/certificates/{id}/renew` retries, `PUT /api/certificates/{id} {cert_pem, key_pem}` uploads a pair, `DELETE` removes it. A host whose routes have no certificate of their own is served by the covering certificate (exact before wildcard; `*.x` covers one label), routes show it as `covered_by` / `covered_until`, and no HTTP-01 order is made for covered hosts. Routes for `*.example.com` with `acme: true` also use DNS-01. `features` in `GET /api/version` lists `certificates`, `acme` and `dns-01`.
- **Fallback hits:** `GET /api/fallback-hits` lists every host that reached the fallback upstream (HTTP and TLS counts, first and last seen). The counters survive restarts; `DELETE /api/fallback-hits` resets them. The panel uses them to decide when the old proxy can be removed.
- **Rate limits:** a route's `rate_limit` (requests per second per client IP) answers 429 with `Retry-After: 1` above the limit. A client that keeps going (more than 10 × the limit rejected within a minute) is blocked for `rate_limit_block_minutes` (setting, default 10, `0` = never block; env `RATE_LIMIT_BLOCK_MINUTES`). Scanners (`/.env`, `/wp-login.php` …) and unknown-domain sweeps are still blocked for 24 h. `features` in `/api/version` contains `rate-limit-429`.
- **Block an IP by hand:** `POST /api/blocked {ip, reason, ttl_seconds}` (no TTL = permanent; used when importing a standalone gateway's block list).
- `GET /api/version` → `{version, api_version, headless, features}`, `GET /healthz`, `GET /readyz` (no auth). The proxy answers `/__nectar/canary` with `200 ok` for any host (update health checks).

### Service token & headless mode

| Var | | |
|---|---|---|
| `GATEWAY_API_TOKEN` | — | bearer token for controllers such as [nectar_apps](https://github.com/minelifes/nectar_apps) (min. 24 chars) |
| `ADMIN_UI` | `true` | `false` = headless: no admin UI, API only; password login is off unless `ADMIN_USER`/`ADMIN_PASS` are set explicitly |
| `ACME_EMAIL` | — | enables the built-in Let's Encrypt client (HTTP-01, certificates stored in the database, renewed 30 days before expiry) |
| `DNS_PROVIDER` / `DNS_API_TOKEN` | — | default DNS-01 provider (`cloudflare`) and its token for wildcard certificates; `PUT /api/settings` overrides |
| `ACME_DIRECTORY` | Let's Encrypt | e.g. `https://acme-staging-v02.api.letsencrypt.org/directory` for testing |
| `FALLBACK_HTTP` / `FALLBACK_TLS` | — | default fallback upstream / SNI passthrough target (`host:port`); `PUT /api/settings` overrides |
| `RATE_LIMIT_BLOCK_MINUTES` | `10` | how long a client that keeps exceeding a rate limit is blocked (`0` = never, only 429); `PUT /api/settings` overrides |
| `ACCESS_LOG_SIZE` | `2000` | access-log entries kept in memory |

### Releases

Merging the release PR that release-please keeps open on `main` tags `vX.Y.Z`; `.github/workflows/release.yml` then pushes the multi-arch image `ghcr.io/minelifes/nectar-gateway:X.Y.Z` (+ `:X.Y`, `:stable`), attaches `release.json` (read by the nectar-apps updater) and updates `updates.json` on `gh-pages`. Pre-releases: push a tag like `v0.3.0-beta.1`. Commit messages follow conventional commits (`fix:`, `feat:`, `feat!:` = breaking, `fix(security):`).

Inside Kubernetes the gateway runs as a container (`Dockerfile`) with `hostNetwork` on ports 80/443; nectar_apps installs and drives it.

## Dev mode (UI hot reload)

```bash
go run .            # backend
cd ui && npm run dev  # Vite on :5173, proxies /api to :8081
```
