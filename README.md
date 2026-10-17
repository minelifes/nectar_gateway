# Nectar Gateway

NGINX-like reverse proxy in Go with a React + Material UI admin panel.
Add a domain → requests to that domain are proxied (all headers preserved) to the IP:port you set. Unknown domain → **410 Gone**.

## Build & run

```bash
cd ui && npm install && npm run build && cd ..
go mod tidy
go build -o nectar_gateway .
./nectar_gateway
```

- Proxy: `:8080` — point your domains' DNS/hosts here
- Admin UI: `http://localhost:8081` — login `admin` / `admin`

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

`GET/POST /api/routes`, `PUT/DELETE /api/routes/{id}` — JSON `{domain, target_ip, target_port}`.

## Dev mode (UI hot reload)

```bash
go run .            # backend
cd ui && npm run dev  # Vite on :5173, proxies /api to :8081
```
