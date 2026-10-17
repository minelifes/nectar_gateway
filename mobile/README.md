# Nectar Mobile

Flutter app (Android + iOS) for Nectar Gateway: live status of every domain/backend, last-known data when offline, and **local notifications** when the gateway or one of your backends goes down. No Firebase, no third-party push service.

## Setup

Requires the [Flutter SDK](https://docs.flutter.dev/get-started/install) and `python3`.

```bash
cd mobile
./tool/setup.sh        # generates android/ + ios/, patches them, runs `flutter pub get`
flutter run            # on a connected device / emulator
```

`setup.sh` is idempotent. It adds the Internet + notification permissions, core-library desugaring (needed by `flutter_local_notifications`), iOS background modes / task identifier / `AppDelegate` wiring for `workmanager`. If a step prints a warning, the README of that package describes the manual equivalent.

Sign in with the **admin URL** of your gateway (`https://admin.example.com`, or `http://IP:8081` on a trusted LAN) and the same username/password as the web UI. Use https — the login screen warns on plain http.

The gateway must be the new version (it adds `/api/auth/login|refresh|logout`).

## How it works

**Auth / auto-refresh.** Login returns a 15-minute access token and a 30-day refresh token (stored in Keychain/Keystore). The client refreshes the access token ~60 s before expiry, and on any `401` once (covers a gateway restart, which forgets access tokens). Concurrent requests share one refresh. A network failure while refreshing never signs you out — only the server explicitly rejecting the refresh token does. The refresh token's expiry slides forward on every refresh, so a device that is checked regularly stays signed in indefinitely.

**Always showing the last info.** Every successful check is cached; the app shows that cache instantly on launch (marked "cached") and keeps showing it, with a banner, when the gateway is unreachable or the phone is offline.

**Alerts.**

| Event | Notification |
|---|---|
| Backend health check goes down | `🔴 api.example.com is DOWN` + failure reason |
| Backend recovers | `🟢 api.example.com recovered` (replaces the DOWN one) |
| Gateway itself unreachable (phone has internet) | `🔴 Nectar Gateway is unreachable` |
| Gateway reachable again | `🟢 Gateway reachable again` |
| Session expired (background only) | `Nectar: signed out` |

Alerts fire on *transitions* only (state is persisted, so the foreground and background checks never duplicate each other). A gateway outage needs 3 failed attempts in one background run (or 2 consecutive foreground checks) before alerting, and is only reported if the phone can reach the public internet — being offline never triggers a false alarm. Backend-down alerts come from the gateway's own health checks, so enable **Health check** on each domain in the web UI (that is also what the dots in the app reflect).

**Checking.** While the app is open: every 20 s. While closed: a WorkManager periodic task roughly every 15 minutes.

**Fast monitoring (Android, on by default; can be switched off in the menu → Monitoring settings).** WorkManager cannot go below 15 minutes. Turn on *Monitoring settings → Fast monitoring* to run a foreground service that checks **every 60 seconds** even with the app closed. It shows a permanent notification with live status (`All systems operational · 4 monitored · checked 12:03`), restarts after a reboot or app update, and costs noticeably more battery. The 15-minute WorkManager task keeps running alongside as a safety net if your phone's vendor kills the service. Also tap *Unrestricted battery use* in the same sheet. The service uses the `specialUse` foreground-service type (the `dataSync` type is cut off after 6 h per 24 h on Android 15+); that type is fine for sideloading, but Google Play requires a declaration form for it. `flutter_foreground_task` 11 needs Flutter 3.44+ / Dart 3.12+, Kotlin 2.2.20+ and Gradle 8.11.1+. After pulling this change run `./tool/setup.sh` again (idempotent) to add the service to the manifest.

## Managing domains (same as the web UI)

- **Add domain**: the "Add domain" button. **Edit / delete**: tap a domain.
- **Add subdomain**: the `+` on a group header; type only the prefix (`.example.com` is appended).
- The form covers proxy / static mode, target IP + port, "Backend uses HTTPS", rate limit, SSL cert/key paths, Force HTTPS, *Save & get Let's Encrypt certificate*, and the health check (path, interval, type status / contains / json, expectation).
- **Import from nginx**: top-right menu. Paste a config, *Preview*, then *Import* (existing domains are skipped).

## Platform limits you should know

- **Android** (without fast monitoring): 15 minutes is the OS minimum, and Doze can delay runs further. Many vendors (Xiaomi, Huawei, Samsung, OnePlus…) kill background work aggressively — set the app's battery usage to **Unrestricted** / disable battery optimization, or alerts while closed may be late or missing. See <https://dontkillmyapp.com>.
- **iOS**: Apple decides when (and whether) background tasks run, usually based on how often you open the app — it can be hours, and it is not guaranteed. Alerts while the app is open/recently used are reliable; for guaranteed closed-app alerts on iOS you would need real push (APNs via a push service), which this app deliberately avoids. You also need an Apple developer signing setup to run on a device.
- Because the checks run on the phone, an outage that starts while the phone has no internet is reported at the first background run after it reconnects.

## Tests

```bash
flutter test
```

Covers the alert logic (transitions, debounce, recovery, restart handling) and JSON round-trips.
