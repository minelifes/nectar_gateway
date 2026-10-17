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

## Platform limits you should know

- **Android**: 15 minutes is the OS minimum, and Doze can delay runs further. Many vendors (Xiaomi, Huawei, Samsung, OnePlus…) kill background work aggressively — set the app's battery usage to **Unrestricted** / disable battery optimization, or alerts while closed may be late or missing. See <https://dontkillmyapp.com>.
- **iOS**: Apple decides when (and whether) background tasks run, usually based on how often you open the app — it can be hours, and it is not guaranteed. Alerts while the app is open/recently used are reliable; for guaranteed closed-app alerts on iOS you would need real push (APNs via a push service), which this app deliberately avoids. You also need an Apple developer signing setup to run on a device.
- Because the checks run on the phone, an outage that starts while the phone has no internet is reported at the first background run after it reconnects.

## Tests

```bash
flutter test
```

Covers the alert logic (transitions, debounce, recovery, restart handling) and JSON round-trips.
