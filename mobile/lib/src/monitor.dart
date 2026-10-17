import 'package:http/http.dart' as http;

import 'api_client.dart';
import 'config.dart';
import 'models.dart';
import 'notifier.dart';
import 'storage.dart';

// ---------------------------------------------------------------------------
// Pure alert logic (no I/O) - unit tested in test/monitor_test.dart
// ---------------------------------------------------------------------------

/// What the user has already been told about. Persisted, so the foreground
/// and background isolates never send duplicate alerts.
class MonitorState {
  const MonitorState({
    this.serverUp,
    this.serverFails = 0,
    this.routes = const {},
  });

  /// null = never checked; false = we alerted that the gateway is down.
  final bool? serverUp;

  /// Consecutive failed checks of the gateway (debounce counter).
  final int serverFails;

  /// Last known health per monitored route id (true = up, false = down).
  final Map<int, bool> routes;

  MonitorState copyWith({bool? serverUp, int? serverFails, Map<int, bool>? routes}) => MonitorState(
        serverUp: serverUp ?? this.serverUp,
        serverFails: serverFails ?? this.serverFails,
        routes: routes ?? this.routes,
      );

  Map<String, dynamic> toJson() => {
        'server_up': serverUp,
        'server_fails': serverFails,
        'routes': {for (final e in routes.entries) '${e.key}': e.value},
      };

  factory MonitorState.fromJson(Map<String, dynamic> j) {
    final routes = <int, bool>{};
    ((j['routes'] as Map?) ?? const {}).forEach((k, v) {
      final id = int.tryParse('$k');
      if (id != null && v is bool) routes[id] = v;
    });
    return MonitorState(
      serverUp: j['server_up'] as bool?,
      serverFails: (j['server_fails'] as num?)?.toInt() ?? 0,
      routes: routes,
    );
  }
}

class Alert {
  const Alert(this.id, this.title, this.body);
  final int id;
  final String title;
  final String body;
}

class Evaluation {
  const Evaluation(this.state, this.alerts);
  final MonitorState state;
  final List<Alert> alerts;
}

/// The gateway answered. Compares each monitored backend with what we last
/// knew and emits an alert on every up->down / down->up transition.
Evaluation evaluateSnapshot(MonitorState prev, Snapshot snap) {
  final alerts = <Alert>[];

  if (prev.serverUp == false) {
    alerts.add(const Alert(kServerAlertId, '🟢 Gateway reachable again', 'Nectar Gateway is responding again.'));
  }

  final routes = <int, bool>{};
  for (final r in snap.routes) {
    if (!r.hcEnabled) continue;
    final h = snap.health[r.id];
    final up = h?.up;
    final was = prev.routes[r.id];

    if (up == null) {
      // gateway has no verdict yet (e.g. just restarted): keep what we knew
      if (was != null) routes[r.id] = was;
      continue;
    }
    routes[r.id] = up;

    final id = kRouteAlertBase + r.id;
    if (!up && was != false) {
      final err = h?.lastError ?? '';
      alerts.add(Alert(id, '🔴 ${r.domain} is DOWN', err.isEmpty ? 'Health check failed' : err));
    } else if (up && was == false) {
      alerts.add(Alert(id, '🟢 ${r.domain} recovered', 'Backend is healthy again.'));
    }
  }

  return Evaluation(MonitorState(serverUp: true, serverFails: 0, routes: routes), alerts);
}

/// The gateway could not be reached although the phone has internet.
/// An alert fires once [threshold] consecutive failures have been seen.
Evaluation evaluateUnreachable(MonitorState prev, String reason, {int threshold = 1}) {
  final fails = prev.serverFails + 1;
  final alerts = <Alert>[];
  var serverUp = prev.serverUp;
  if (fails >= threshold && prev.serverUp != false) {
    serverUp = false;
    alerts.add(Alert(kServerAlertId, '🔴 Nectar Gateway is unreachable', reason));
  }
  return Evaluation(prev.copyWith(serverFails: fails, serverUp: serverUp), alerts);
}

// ---------------------------------------------------------------------------
// Runner: fetch -> evaluate -> persist -> notify
// ---------------------------------------------------------------------------

enum CheckStatus { ok, offline, serverUnreachable, serverError, authExpired, notLoggedIn }

class CheckResult {
  const CheckResult(this.status, {this.snapshot, this.message});
  final CheckStatus status;
  final Snapshot? snapshot;
  final String? message;
}

class Monitor {
  /// One full check, used by both the foreground poller and the background task.
  ///
  /// [attempts] / [retryDelay]: retries within one run before the gateway is
  /// declared unreachable (background uses 3, so a single blip never alerts).
  /// [failureThreshold]: consecutive failed *runs* required before alerting
  /// (foreground uses 2).
  static Future<CheckResult> run({
    int attempts = 1,
    Duration retryDelay = const Duration(seconds: 10),
    int failureThreshold = 1,
    bool inBackground = false,
  }) async {
    final storage = Storage();
    final api = ApiClient(storage);

    if (!await storage.isLoggedIn()) return const CheckResult(CheckStatus.notLoggedIn);

    final state = await storage.loadMonitorState();
    String lastReason = 'No response';

    for (var i = 0; i < attempts; i++) {
      if (i > 0) await Future<void>.delayed(retryDelay);
      try {
        final snap = await api.fetchSnapshot();
        await storage.saveSnapshot(snap);
        final ev = evaluateSnapshot(state, snap);
        await storage.saveMonitorState(ev.state);
        await _show(ev.alerts);
        return CheckResult(CheckStatus.ok, snapshot: snap);
      } on AuthExpiredException {
        // Only alert from the background; in the foreground the login screen appears.
        if (inBackground) {
          await _show(const [
            Alert(kAuthAlertId, 'Nectar: signed out',
                'Your session expired, so monitoring is paused. Open the app and sign in again.'),
          ]);
        }
        return const CheckResult(CheckStatus.authExpired);
      } on ServerUnreachableException catch (e) {
        lastReason = e.message;
      } on ApiException catch (e) {
        if (e.status >= 502 && e.status <= 504) {
          lastReason = 'HTTP ${e.status}'; // front proxy reachable, admin backend is not
        } else {
          return CheckResult(CheckStatus.serverError, message: e.message);
        }
      }
    }

    // Every attempt failed. Only blame the server if the phone itself is online.
    if (!await hasInternet()) return CheckResult(CheckStatus.offline, message: lastReason);

    final host = Uri.tryParse(await storage.serverUrl() ?? '')?.host ?? 'server';
    final ev = evaluateUnreachable(state, '$host: $lastReason', threshold: failureThreshold);
    await storage.saveMonitorState(ev.state);
    await _show(ev.alerts);
    return CheckResult(CheckStatus.serverUnreachable, message: lastReason);
  }

  /// True when the phone can reach the public internet (so a failure to reach
  /// the gateway means the gateway is the problem, not the phone's connection).
  static Future<bool> hasInternet() async {
    const probes = [
      'https://connectivitycheck.gstatic.com/generate_204',
      'https://www.cloudflare.com/cdn-cgi/trace',
    ];
    for (final url in probes) {
      try {
        final r = await http.get(Uri.parse(url)).timeout(const Duration(seconds: 5));
        if (r.statusCode == 204 || r.statusCode == 200) return true;
      } catch (_) {
        // try the next probe
      }
    }
    return false;
  }

  static Future<void> _show(List<Alert> alerts) async {
    for (final a in alerts) {
      try {
        await Notifier.show(id: a.id, title: a.title, body: a.body);
      } catch (_) {
        // a notification problem must never break monitoring
      }
    }
  }
}
