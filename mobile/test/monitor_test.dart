import 'package:flutter_test/flutter_test.dart';
import 'package:nectar_mobile/src/config.dart';
import 'package:nectar_mobile/src/models.dart';
import 'package:nectar_mobile/src/monitor.dart';

RouteInfo route(int id, String domain, {bool hc = true}) => RouteInfo(
      id: id,
      domain: domain,
      mode: 'proxy',
      targetLabel: '10.0.0.$id:80',
      hcEnabled: hc,
      hasSsl: false,
    );

Snapshot snap(List<RouteInfo> routes, Map<int, HealthInfo> health) =>
    Snapshot(routes: routes, health: health, fetchedAt: DateTime(2026, 1, 1));

void main() {
  group('evaluateSnapshot', () {
    test('alerts once when a backend goes down, not again while it stays down', () {
      final r = route(1, 'api.example.com');
      final down = snap([r], {1: const HealthInfo(up: false, lastError: 'status 500')});

      final first = evaluateSnapshot(const MonitorState(), down);
      expect(first.alerts, hasLength(1));
      expect(first.alerts.single.title, contains('api.example.com'));
      expect(first.alerts.single.body, 'status 500');
      expect(first.alerts.single.id, kRouteAlertBase + 1);
      expect(first.state.routes[1], false);

      final second = evaluateSnapshot(first.state, down);
      expect(second.alerts, isEmpty);
    });

    test('alerts on recovery, reusing the same notification id', () {
      final r = route(1, 'api.example.com');
      final prev = const MonitorState(routes: {1: false});
      final up = snap([r], {1: const HealthInfo(up: true)});

      final ev = evaluateSnapshot(prev, up);
      expect(ev.alerts, hasLength(1));
      expect(ev.alerts.single.title, contains('recovered'));
      expect(ev.alerts.single.id, kRouteAlertBase + 1);
      expect(ev.state.routes[1], true);
    });

    test('no alert when a healthy backend stays healthy', () {
      final r = route(1, 'a.example.com');
      final ev = evaluateSnapshot(const MonitorState(routes: {1: true}), snap([r], {1: const HealthInfo(up: true)}));
      expect(ev.alerts, isEmpty);
    });

    test('unknown verdict (gateway just restarted) keeps previous state and stays quiet', () {
      final r = route(1, 'a.example.com');
      final ev = evaluateSnapshot(const MonitorState(routes: {1: false}), snap([r], {1: const HealthInfo(up: null)}));
      expect(ev.alerts, isEmpty);
      expect(ev.state.routes[1], false);
    });

    test('routes without health check are ignored', () {
      final r = route(1, 'a.example.com', hc: false);
      final ev = evaluateSnapshot(const MonitorState(), snap([r], {1: const HealthInfo(up: false)}));
      expect(ev.alerts, isEmpty);
      expect(ev.state.routes, isEmpty);
    });

    test('a backend that is already down on the very first check alerts', () {
      final r = route(1, 'a.example.com');
      final ev = evaluateSnapshot(const MonitorState(), snap([r], {1: const HealthInfo(up: false)}));
      expect(ev.alerts, hasLength(1));
      expect(ev.alerts.single.body, 'Health check failed');
    });

    test('announces that the gateway is reachable again', () {
      final ev = evaluateSnapshot(const MonitorState(serverUp: false, serverFails: 3), snap([], {}));
      expect(ev.alerts.single.id, kServerAlertId);
      expect(ev.alerts.single.title, contains('reachable again'));
      expect(ev.state.serverUp, true);
      expect(ev.state.serverFails, 0);
    });
  });

  group('evaluateUnreachable', () {
    test('alerts immediately with threshold 1, only once', () {
      final first = evaluateUnreachable(const MonitorState(), 'host: Timed out');
      expect(first.alerts.single.id, kServerAlertId);
      expect(first.state.serverUp, false);

      final second = evaluateUnreachable(first.state, 'host: Timed out');
      expect(second.alerts, isEmpty);
    });

    test('debounces with threshold 2', () {
      final first = evaluateUnreachable(const MonitorState(), 'x', threshold: 2);
      expect(first.alerts, isEmpty);
      expect(first.state.serverFails, 1);

      final second = evaluateUnreachable(first.state, 'x', threshold: 2);
      expect(second.alerts, hasLength(1));
    });
  });

  group('serialization', () {
    test('MonitorState survives a JSON round trip', () {
      const s = MonitorState(serverUp: false, serverFails: 2, routes: {1: true, 7: false});
      final back = MonitorState.fromJson(s.toJson());
      expect(back.serverUp, false);
      expect(back.serverFails, 2);
      expect(back.routes, {1: true, 7: false});
    });

    test('Snapshot survives a JSON round trip', () {
      final s = snap([route(1, 'a.b.example.com')], {1: const HealthInfo(up: false, lastError: 'boom')});
      final back = Snapshot.fromJson(s.toJson());
      expect(back.routes.single.domain, 'a.b.example.com');
      expect(back.health[1]!.up, false);
      expect(back.health[1]!.lastError, 'boom');
      expect(back.downCount, 1);
    });

    test('Snapshot.fromApi parses the gateway payloads', () {
      final s = Snapshot.fromApi(
        [
          {'id': 3, 'domain': 'x.y.com', 'mode': 'proxy', 'target_ip': '1.2.3.4', 'target_port': 9443, 'target_https': true, 'hc_enabled': true, 'cert_file': 'c', 'key_file': 'k'},
        ],
        {
          '3': {'up': false, 'last_error': 'status 502', 'last_check': '2026-09-13T10:00:00Z'},
        },
        DateTime(2026, 1, 1),
      );
      expect(s.routes.single.targetLabel, 'https://1.2.3.4:9443');
      expect(s.routes.single.hasSsl, true);
      expect(s.routes.single.parent, 'y.com');
      expect(s.isDown(s.routes.single), true);
    });
  });
}
