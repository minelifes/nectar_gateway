class RouteInfo {
  const RouteInfo({
    required this.id,
    required this.domain,
    required this.mode,
    required this.targetLabel,
    required this.hcEnabled,
    required this.hasSsl,
    this.raw = const {},
  });

  /// Full route object as sent by the API (used by the edit form).
  final Map<String, dynamic> raw;

  final int id;
  final String domain;
  final String mode; // "proxy" | "static"
  final String targetLabel;
  final bool hcEnabled;
  final bool hasSsl;

  /// abc.domainA.com -> domainA.com (same grouping as the web UI).
  String get parent {
    final parts = domain.split('.');
    return parts.length <= 2 ? domain : parts.sublist(parts.length - 2).join('.');
  }

  /// Parses a route object as returned by GET /api/routes.
  factory RouteInfo.fromApi(Map<String, dynamic> j) {
    final mode = (j['mode'] as String?) ?? 'proxy';
    final String target;
    if (mode == 'static') {
      target = (j['static_dir'] as String?) ?? '';
    } else {
      final https = j['target_https'] == true;
      target = '${https ? 'https://' : ''}${j['target_ip'] ?? ''}:${j['target_port'] ?? 80}';
    }
    return RouteInfo(
      id: (j['id'] as num).toInt(),
      domain: (j['domain'] as String?) ?? '',
      mode: mode,
      targetLabel: target,
      hcEnabled: j['hc_enabled'] == true,
      hasSsl: ((j['cert_file'] as String?) ?? '').isNotEmpty &&
          ((j['key_file'] as String?) ?? '').isNotEmpty,
      raw: Map<String, dynamic>.from(j),
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'domain': domain,
        'mode': mode,
        'target_label': targetLabel,
        'hc_enabled': hcEnabled,
        'has_ssl': hasSsl,
        'raw': raw,
      };

  factory RouteInfo.fromJson(Map<String, dynamic> j) => RouteInfo(
        id: (j['id'] as num).toInt(),
        domain: j['domain'] as String,
        mode: j['mode'] as String,
        targetLabel: j['target_label'] as String,
        hcEnabled: j['hc_enabled'] as bool,
        hasSsl: j['has_ssl'] as bool,
        raw: (j['raw'] as Map?)?.cast<String, dynamic>() ?? const {},
      );
}

/// Result of an nginx config import / preview.
class ImportResult {
  const ImportResult({required this.routes, required this.skipped});
  final List<Map<String, dynamic>> routes;
  final List<String> skipped;

  factory ImportResult.fromApi(Map<String, dynamic> j) => ImportResult(
        routes: [for (final r in (j['routes'] as List? ?? const [])) (r as Map).cast<String, dynamic>()],
        skipped: [for (final s in (j['skipped'] as List? ?? const [])) '$s'],
      );
}

class BlockedIp {
  const BlockedIp({
    required this.ip,
    required this.reason,
    required this.blockedAt,
    required this.expiresAt,
  });

  final String ip;
  final String reason;
  final DateTime blockedAt;
  final DateTime expiresAt;

  /// Parses an entry of GET /api/blocked (also used for the local cache).
  factory BlockedIp.fromJson(Map<String, dynamic> j) => BlockedIp(
        ip: j['ip'] as String,
        reason: (j['reason'] as String?) ?? '',
        blockedAt: DateTime.parse(j['blocked_at'] as String).toLocal(),
        expiresAt: DateTime.parse(j['expires_at'] as String).toLocal(),
      );

  Map<String, dynamic> toJson() => {
        'ip': ip,
        'reason': reason,
        'blocked_at': blockedAt.toUtc().toIso8601String(),
        'expires_at': expiresAt.toUtc().toIso8601String(),
      };
}

class HealthInfo {
  const HealthInfo({this.up, this.lastError = '', this.lastCheck});

  /// null until the gateway finished its first check of this backend.
  final bool? up;
  final String lastError;
  final DateTime? lastCheck;

  factory HealthInfo.fromJson(Map<String, dynamic> j) => HealthInfo(
        up: j['up'] as bool?,
        lastError: (j['last_error'] as String?) ?? '',
        lastCheck: DateTime.tryParse((j['last_check'] as String?) ?? ''),
      );

  Map<String, dynamic> toJson() => {
        'up': up,
        'last_error': lastError,
        'last_check': lastCheck?.toIso8601String(),
      };
}

class Snapshot {
  const Snapshot({
    required this.routes,
    required this.health,
    required this.fetchedAt,
  });

  final List<RouteInfo> routes;
  final Map<int, HealthInfo> health;
  final DateTime fetchedAt;

  bool isDown(RouteInfo r) => r.hcEnabled && health[r.id]?.up == false;
  int get downCount => routes.where(isDown).length;
  int get monitoredCount => routes.where((r) => r.hcEnabled).length;

  /// Builds a snapshot from the raw /api/routes and /api/health payloads.
  factory Snapshot.fromApi(List<dynamic> routesJson, Map<String, dynamic> healthJson, DateTime now) {
    final routes = [
      for (final r in routesJson) RouteInfo.fromApi((r as Map).cast<String, dynamic>()),
    ];
    final health = <int, HealthInfo>{};
    healthJson.forEach((key, value) {
      final id = int.tryParse(key);
      if (id != null && value is Map) {
        health[id] = HealthInfo.fromJson(value.cast<String, dynamic>());
      }
    });
    return Snapshot(routes: routes, health: health, fetchedAt: now);
  }

  Map<String, dynamic> toJson() => {
        'fetched_at': fetchedAt.toIso8601String(),
        'routes': [for (final r in routes) r.toJson()],
        'health': {for (final e in health.entries) '${e.key}': e.value.toJson()},
      };

  factory Snapshot.fromJson(Map<String, dynamic> j) {
    final health = <int, HealthInfo>{};
    (j['health'] as Map).forEach((k, v) {
      final id = int.tryParse('$k');
      if (id != null) health[id] = HealthInfo.fromJson((v as Map).cast<String, dynamic>());
    });
    return Snapshot(
      routes: [
        for (final r in (j['routes'] as List)) RouteInfo.fromJson((r as Map).cast<String, dynamic>()),
      ],
      health: health,
      fetchedAt: DateTime.parse(j['fetched_at'] as String),
    );
  }
}
