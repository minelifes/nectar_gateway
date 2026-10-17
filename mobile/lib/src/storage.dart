import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'models.dart';
import 'monitor.dart' show MonitorState;

class AuthTokens {
  const AuthTokens({required this.refresh, this.access, required this.accessExpiresAt});

  final String refresh;
  final String? access;
  final DateTime accessExpiresAt;
}

/// Persistent storage shared by the UI isolate and the background isolate.
///
/// - tokens           -> flutter_secure_storage (Keychain / Keystore)
/// - everything else  -> SharedPreferencesAsync (no per-isolate cache, so the
///                       foreground and background isolates always agree)
class Storage {
  Storage();

  static final FlutterSecureStorage _secure = FlutterSecureStorage();
  static final SharedPreferencesAsync _prefs = SharedPreferencesAsync();

  static const _kUrl = 'server_url';
  static const _kUser = 'username';
  static const _kAccess = 'access_token';
  static const _kAccessExp = 'access_expires_ms';
  static const _kRefresh = 'refresh_token';
  static const _kSnapshot = 'snapshot';
  static const _kMonitor = 'monitor_state';

  // ---- server ----

  Future<String?> serverUrl() => _prefs.getString(_kUrl);
  Future<String?> username() => _prefs.getString(_kUser);

  Future<void> saveServer(String url, String username) async {
    await _prefs.setString(_kUrl, url);
    await _prefs.setString(_kUser, username);
  }

  // ---- tokens ----

  Future<bool> isLoggedIn() async => (await _secure.read(key: _kRefresh)) != null;

  Future<AuthTokens?> loadTokens() async {
    final refresh = await _secure.read(key: _kRefresh);
    if (refresh == null) return null;
    final access = await _secure.read(key: _kAccess);
    final expMs = int.tryParse(await _secure.read(key: _kAccessExp) ?? '');
    return AuthTokens(
      refresh: refresh,
      access: (access == null || access.isEmpty) ? null : access,
      accessExpiresAt: DateTime.fromMillisecondsSinceEpoch(expMs ?? 0),
    );
  }

  Future<void> saveTokens({
    required String access,
    required String refresh,
    required int expiresInSeconds,
  }) async {
    final exp = DateTime.now().add(Duration(seconds: expiresInSeconds)).millisecondsSinceEpoch;
    await _secure.write(key: _kRefresh, value: refresh);
    await _secure.write(key: _kAccess, value: access);
    await _secure.write(key: _kAccessExp, value: '$exp');
  }

  /// Drops the tokens (session ended) but keeps the server URL for the login form.
  Future<void> clearTokens() async {
    await _secure.delete(key: _kRefresh);
    await _secure.delete(key: _kAccess);
    await _secure.delete(key: _kAccessExp);
  }

  /// Full sign-out: tokens plus all cached data and monitor state.
  Future<void> clearAll() async {
    await clearTokens();
    await _prefs.remove(_kSnapshot);
    await _prefs.remove(_kMonitor);
  }

  // ---- cached last-known data ----

  Future<void> saveSnapshot(Snapshot s) => _prefs.setString(_kSnapshot, jsonEncode(s.toJson()));

  Future<Snapshot?> loadSnapshot() async {
    final raw = await _prefs.getString(_kSnapshot);
    if (raw == null) return null;
    try {
      return Snapshot.fromJson((jsonDecode(raw) as Map).cast<String, dynamic>());
    } catch (_) {
      return null; // corrupt/old cache format - just refetch
    }
  }

  // ---- monitor state (what we already notified about) ----

  Future<MonitorState> loadMonitorState() async {
    final raw = await _prefs.getString(_kMonitor);
    if (raw == null) return const MonitorState();
    try {
      return MonitorState.fromJson((jsonDecode(raw) as Map).cast<String, dynamic>());
    } catch (_) {
      return const MonitorState();
    }
  }

  Future<void> saveMonitorState(MonitorState s) => _prefs.setString(_kMonitor, jsonEncode(s.toJson()));
}
