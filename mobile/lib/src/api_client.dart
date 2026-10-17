import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'config.dart';
import 'models.dart';
import 'storage.dart';

/// The refresh token was rejected (or there is no session). The user has to
/// sign in again. This is the ONLY condition that ends the session.
class AuthExpiredException implements Exception {
  @override
  String toString() => 'Session expired';
}

/// Network-level failure: DNS, refused, timeout, TLS. The server may be down.
class ServerUnreachableException implements Exception {
  ServerUnreachableException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// The server answered with an error status.
class ApiException implements Exception {
  ApiException(this.status, this.message);
  final int status;
  final String message;
  @override
  String toString() => message;
}

/// HTTP client for the Nectar admin API with transparent token refresh:
///
/// - the access token (15 min) is refreshed proactively shortly before expiry;
/// - a 401 triggers one refresh + retry (covers a server restart that wiped
///   its in-memory access tokens);
/// - concurrent requests share a single in-flight refresh;
/// - a network failure during refresh NEVER logs the user out - only an
///   explicit rejection of the refresh token does.
class ApiClient {
  ApiClient(this._storage, {http.Client? client}) : _http = client ?? http.Client();

  final Storage _storage;
  final http.Client _http;

  static Future<void>? _refreshing;

  // ---- public API ----

  static String normalizeUrl(String input) {
    var u = input.trim();
    if (u.isEmpty) throw const FormatException('Server URL is required');
    if (!u.contains('://')) u = 'https://$u';
    while (u.endsWith('/')) {
      u = u.substring(0, u.length - 1);
    }
    final uri = Uri.tryParse(u);
    if (uri == null || uri.host.isEmpty) throw const FormatException('Invalid server URL');
    return u;
  }

  Future<void> login({
    required String serverUrl,
    required String username,
    required String password,
  }) async {
    final base = normalizeUrl(serverUrl);
    final res = await _raw('POST', Uri.parse('$base/api/auth/login'),
        body: {'username': username, 'password': password});
    if (res.statusCode != 200) throw ApiException(res.statusCode, _errorMessage(res));
    try {
      final j = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
      await _storage.saveServer(base, username);
      await _storage.saveTokens(
        access: j['access_token'] as String,
        refresh: j['refresh_token'] as String,
        expiresInSeconds: (j['expires_in'] as num).toInt(),
      );
    } on FormatException {
      throw ApiException(0, 'Unexpected response - is this the Nectar admin URL, and is the backend up to date?');
    } on TypeError {
      throw ApiException(0, 'Unexpected response - is this the Nectar admin URL, and is the backend up to date?');
    }
  }

  /// Best-effort server-side revoke, then wipe everything local.
  Future<void> logout() async {
    try {
      final tokens = await _storage.loadTokens();
      if (tokens != null) {
        await _raw('POST', await _uri('/api/auth/logout'),
            body: {'refresh_token': tokens.refresh},
            headers: tokens.access == null ? null : {'Authorization': 'Bearer ${tokens.access}'});
      }
    } catch (_) {
      // offline logout is fine - local state is wiped regardless
    }
    await _storage.clearAll();
  }

  /// Fetches routes + health in parallel and returns a fresh snapshot.
  Future<Snapshot> fetchSnapshot() async {
    final results = await Future.wait<dynamic>([
      _getJson('/api/routes'),
      _getJson('/api/health'),
    ]);
    return Snapshot.fromApi(
      results[0] as List<dynamic>,
      (results[1] as Map).cast<String, dynamic>(),
      DateTime.now(),
    );
  }

  // ---- internals ----

  Future<dynamic> _getJson(String path) async {
    await _ensureFresh();
    var res = await _raw('GET', await _uri(path), headers: await _authHeader());
    if (res.statusCode == 401) {
      await _refresh();
      res = await _raw('GET', await _uri(path), headers: await _authHeader());
    }
    if (res.statusCode >= 400) throw ApiException(res.statusCode, _errorMessage(res));
    try {
      return jsonDecode(utf8.decode(res.bodyBytes));
    } on FormatException {
      throw ApiException(res.statusCode, 'Server returned invalid JSON');
    }
  }

  Future<void> _ensureFresh() async {
    final t = await _storage.loadTokens();
    if (t == null) throw AuthExpiredException();
    final stale = t.access == null || DateTime.now().add(kAccessTokenSkew).isAfter(t.accessExpiresAt);
    if (stale) await _refresh();
  }

  /// Single-flight refresh shared by every concurrent caller in this isolate.
  Future<void> _refresh() => _refreshing ??= _doRefresh().whenComplete(() => _refreshing = null);

  Future<void> _doRefresh() async {
    final tokens = await _storage.loadTokens();
    if (tokens == null) throw AuthExpiredException();

    final res = await _raw('POST', await _uri('/api/auth/refresh'),
        body: {'refresh_token': tokens.refresh});

    if (res.statusCode == 200) {
      final j = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
      await _storage.saveTokens(
        access: j['access_token'] as String,
        refresh: (j['refresh_token'] as String?) ?? tokens.refresh,
        expiresInSeconds: (j['expires_in'] as num).toInt(),
      );
      return;
    }
    if (res.statusCode == 401 || res.statusCode == 400) {
      await _storage.clearTokens();
      throw AuthExpiredException();
    }
    // 5xx etc: transient, keep the session
    throw ApiException(res.statusCode, _errorMessage(res));
  }

  Future<Map<String, String>> _authHeader() async {
    final t = await _storage.loadTokens();
    if (t == null || t.access == null) throw AuthExpiredException();
    return {'Authorization': 'Bearer ${t.access}'};
  }

  Future<Uri> _uri(String path) async {
    final base = await _storage.serverUrl();
    if (base == null || base.isEmpty) throw AuthExpiredException();
    return Uri.parse('$base$path');
  }

  Future<http.Response> _raw(
    String method,
    Uri uri, {
    Map<String, String>? headers,
    Object? body,
  }) async {
    final req = http.Request(method, uri)..headers['Accept'] = 'application/json';
    if (body != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(body);
    }
    if (headers != null) req.headers.addAll(headers);
    try {
      final streamed = await _http.send(req).timeout(kRequestTimeout);
      return await http.Response.fromStream(streamed).timeout(kRequestTimeout);
    } on TimeoutException {
      throw ServerUnreachableException('Timed out');
    } on SocketException catch (e) {
      throw ServerUnreachableException(e.message.isEmpty ? 'Connection failed' : e.message);
    } on TlsException catch (e) {
      throw ServerUnreachableException('TLS error: ${e.message}');
    } on http.ClientException catch (e) {
      throw ServerUnreachableException(e.message);
    }
  }

  String _errorMessage(http.Response res) {
    try {
      final j = jsonDecode(utf8.decode(res.bodyBytes));
      if (j is Map && j['error'] is String) return j['error'] as String;
    } catch (_) {}
    return 'HTTP ${res.statusCode}';
  }
}
