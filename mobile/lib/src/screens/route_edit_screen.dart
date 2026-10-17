import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../storage.dart';

/// Add / edit a domain. Mirrors the web UI dialog.
///
/// - [route] set: edit that domain.
/// - [parentDomain] set (and no route): add a subdomain - only the prefix is typed.
/// - [prefill]: initial values (used by the nginx import).
/// Pops `true` when something changed on the server.
class RouteEditScreen extends StatefulWidget {
  const RouteEditScreen({
    super.key,
    this.route,
    this.parentDomain,
    required this.onAuthExpired,
  });

  final RouteInfo? route;
  final String? parentDomain;
  final Future<void> Function() onAuthExpired;

  @override
  State<RouteEditScreen> createState() => _RouteEditScreenState();
}

class _RouteEditScreenState extends State<RouteEditScreen> {
  final _form = GlobalKey<FormState>();
  late final ApiClient _api = ApiClient(Storage());

  late final TextEditingController _domain;
  late final TextEditingController _ip;
  late final TextEditingController _port;
  late final TextEditingController _staticDir;
  late final TextEditingController _rate;
  late final TextEditingController _cert;
  late final TextEditingController _key;
  late final TextEditingController _hcPath;
  late final TextEditingController _hcInterval;
  late final TextEditingController _hcExpect;

  String _mode = 'proxy';
  bool _https = false;
  bool _forceSsl = false;
  bool _hc = false;
  String _hcType = 'status';
  bool _busy = false;
  String? _error;

  bool get _isEdit => widget.route != null;
  bool get _isSub => !_isEdit && widget.parentDomain != null;

  @override
  void initState() {
    super.initState();
    final r = widget.route?.raw ?? const <String, dynamic>{};
    String s(String k, [String d = '']) => (r[k] as String?) ?? d;
    int n(String k, int d) => (r[k] as num?)?.toInt() ?? d;

    _domain = TextEditingController(text: _isSub ? '' : s('domain'));
    _mode = s('mode', 'proxy') == 'static' ? 'static' : 'proxy';
    _ip = TextEditingController(text: s('target_ip'));
    _port = TextEditingController(text: _isEdit ? '${n('target_port', 80)}' : '80');
    _https = r['target_https'] == true;
    _staticDir = TextEditingController(text: s('static_dir'));
    _rate = TextEditingController(text: '${n('rate_limit', 0)}');
    _cert = TextEditingController(text: s('cert_file'));
    _key = TextEditingController(text: s('key_file'));
    _forceSsl = r['force_ssl'] == true;
    _hc = r['hc_enabled'] == true;
    _hcPath = TextEditingController(text: s('hc_path', '/'));
    _hcInterval = TextEditingController(text: '${n('hc_interval', 30)}');
    _hcType = const ['status', 'contains', 'json'].contains(s('hc_type')) ? s('hc_type') : 'status';
    _hcExpect = TextEditingController(text: s('hc_expect'));
  }

  @override
  void dispose() {
    for (final c in [_domain, _ip, _port, _staticDir, _rate, _cert, _key, _hcPath, _hcInterval, _hcExpect]) {
      c.dispose();
    }
    super.dispose();
  }

  String get _fullDomain {
    final d = _domain.text.trim().toLowerCase();
    return _isSub ? '$d.${widget.parentDomain}' : d;
  }

  Map<String, dynamic> _payload() => {
        'domain': _fullDomain,
        'mode': _mode,
        'target_ip': _mode == 'proxy' ? _ip.text.trim() : '',
        'target_port': _mode == 'proxy' ? int.parse(_port.text.trim()) : 0,
        'target_https': _mode == 'proxy' && _https,
        'static_dir': _mode == 'static' ? _staticDir.text.trim() : '',
        'rate_limit': int.tryParse(_rate.text.trim()) ?? 0,
        'hc_enabled': _hc,
        'hc_path': _hcPath.text.trim(),
        'hc_interval': int.tryParse(_hcInterval.text.trim()) ?? 30,
        'hc_type': _hcType,
        'hc_expect': _hcExpect.text.trim(),
        'cert_file': _cert.text.trim(),
        'key_file': _key.text.trim(),
        'force_ssl': _forceSsl,
      };

  /// Runs [body]; maps API errors to the inline error banner.
  Future<bool> _guard(Future<void> Function() body) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await body();
      return true;
    } on AuthExpiredException {
      if (mounted) Navigator.pop(context, false);
      await widget.onAuthExpired();
    } on ServerUnreachableException catch (e) {
      _fail('Gateway unreachable: ${e.message}');
    } on ApiException catch (e) {
      _fail(e.message);
    } catch (e) {
      _fail('$e');
    }
    return false;
  }

  void _fail(String msg) {
    if (mounted) setState(() => _error = msg);
  }

  /// Saves; returns the saved route (with id) or null.
  Future<Map<String, dynamic>?> _saveRoute() async {
    if (!_form.currentState!.validate()) return null;
    Map<String, dynamic>? saved;
    final ok = await _guard(() async {
      saved = _isEdit
          ? await _api.updateRoute(widget.route!.id, _payload())
          : await _api.createRoute(_payload());
    });
    return ok ? saved : null;
  }

  Future<void> _save({bool issueCert = false}) async {
    final saved = await _saveRoute();
    if (saved == null) {
      if (mounted) setState(() => _busy = false);
      return;
    }
    if (issueCert) {
      final id = (saved['id'] as num).toInt();
      final ok = await _guard(() async {
        final r = await _api.issueCert(id);
        _cert.text = (r['cert_file'] as String?) ?? '';
        _key.text = (r['key_file'] as String?) ?? '';
      });
      if (!ok) {
        // Saved, but certbot failed: stay on the form so the user sees why.
        if (mounted) {
          setState(() {
            _busy = false;
            _error = 'Saved, but certificate failed: ${_error ?? 'unknown error'}';
          });
        }
        return;
      }
    }
    if (mounted) Navigator.pop(context, true);
  }

  Future<void> _delete() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Delete ${widget.route!.domain}?'),
        content: const Text('Requests to this domain will get 410 Gone.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
        ],
      ),
    );
    if (ok != true) return;
    final done = await _guard(() => _api.deleteRoute(widget.route!.id));
    if (done && mounted) Navigator.pop(context, true);
  }

  String? _required(String? v) => (v == null || v.trim().isEmpty) ? 'Required' : null;

  String? _intIn(String? v, int min, int max) {
    final n = int.tryParse((v ?? '').trim());
    if (n == null || n < min || n > max) return '$min-$max';
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final title = _isEdit ? 'Edit domain' : (_isSub ? 'Add subdomain' : 'Add domain');
    final hcHelp = switch (_hcType) {
      'status' => 'Healthy when the response status is 200 (leave blank) or the given code.',
      'contains' => 'Healthy when the response body contains this text.',
      _ => 'field=value; other=value - all must match. Alternatives with |: status=ok|degraded; checks.db=up',
    };

    return Scaffold(
      appBar: AppBar(
        title: Text(title),
        actions: [
          if (_isEdit)
            IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Delete',
              onPressed: _busy ? null : _delete,
            ),
        ],
      ),
      body: AbsorbPointer(
        absorbing: _busy,
        child: Form(
          key: _form,
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (_error != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(color: scheme.errorContainer, borderRadius: BorderRadius.circular(12)),
                  child: Text(_error!, style: TextStyle(color: scheme.onErrorContainer)),
                ),
              TextFormField(
                controller: _domain,
                autocorrect: false,
                enableSuggestions: false,
                keyboardType: TextInputType.url,
                decoration: InputDecoration(
                  labelText: _isSub ? 'Subdomain' : 'Domain',
                  hintText: _isSub ? 'api' : 'example.com',
                  suffixText: _isSub ? '.${widget.parentDomain}' : null,
                  border: const OutlineInputBorder(),
                ),
                validator: _required,
              ),
              const SizedBox(height: 16),
              SegmentedButton<String>(
                segments: const [
                  ButtonSegment(value: 'proxy', label: Text('Proxy'), icon: Icon(Icons.swap_horiz)),
                  ButtonSegment(value: 'static', label: Text('Static files'), icon: Icon(Icons.folder_outlined)),
                ],
                selected: {_mode},
                onSelectionChanged: (s) => setState(() => _mode = s.first),
              ),
              const SizedBox(height: 16),
              if (_mode == 'proxy') ...[
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      flex: 3,
                      child: TextFormField(
                        controller: _ip,
                        autocorrect: false,
                        enableSuggestions: false,
                        keyboardType: TextInputType.url,
                        decoration: const InputDecoration(
                            labelText: 'Target IP / host', hintText: '10.0.0.5', border: OutlineInputBorder()),
                        validator: _required,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      flex: 2,
                      child: TextFormField(
                        controller: _port,
                        keyboardType: TextInputType.number,
                        decoration: const InputDecoration(labelText: 'Port', border: OutlineInputBorder()),
                        validator: (v) => _intIn(v, 1, 65535),
                      ),
                    ),
                  ],
                ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  value: _https,
                  onChanged: (v) => setState(() => _https = v),
                  title: const Text('Backend uses HTTPS'),
                  subtitle: const Text('Connect to the backend over TLS (certificate is not verified)'),
                ),
              ] else
                TextFormField(
                  controller: _staticDir,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(
                    labelText: 'Directory on the server',
                    hintText: '/var/www/site',
                    border: OutlineInputBorder(),
                  ),
                  validator: _required,
                ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _rate,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'Rate limit (requests/sec per IP)',
                  helperText: '0 = unlimited. Exceeding it blocks the IP for 24 h.',
                  border: OutlineInputBorder(),
                ),
                validator: (v) => _intIn(v, 0, 1000000),
              ),
              const SizedBox(height: 20),
              _section(context, 'SSL'),
              TextFormField(
                controller: _cert,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Certificate (fullchain.pem)',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _key,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(labelText: 'Private key (privkey.pem)', border: OutlineInputBorder()),
              ),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: _forceSsl,
                onChanged: (v) => setState(() => _forceSsl = v),
                title: const Text('Force HTTPS'),
                subtitle: const Text('Redirect HTTP to HTTPS'),
              ),
              OutlinedButton.icon(
                onPressed: _busy ? null : () => _save(issueCert: true),
                icon: const Icon(Icons.verified_user_outlined),
                label: Text(_cert.text.isEmpty ? "Save & get Let's Encrypt certificate" : 'Save & renew certificate'),
              ),
              const SizedBox(height: 20),
              _section(context, 'Health check'),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: _hc,
                onChanged: (v) => setState(() => _hc = v),
                title: const Text('Monitor this backend'),
                subtitle: const Text('You get an alert when it goes down'),
              ),
              if (_hc) ...[
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      flex: 3,
                      child: TextFormField(
                        controller: _hcPath,
                        autocorrect: false,
                        enableSuggestions: false,
                        decoration: const InputDecoration(labelText: 'Path', hintText: '/health', border: OutlineInputBorder()),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      flex: 2,
                      child: TextFormField(
                        controller: _hcInterval,
                        keyboardType: TextInputType.number,
                        decoration: const InputDecoration(labelText: 'Every (s)', border: OutlineInputBorder()),
                        validator: (v) => _intIn(v, 5, 86400),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  initialValue: _hcType,
                  decoration: const InputDecoration(labelText: 'Check type', border: OutlineInputBorder()),
                  items: const [
                    DropdownMenuItem(value: 'status', child: Text('HTTP status')),
                    DropdownMenuItem(value: 'contains', child: Text('Body contains text')),
                    DropdownMenuItem(value: 'json', child: Text('JSON field equals')),
                  ],
                  onChanged: (v) => setState(() => _hcType = v ?? 'status'),
                ),
                const SizedBox(height: 12),
                TextFormField(
                  controller: _hcExpect,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: InputDecoration(
                    labelText: 'Expectation',
                    helperText: hcHelp,
                    helperMaxLines: 3,
                    border: const OutlineInputBorder(),
                  ),
                  validator: (v) => _hc && _hcType != 'status' && (v ?? '').trim().isEmpty ? 'Required' : null,
                ),
              ],
              const SizedBox(height: 24),
              FilledButton(
                onPressed: _busy ? null : _save,
                child: _busy
                    ? const SizedBox(height: 20, width: 20, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Text('Save'),
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _section(BuildContext context, String t) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Text(t, style: Theme.of(context).textTheme.titleSmall?.copyWith(color: Theme.of(context).colorScheme.primary)),
      );
}
