import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api_client.dart';
import '../models.dart';
import '../storage.dart';

/// Paste an nginx config, preview what will be imported, then import.
/// Pops `true` when routes were created.
class ImportNginxScreen extends StatefulWidget {
  const ImportNginxScreen({super.key, required this.onAuthExpired});
  final Future<void> Function() onAuthExpired;

  @override
  State<ImportNginxScreen> createState() => _ImportNginxScreenState();
}

class _ImportNginxScreenState extends State<ImportNginxScreen> {
  final _api = ApiClient(Storage());
  final _config = TextEditingController();
  ImportResult? _preview;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _config.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final d = await Clipboard.getData(Clipboard.kTextPlain);
    if (d?.text != null) {
      setState(() {
        _config.text = d!.text!;
        _preview = null;
      });
    }
  }

  Future<void> _run({required bool dryRun}) async {
    if (_config.text.trim().isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final r = await _api.importNginx(_config.text, dryRun: dryRun);
      if (!mounted) return;
      if (dryRun) {
        setState(() => _preview = r);
      } else {
        Navigator.pop(context, r.routes.isNotEmpty);
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Imported ${r.routes.length} domain${r.routes.length == 1 ? '' : 's'}'
              '${r.skipped.isEmpty ? '' : ' (${r.skipped.length} skipped)'}'),
        ));
        return;
      }
    } on AuthExpiredException {
      if (mounted) Navigator.pop(context, false);
      await widget.onAuthExpired();
      return;
    } on ServerUnreachableException catch (e) {
      _error = 'Gateway unreachable: ${e.message}';
    } on ApiException catch (e) {
      _error = e.message;
    } catch (e) {
      _error = '$e';
    }
    if (mounted) setState(() => _busy = false);
  }

  String _target(Map<String, dynamic> r) {
    if (r['mode'] == 'static') return 'static: ${r['static_dir'] ?? ''}';
    return '${r['target_https'] == true ? 'https://' : ''}${r['target_ip']}:${r['target_port']}';
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final p = _preview;
    return Scaffold(
      appBar: AppBar(title: const Text('Import from nginx')),
      body: AbsorbPointer(
        absorbing: _busy,
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
            TextField(
              controller: _config,
              minLines: 8,
              maxLines: 14,
              autocorrect: false,
              enableSuggestions: false,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              onChanged: (_) => setState(() => _preview = null),
              decoration: const InputDecoration(
                labelText: 'nginx config',
                hintText: 'server { server_name example.com; location / { proxy_pass http://10.0.0.5:3000; } }',
                alignLabelWithHint: true,
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                TextButton.icon(onPressed: _paste, icon: const Icon(Icons.content_paste), label: const Text('Paste')),
                const Spacer(),
                FilledButton.tonal(
                  onPressed: _busy || _config.text.trim().isEmpty ? null : () => _run(dryRun: true),
                  child: const Text('Preview'),
                ),
              ],
            ),
            if (_busy) const Padding(padding: EdgeInsets.all(16), child: Center(child: CircularProgressIndicator())),
            if (p != null) ...[
              const Divider(height: 32),
              Text('${p.routes.length} domain${p.routes.length == 1 ? '' : 's'} found',
                  style: Theme.of(context).textTheme.titleMedium),
              for (final r in p.routes)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                  title: Text('${r['domain']}'),
                  subtitle: Text(_target(r)),
                  trailing: (r['cert_file'] ?? '') != ''
                      ? Tooltip(
                          message: 'SSL${r['force_ssl'] == true ? ' + force HTTPS' : ''}',
                          child: const Icon(Icons.lock, size: 16, color: Colors.green),
                        )
                      : null,
                ),
              if (p.skipped.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text('Skipped', style: Theme.of(context).textTheme.titleSmall?.copyWith(color: scheme.error)),
                for (final s in p.skipped) Text('• $s', style: Theme.of(context).textTheme.bodySmall),
              ],
              const SizedBox(height: 16),
              FilledButton(
                onPressed: _busy || p.routes.isEmpty ? null : () => _run(dryRun: false),
                child: Text('Import ${p.routes.length}'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
