import 'dart:async';

import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../storage.dart';

/// Lists IPs the gateway auto-blocked (scanners, rate-limit offenders) and
/// lets you unblock them. Shows the last known list when the gateway is down.
class BlockedScreen extends StatefulWidget {
  const BlockedScreen({super.key, required this.onAuthExpired, required this.onCount});

  final VoidCallback onAuthExpired;

  /// Reports the number of active blocks (for the navigation badge).
  final ValueChanged<int> onCount;

  @override
  State<BlockedScreen> createState() => _BlockedScreenState();
}

class _BlockedScreenState extends State<BlockedScreen> {
  final _storage = Storage();
  late final ApiClient _api = ApiClient(_storage);

  List<BlockedIp>? _list;
  bool _loading = false;
  String? _error; // set when the live fetch failed (list then shows cached data)

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    final cached = await _storage.loadBlocked();
    if (mounted && cached != null) {
      setState(() => _list = _active(cached));
      widget.onCount(_list!.length);
    }
    await _refresh();
  }

  List<BlockedIp> _active(List<BlockedIp> l) {
    final now = DateTime.now();
    return l.where((b) => b.expiresAt.isAfter(now)).toList()
      ..sort((a, b) => b.blockedAt.compareTo(a.blockedAt));
  }

  Future<void> _refresh() async {
    if (_loading) return;
    setState(() => _loading = true);
    try {
      final fresh = await _api.fetchBlocked();
      await _storage.saveBlocked(fresh);
      if (!mounted) return;
      setState(() {
        _list = _active(fresh);
        _error = null;
        _loading = false;
      });
      widget.onCount(_list!.length);
    } on AuthExpiredException {
      widget.onAuthExpired();
    } on ServerUnreachableException catch (e) {
      _fail('Gateway unreachable: ${e.message}');
    } on ApiException catch (e) {
      _fail(e.message);
    } catch (e) {
      _fail('$e');
    }
  }

  void _fail(String message) {
    if (!mounted) return;
    setState(() {
      _loading = false;
      _error = message;
    });
  }

  Future<void> _unblock(BlockedIp b) async {
    try {
      await _api.unblock(b.ip);
      if (!mounted) return;
      setState(() => _list = _list?.where((x) => x.ip != b.ip).toList());
      widget.onCount(_list?.length ?? 0);
      unawaited(_storage.saveBlocked(_list ?? const []));
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('${b.ip} unblocked')));
    } on AuthExpiredException {
      widget.onAuthExpired();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Unblock failed: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final list = _list;

    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.only(bottom: 24),
        children: [
          if (_error != null)
            Container(
              margin: const EdgeInsets.all(12),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: scheme.errorContainer, borderRadius: BorderRadius.circular(12)),
              child: Row(children: [
                Icon(Icons.cloud_off, color: scheme.onErrorContainer),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    list == null ? _error! : '$_error\nShowing last known list',
                    style: TextStyle(color: scheme.onErrorContainer),
                  ),
                ),
              ]),
            ),
          if (list == null && _loading)
            const Padding(padding: EdgeInsets.all(48), child: Center(child: CircularProgressIndicator())),
          if (list != null && list.isEmpty)
            const Padding(
              padding: EdgeInsets.all(40),
              child: Center(
                child: Text(
                  'No blocked IPs.\nScanners are blocked automatically for 24 hours.',
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          if (list != null)
            for (final b in list)
              Dismissible(
                key: ValueKey(b.ip),
                direction: DismissDirection.endToStart,
                background: Container(
                  color: scheme.primary,
                  alignment: Alignment.centerRight,
                  padding: const EdgeInsets.only(right: 20),
                  child: Icon(Icons.lock_open, color: scheme.onPrimary),
                ),
                confirmDismiss: (_) async {
                  await _unblock(b);
                  return false; // _unblock already removes the row from the list
                },
                child: ListTile(
                  leading: Icon(Icons.gpp_bad, color: scheme.error),
                  title: Text(b.ip, style: const TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.w600)),
                  subtitle: Text(
                    '${b.reason}\nBlocked ${_fmt(b.blockedAt)} · expires ${_remaining(b.expiresAt)}',
                    maxLines: 3,
                    overflow: TextOverflow.ellipsis,
                  ),
                  isThreeLine: true,
                  trailing: IconButton(
                    icon: const Icon(Icons.lock_open),
                    tooltip: 'Unblock',
                    onPressed: () => _unblock(b),
                  ),
                ),
              ),
        ],
      ),
    );
  }
}

String _two(int n) => n.toString().padLeft(2, '0');

String _fmt(DateTime t) => '${t.year}-${_two(t.month)}-${_two(t.day)} ${_two(t.hour)}:${_two(t.minute)}';

String _remaining(DateTime t) {
  final d = t.difference(DateTime.now());
  if (d.isNegative) return 'now';
  if (d.inHours >= 1) return 'in ${d.inHours}h ${d.inMinutes % 60}m';
  return 'in ${d.inMinutes}m';
}
