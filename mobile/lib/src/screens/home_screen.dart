import 'dart:async';

import 'package:flutter/material.dart';

import '../api_client.dart';
import '../config.dart';
import '../models.dart';
import '../monitor.dart';
import '../notifier.dart';
import '../storage.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.onSignedOut});

  /// Called after sign-out or when the session can no longer be refreshed.
  final Future<void> Function({String? notice}) onSignedOut;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  final _storage = Storage();

  Snapshot? _snapshot; // last known data (cached first, then live)
  bool _fromCache = true;
  CheckStatus _status = CheckStatus.ok;
  String? _message;
  bool _refreshing = false;
  bool? _notifEnabled;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _boot();
  }

  Future<void> _boot() async {
    // Show the last known state instantly, then refresh in the background.
    final cached = await _storage.loadSnapshot();
    if (mounted && cached != null) setState(() => _snapshot = cached);
    _startTimer();
    unawaited(_checkNotifications());
    await _refresh();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _timer?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _startTimer();
      unawaited(_checkNotifications());
      unawaited(_refresh());
    } else if (state == AppLifecycleState.paused) {
      _timer?.cancel(); // the WorkManager task takes over while closed
    }
  }

  void _startTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(kForegroundPoll, (_) => _refresh());
  }

  Future<void> _checkNotifications() async {
    final enabled = await Notifier.isEnabled();
    if (mounted) setState(() => _notifEnabled = enabled);
  }

  Future<void> _refresh() async {
    if (_refreshing) return;
    if (mounted) setState(() => _refreshing = true);

    CheckResult r;
    try {
      r = await Monitor.run(failureThreshold: 2);
    } catch (e) {
      // e.g. the URL points at something that is not a Nectar admin API
      r = CheckResult(CheckStatus.serverError, message: '$e');
    }
    if (!mounted) return;

    if (r.status == CheckStatus.authExpired || r.status == CheckStatus.notLoggedIn) {
      await widget.onSignedOut(notice: 'Your session expired. Please sign in again.');
      return;
    }
    setState(() {
      _refreshing = false;
      _status = r.status;
      _message = r.message;
      if (r.snapshot != null) {
        _snapshot = r.snapshot; // on failure we keep showing the last known data
        _fromCache = false;
      }
    });
  }

  Future<void> _enableNotifications() async {
    final granted = await Notifier.requestPermission();
    if (!mounted) return;
    setState(() => _notifEnabled = granted ? true : _notifEnabled);
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(granted
          ? 'Alerts enabled'
          : 'Permission denied - allow notifications for Nectar in system settings'),
    ));
  }

  Future<void> _signOut() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sign out?'),
        content: const Text('Background monitoring and alerts will stop on this device.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Sign out')),
        ],
      ),
    );
    if (ok != true) return;
    await ApiClient(_storage).logout();
    await widget.onSignedOut();
  }

  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final snap = _snapshot;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Nectar Gateway'),
        actions: [
          if (_refreshing)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 14),
              child: Center(child: SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))),
            )
          else
            IconButton(icon: const Icon(Icons.refresh), tooltip: 'Refresh', onPressed: _refresh),
          IconButton(icon: const Icon(Icons.logout), tooltip: 'Sign out', onPressed: _signOut),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.only(bottom: 24),
          children: [
            _StatusBanner(snapshot: snap, status: _status, message: _message, fromCache: _fromCache, refreshing: _refreshing),
            if (_notifEnabled == false) _NotificationsBanner(onEnable: _enableNotifications),
            if (snap != null) ..._groups(snap),
            if (snap != null && snap.routes.isEmpty)
              const Padding(
                padding: EdgeInsets.all(32),
                child: Center(child: Text('No domains configured on the gateway.')),
              ),
          ],
        ),
      ),
    );
  }

  List<Widget> _groups(Snapshot snap) {
    final groups = <String, List<RouteInfo>>{};
    for (final r in snap.routes) {
      groups.putIfAbsent(r.parent, () => []).add(r);
    }
    int downIn(String p) => groups[p]!.where(snap.isDown).length;

    // problems first, then alphabetical
    final parents = groups.keys.toList()
      ..sort((a, b) {
        final d = downIn(b).compareTo(downIn(a));
        return d != 0 ? d : a.compareTo(b);
      });

    return [
      for (final parent in parents)
        _GroupTile(
          key: PageStorageKey<String>(parent),
          parent: parent,
          routes: (groups[parent]!
            ..sort((a, b) {
              final d = (snap.isDown(b) ? 1 : 0).compareTo(snap.isDown(a) ? 1 : 0);
              return d != 0 ? d : a.domain.compareTo(b.domain);
            })),
          snapshot: snap,
        ),
    ];
  }
}

// -----------------------------------------------------------------------------

class _StatusBanner extends StatelessWidget {
  const _StatusBanner({
    required this.snapshot,
    required this.status,
    required this.message,
    required this.fromCache,
    required this.refreshing,
  });

  final Snapshot? snapshot;
  final CheckStatus status;
  final String? message;
  final bool fromCache;
  final bool refreshing;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final snap = snapshot;

    Color bg;
    Color fg;
    IconData icon;
    String title;
    String? sub;

    switch (status) {
      case CheckStatus.serverUnreachable:
        bg = scheme.errorContainer;
        fg = scheme.onErrorContainer;
        icon = Icons.cloud_off;
        title = 'Gateway unreachable';
        sub = message;
      case CheckStatus.offline:
        bg = scheme.surfaceContainerHighest;
        fg = scheme.onSurface;
        icon = Icons.wifi_off;
        title = 'You are offline';
        sub = 'Showing last known data';
      case CheckStatus.serverError:
        bg = scheme.errorContainer;
        fg = scheme.onErrorContainer;
        icon = Icons.error_outline;
        title = 'Server error';
        sub = message;
      case CheckStatus.ok:
      case CheckStatus.authExpired:
      case CheckStatus.notLoggedIn:
        if (snap == null) {
          bg = scheme.surfaceContainerHighest;
          fg = scheme.onSurface;
          icon = Icons.hourglass_empty;
          title = refreshing ? 'Loading…' : 'No data yet';
          sub = null;
        } else if (snap.downCount > 0) {
          bg = scheme.errorContainer;
          fg = scheme.onErrorContainer;
          icon = Icons.warning_amber_rounded;
          title = '${snap.downCount} backend${snap.downCount == 1 ? '' : 's'} down';
          sub = '${snap.monitoredCount} monitored';
        } else {
          bg = Colors.green.shade800;
          fg = Colors.white;
          icon = Icons.check_circle_outline;
          title = 'All systems operational';
          sub = snap.monitoredCount == 0
              ? 'No backends have health checks enabled'
              : '${snap.monitoredCount} backend${snap.monitoredCount == 1 ? '' : 's'} monitored';
        }
    }

    final updated = snap == null ? null : 'Updated ${_ago(snap.fetchedAt)}${fromCache ? ' (cached)' : ''}';
    final subtitle = [
      if (sub != null && sub.isNotEmpty) sub,
      if (updated != null) updated,
    ].join(' · ');

    return Container(
      margin: const EdgeInsets.all(12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(16)),
      child: Row(
        children: [
          Icon(icon, color: fg, size: 34),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: Theme.of(context).textTheme.titleMedium?.copyWith(color: fg, fontWeight: FontWeight.w600)),
                if (subtitle.isNotEmpty)
                  Text(subtitle, style: Theme.of(context).textTheme.bodySmall?.copyWith(color: fg.withValues(alpha: 0.85))),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _NotificationsBanner extends StatelessWidget {
  const _NotificationsBanner({required this.onEnable});
  final VoidCallback onEnable;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      margin: const EdgeInsets.fromLTRB(12, 0, 12, 8),
      color: scheme.tertiaryContainer,
      child: ListTile(
        leading: Icon(Icons.notifications_off, color: scheme.onTertiaryContainer),
        title: Text('Alerts are off', style: TextStyle(color: scheme.onTertiaryContainer)),
        subtitle: Text('Enable notifications to get told when something goes down',
            style: TextStyle(color: scheme.onTertiaryContainer)),
        trailing: TextButton(onPressed: onEnable, child: const Text('Enable')),
      ),
    );
  }
}

class _GroupTile extends StatelessWidget {
  const _GroupTile({super.key, required this.parent, required this.routes, required this.snapshot});

  final String parent;
  final List<RouteInfo> routes;
  final Snapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final down = routes.where(snapshot.isDown).length;

    return ExpansionTile(
      initiallyExpanded: true,
      leading: Icon(Icons.language, color: down > 0 ? scheme.error : scheme.primary),
      title: Text(parent, style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text(
        down > 0 ? '$down of ${routes.length} down' : '${routes.length} domain${routes.length == 1 ? '' : 's'}',
        style: TextStyle(color: down > 0 ? scheme.error : null),
      ),
      children: [for (final r in routes) _RouteTile(route: r, snapshot: snapshot)],
    );
  }
}

class _RouteTile extends StatelessWidget {
  const _RouteTile({required this.route, required this.snapshot});

  final RouteInfo route;
  final Snapshot snapshot;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final health = snapshot.health[route.id];
    final down = snapshot.isDown(route);

    Color dot;
    String subtitle;
    if (!route.hcEnabled) {
      dot = Colors.grey;
      subtitle = '${route.targetLabel} · not monitored';
    } else if (health?.up == true) {
      dot = Colors.green;
      subtitle = route.targetLabel;
    } else if (down) {
      dot = scheme.error;
      subtitle = (health?.lastError.isNotEmpty ?? false) ? health!.lastError : 'Health check failed';
    } else {
      dot = Colors.grey;
      subtitle = '${route.targetLabel} · waiting for first check';
    }

    return ListTile(
      dense: true,
      contentPadding: const EdgeInsets.only(left: 24, right: 16),
      leading: Container(
        width: 12,
        height: 12,
        decoration: BoxDecoration(color: dot, shape: BoxShape.circle),
      ),
      title: Text(route.domain),
      subtitle: Text(subtitle, maxLines: 2, overflow: TextOverflow.ellipsis, style: TextStyle(color: down ? scheme.error : null)),
      trailing: route.hasSsl ? const Icon(Icons.lock, size: 16, color: Colors.green) : null,
    );
  }
}

String _ago(DateTime t) {
  final d = DateTime.now().difference(t);
  if (d.inSeconds < 10) return 'just now';
  if (d.inSeconds < 60) return '${d.inSeconds}s ago';
  if (d.inMinutes < 60) return '${d.inMinutes}m ago';
  if (d.inHours < 24) return '${d.inHours}h ago';
  return '${t.year}-${t.month.toString().padLeft(2, '0')}-${t.day.toString().padLeft(2, '0')}';
}
