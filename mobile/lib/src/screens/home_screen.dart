import 'dart:async';

import 'package:flutter/material.dart';

import '../api_client.dart';
import '../config.dart';
import '../fast_monitor.dart';
import '../models.dart';
import '../monitor.dart';
import '../notifier.dart';
import '../storage.dart';
import 'blocked_screen.dart';
import 'import_nginx_screen.dart';
import 'route_edit_screen.dart';

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
  int _tab = 0; // 0 = domains, 1 = blocked IPs
  int _blockedCount = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _boot();
  }

  Future<void> _boot() async {
    // Show the last known state instantly, then refresh in the background.
    final cached = await _storage.loadSnapshot();
    final cachedBlocked = await _storage.loadBlocked();
    if (mounted) {
      setState(() {
        if (cached != null) _snapshot = cached;
        if (cachedBlocked != null) {
          final now = DateTime.now();
          _blockedCount = cachedBlocked.where((b) => b.expiresAt.isAfter(now)).length;
        }
      });
    }
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

  Future<void> _openSettings() async {
    var fast = await _storage.fastMode();
    var exempt = await FastMonitor.batteryExempt();
    if (!mounted) return;

    await showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSheet) => SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(8, 0, 8, 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                SwitchListTile(
                  value: fast,
                  onChanged: FastMonitor.supported
                      ? (on) async {
                          setSheet(() => fast = on);
                          final ok = await _setFastMode(on);
                          setSheet(() => fast = ok ? on : false);
                        }
                      : null,
                  title: const Text('Fast monitoring (every 60 s)'),
                  subtitle: Text(
                    FastMonitor.supported
                        ? 'Keeps a permanent notification with live status and checks every minute, even when the app is closed. Uses more battery. Off: checks about every 15 minutes.'
                        : 'Android only. iOS decides when background checks run.',
                  ),
                ),
                if (FastMonitor.supported)
                  ListTile(
                    leading: Icon(exempt ? Icons.battery_charging_full : Icons.battery_alert),
                    title: const Text('Unrestricted battery use'),
                    subtitle: Text(exempt
                        ? 'Allowed - the system will not stop monitoring to save power'
                        : 'Recommended, otherwise some phones stop background checks'),
                    trailing: exempt ? null : const Icon(Icons.chevron_right),
                    onTap: exempt
                        ? null
                        : () async {
                            await FastMonitor.requestBatteryExemption();
                            final now = await FastMonitor.batteryExempt();
                            setSheet(() => exempt = now);
                          },
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Returns whether the requested state was reached.
  Future<bool> _setFastMode(bool on) async {
    await _storage.setFastMode(on);
    if (!on) {
      await FastMonitor.stop();
      return true;
    }
    // Android 13+: without this permission the service runs but its notification is hidden.
    await Notifier.requestPermission();
    final running = await FastMonitor.start();
    if (!running) {
      await _storage.setFastMode(false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Could not start the monitoring service')),
        );
      }
    }
    return running;
  }

  Future<void> _openEdit({RouteInfo? route, String? parent}) async {
    final changed = await Navigator.of(context).push<bool>(MaterialPageRoute(
      builder: (_) => RouteEditScreen(
        route: route,
        parentDomain: parent,
        onAuthExpired: () => widget.onSignedOut(notice: 'Your session expired. Please sign in again.'),
      ),
    ));
    if (changed == true && mounted) await _refresh();
  }

  Future<void> _openImport() async {
    final changed = await Navigator.of(context).push<bool>(MaterialPageRoute(
      builder: (_) => ImportNginxScreen(
        onAuthExpired: () => widget.onSignedOut(notice: 'Your session expired. Please sign in again.'),
      ),
    ));
    if (changed == true && mounted) await _refresh();
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
        title: Text(_tab == 0 ? 'Nectar Gateway' : 'Blocked IPs'),
        actions: [
          if (_tab == 0 && _refreshing)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 14),
              child: Center(child: SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))),
            )
          else if (_tab == 0)
            IconButton(icon: const Icon(Icons.refresh), tooltip: 'Refresh', onPressed: _refresh),
          PopupMenuButton<String>(
            onSelected: (v) {
              switch (v) {
                case 'import':
                  _openImport();
                case 'settings':
                  _openSettings();
                case 'signout':
                  _signOut();
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'import', child: ListTile(leading: Icon(Icons.upload_file), title: Text('Import from nginx'))),
              PopupMenuItem(value: 'settings', child: ListTile(leading: Icon(Icons.tune), title: Text('Monitoring settings'))),
              PopupMenuItem(value: 'signout', child: ListTile(leading: Icon(Icons.logout), title: Text('Sign out'))),
            ],
          ),
        ],
      ),
      floatingActionButton: _tab == 0
          ? FloatingActionButton.extended(
              onPressed: () => _openEdit(),
              icon: const Icon(Icons.add),
              label: const Text('Add domain'),
            )
          : null,
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: [
          NavigationDestination(
            icon: Icon(Icons.dns_outlined, color: (_snapshot?.downCount ?? 0) > 0 ? Theme.of(context).colorScheme.error : null),
            selectedIcon: const Icon(Icons.dns),
            label: 'Domains',
          ),
          NavigationDestination(
            icon: Badge(isLabelVisible: _blockedCount > 0, label: Text('$_blockedCount'), child: const Icon(Icons.gpp_bad_outlined)),
            selectedIcon: Badge(isLabelVisible: _blockedCount > 0, label: Text('$_blockedCount'), child: const Icon(Icons.gpp_bad)),
            label: 'Blocked IPs',
          ),
        ],
      ),
      body: _tab == 1
          ? BlockedScreen(
              onAuthExpired: () => widget.onSignedOut(notice: 'Your session expired. Please sign in again.'),
              onCount: (n) {
                if (mounted && n != _blockedCount) setState(() => _blockedCount = n);
              },
            )
          : RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.only(bottom: 88), // room for the FAB
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
          onAddSub: () => _openEdit(parent: parent),
          onEdit: (r) => _openEdit(route: r),
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
  const _GroupTile({
    super.key,
    required this.parent,
    required this.routes,
    required this.snapshot,
    required this.onAddSub,
    required this.onEdit,
  });

  final String parent;
  final List<RouteInfo> routes;
  final Snapshot snapshot;
  final VoidCallback onAddSub;
  final void Function(RouteInfo) onEdit;

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
      trailing: IconButton(
        icon: const Icon(Icons.add_circle_outline),
        tooltip: 'Add subdomain',
        onPressed: onAddSub,
      ),
      children: [for (final r in routes) _RouteTile(route: r, snapshot: snapshot, onTap: () => onEdit(r))],
    );
  }
}

class _RouteTile extends StatelessWidget {
  const _RouteTile({required this.route, required this.snapshot, required this.onTap});

  final RouteInfo route;
  final Snapshot snapshot;
  final VoidCallback onTap;

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
      onTap: onTap,
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
