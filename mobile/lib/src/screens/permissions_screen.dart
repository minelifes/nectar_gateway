import 'package:flutter/material.dart';

import '../fast_monitor.dart';
import '../notifier.dart';

/// Checklist of what the app needs to alert you reliably. Re-checks every time
/// the app comes back to the foreground (e.g. after visiting system settings).
class PermissionsScreen extends StatefulWidget {
  const PermissionsScreen({super.key});

  /// True when everything required is already granted.
  static Future<bool> allGranted() async {
    final notif = (await Notifier.isEnabled()) ?? true;
    final battery = !FastMonitor.supported || await FastMonitor.batteryExempt();
    return notif && battery;
  }

  @override
  State<PermissionsScreen> createState() => _PermissionsScreenState();
}

class _PermissionsScreenState extends State<PermissionsScreen> with WidgetsBindingObserver {
  bool? _notif;
  bool? _battery;
  String? _hint;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _check();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _check();
  }

  Future<void> _check() async {
    final n = (await Notifier.isEnabled()) ?? true;
    final b = !FastMonitor.supported || await FastMonitor.batteryExempt();
    if (mounted) {
      setState(() {
        _notif = n;
        _battery = b;
        if (n) _hint = null;
      });
    }
  }

  Future<void> _askNotifications() async {
    final ok = await Notifier.requestPermission();
    await _check();
    if (!ok && mounted) {
      setState(() => _hint =
          'Android no longer shows the prompt. Open Settings → Apps → Nectar → Notifications and turn them on.');
    }
  }

  Future<void> _askBattery() async {
    await FastMonitor.requestBatteryExemption();
    await _check();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final allOk = (_notif ?? false) && (_battery ?? false);

    return Scaffold(
      appBar: AppBar(title: const Text('Permissions')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            color: allOk ? Colors.green.shade800 : scheme.tertiaryContainer,
            child: ListTile(
              leading: Icon(allOk ? Icons.check_circle : Icons.info_outline,
                  color: allOk ? Colors.white : scheme.onTertiaryContainer),
              title: Text(
                allOk ? 'Everything is set' : 'A few permissions are missing',
                style: TextStyle(color: allOk ? Colors.white : scheme.onTertiaryContainer),
              ),
              subtitle: Text(
                allOk
                    ? 'Nectar can alert you even when the app is closed.'
                    : 'Without them alerts can be late or never arrive.',
                style: TextStyle(color: allOk ? Colors.white70 : scheme.onTertiaryContainer),
              ),
            ),
          ),
          const SizedBox(height: 8),
          _Row(
            icon: Icons.notifications_active_outlined,
            title: 'Notifications',
            subtitle: 'Required to show "server down" alerts and the monitoring status.',
            granted: _notif,
            onGrant: _askNotifications,
          ),
          if (FastMonitor.supported)
            _Row(
              icon: Icons.battery_charging_full,
              title: 'Unrestricted battery use',
              subtitle: 'Stops the phone from killing the 60 s monitoring service in the background.',
              granted: _battery,
              onGrant: _askBattery,
            ),
          if (_hint != null)
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 4, 8, 0),
              child: Text(_hint!, style: TextStyle(color: scheme.error)),
            ),
          if (FastMonitor.supported) ...[
            const SizedBox(height: 16),
            Card(
              child: ListTile(
                leading: const Icon(Icons.phone_android),
                title: const Text('Xiaomi, Huawei, Samsung, OnePlus, Oppo…'),
                subtitle: const Text(
                    'These phones have an extra "Autostart" / "Background activity" switch in system settings that '
                    'cannot be checked from the app. Enable it for Nectar, and lock the app in the recent-apps list. '
                    'Details: dontkillmyapp.com'),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _Row extends StatelessWidget {
  const _Row({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.granted,
    required this.onGrant,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final bool? granted; // null while checking
  final VoidCallback onGrant;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: ListTile(
        leading: Icon(icon),
        title: Text(title),
        subtitle: Text(subtitle),
        trailing: granted == null
            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
            : granted!
                ? const Icon(Icons.check_circle, color: Colors.green)
                : FilledButton.tonal(onPressed: onGrant, child: const Text('Allow')),
        isThreeLine: true,
        iconColor: granted == false ? scheme.error : null,
      ),
    );
  }
}
