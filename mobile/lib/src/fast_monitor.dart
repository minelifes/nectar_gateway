import 'dart:io';

import 'package:flutter_foreground_task/flutter_foreground_task.dart';

import 'config.dart';
import 'monitor.dart';
import 'notifier.dart';
import 'storage.dart';

/// Entry point of the foreground-service isolate.
@pragma('vm:entry-point')
void fastMonitorCallback() {
  FlutterForegroundTask.setTaskHandler(FastMonitorHandler());
}

/// Runs a full check every [kFastInterval] and mirrors the result in the
/// service's persistent notification ("All OK · checked 12:03").
class FastMonitorHandler extends TaskHandler {
  bool _busy = false;

  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {
    await Notifier.init();
    await _tick();
  }

  @override
  void onRepeatEvent(DateTime timestamp) {
    _tick();
  }

  @override
  Future<void> onDestroy(DateTime timestamp, bool isTimeout) async {}

  Future<void> _tick() async {
    if (_busy) return; // never overlap checks
    _busy = true;
    try {
      // 3 attempts 5 s apart: a single blip must not raise an alert.
      final r = await Monitor.run(
        attempts: 3,
        retryDelay: const Duration(seconds: 5),
        inBackground: true,
      );

      if (r.status == CheckStatus.authExpired || r.status == CheckStatus.notLoggedIn) {
        await FlutterForegroundTask.stopService(); // signed out: nothing left to monitor
        return;
      }
      final (title, text) = _describe(r);
      await FlutterForegroundTask.updateService(notificationTitle: title, notificationText: text);
    } catch (_) {
      // keep the service alive; the next tick retries
    } finally {
      _busy = false;
    }
  }

  (String, String) _describe(CheckResult r) {
    final now = DateTime.now();
    final hm = '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}';
    switch (r.status) {
      case CheckStatus.ok:
        final s = r.snapshot!;
        if (s.downCount > 0) {
          final names = s.routes.where(s.isDown).map((x) => x.domain).take(3).join(', ');
          return ('${s.downCount} backend${s.downCount == 1 ? '' : 's'} down', '$names · checked $hm');
        }
        return ('Nectar: all systems operational', '${s.monitoredCount} monitored · checked $hm');
      case CheckStatus.serverUnreachable:
        return ('Nectar: gateway unreachable', '${r.message ?? 'no response'} · checked $hm');
      case CheckStatus.offline:
        return ('Nectar: waiting for connection', 'No internet · checked $hm');
      case CheckStatus.serverError:
        return ('Nectar: server error', '${r.message ?? ''} · checked $hm');
      case CheckStatus.authExpired:
      case CheckStatus.notLoggedIn:
        return ('Nectar', 'Signed out');
    }
  }
}

/// Controls the optional Android foreground service ("fast monitoring").
///
/// WorkManager cannot run more often than every 15 minutes; a foreground
/// service can, at the price of a permanent notification and more battery.
/// Both run: if the vendor kills the service, WorkManager still covers you.
class FastMonitor {
  static bool get supported => Platform.isAndroid;

  /// Why the last start() failed (shown to the user).
  static String? lastError;

  /// Call once from main(), before runApp.
  static void initPort() {
    if (supported) FlutterForegroundTask.initCommunicationPort();
  }

  static void _init() {
    FlutterForegroundTask.init(
      androidNotificationOptions: AndroidNotificationOptions(
        channelId: 'nectar_fast_monitor',
        channelName: 'Fast monitoring',
        channelDescription: 'Shows that Nectar is checking your servers every minute.',
        onlyAlertOnce: true,
      ),
      iosNotificationOptions: const IOSNotificationOptions(showNotification: false, playSound: false),
      foregroundTaskOptions: ForegroundTaskOptions(
        eventAction: ForegroundTaskEventAction.repeat(kFastInterval.inMilliseconds),
        autoRunOnBoot: true, // come back after a reboot
        autoRunOnMyPackageReplaced: true, // ...and after an app update
        allowWakeLock: true, // needed so the timer fires with the screen off
        allowWifiLock: true,
      ),
    );
  }

  static Future<bool> isRunning() async => supported && await FlutterForegroundTask.isRunningService;

  /// Starts (or restarts) the service. Returns whether it is running afterwards.
  static Future<bool> start() async {
    if (!supported) return false;
    _init();
    lastError = null;
    try {
      final ServiceRequestResult r;
      if (await FlutterForegroundTask.isRunningService) {
        r = await FlutterForegroundTask.restartService();
      } else {
        r = await FlutterForegroundTask.startService(
          serviceId: kFastServiceId,
          notificationTitle: 'Nectar monitor',
          notificationText: 'Starting…',
          callback: fastMonitorCallback,
        );
      }
      if (r is ServiceRequestFailure) lastError = '${r.error}';
    } catch (e) {
      lastError = '$e';
    }
    return FlutterForegroundTask.isRunningService;
  }

  static Future<void> stop() async {
    if (supported && await FlutterForegroundTask.isRunningService) {
      await FlutterForegroundTask.stopService();
    }
  }

  /// Makes the service survive aggressive battery optimization.
  static Future<void> requestBatteryExemption() async {
    if (!supported) return;
    if (!await FlutterForegroundTask.isIgnoringBatteryOptimizations) {
      await FlutterForegroundTask.requestIgnoreBatteryOptimization();
    }
  }

  static Future<bool> batteryExempt() async =>
      supported && await FlutterForegroundTask.isIgnoringBatteryOptimizations;

  /// Brings the service in line with the saved setting (used after login/boot).
  static Future<void> sync(Storage storage) async {
    if (!supported) return;
    if (await storage.fastMode()) {
      if (!await isRunning()) await start();
    } else {
      await stop();
    }
  }
}
