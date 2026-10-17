import 'dart:ui';

import 'package:flutter/widgets.dart';
import 'package:workmanager/workmanager.dart';

import 'config.dart';
import 'monitor.dart';
import 'notifier.dart';

/// Entry point of the background isolate. Runs every ~15 min (Android minimum;
/// iOS decides on its own) even when the app is closed.
@pragma('vm:entry-point')
void callbackDispatcher() {
  Workmanager().executeTask((task, inputData) async {
    WidgetsFlutterBinding.ensureInitialized();
    DartPluginRegistrant.ensureInitialized();
    try {
      await Notifier.init();
      // 3 attempts, 10s apart: one network blip must not wake you up at night.
      await Monitor.run(attempts: 3, retryDelay: const Duration(seconds: 10), inBackground: true);
    } catch (_) {
      // never fail the task: the periodic schedule retries on its own
    }
    return true;
  });
}

class BackgroundMonitor {
  static Future<void> init() => Workmanager().initialize(callbackDispatcher);

  static Future<void> schedule() async {
    await Workmanager().registerPeriodicTask(
      kTaskId,
      kTaskId,
      frequency: const Duration(minutes: 15),
      constraints: Constraints(networkType: NetworkType.connected),
      existingWorkPolicy: ExistingPeriodicWorkPolicy.keep,
    );
  }

  static Future<void> cancel() => Workmanager().cancelByUniqueName(kTaskId);
}
