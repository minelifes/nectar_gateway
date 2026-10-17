import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import 'config.dart';

/// Thin wrapper around flutter_local_notifications, usable from both the UI
/// isolate and the background (WorkManager) isolate.
class Notifier {
  static final FlutterLocalNotificationsPlugin _plugin = FlutterLocalNotificationsPlugin();
  static bool _ready = false;

  static Future<void> init() async {
    if (_ready) return;
    const android = AndroidInitializationSettings('@mipmap/ic_launcher');
    const ios = DarwinInitializationSettings(
      // permissions are requested explicitly after login, not at startup
      requestAlertPermission: false,
      requestBadgePermission: false,
      requestSoundPermission: false,
    );
    await _plugin.initialize(
      settings: const InitializationSettings(android: android, iOS: ios),
    );
    await _plugin
        .resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>()
        ?.createNotificationChannel(
          const AndroidNotificationChannel(
            kAlertChannelId,
            kAlertChannelName,
            description: 'Alerts when the gateway or one of your backends goes down',
            importance: Importance.max,
          ),
        );
    _ready = true;
  }

  /// Asks for notification permission (Android 13+ / iOS). Returns whether granted.
  static Future<bool> requestPermission() async {
    await init();
    final android =
        _plugin.resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();
    if (android != null) {
      return await android.requestNotificationsPermission() ?? false;
    }
    final ios = _plugin.resolvePlatformSpecificImplementation<IOSFlutterLocalNotificationsPlugin>();
    if (ios != null) {
      return await ios.requestPermissions(alert: true, badge: true, sound: true) ?? false;
    }
    return false;
  }

  /// Android: whether notifications are currently allowed. Other platforms: null (unknown).
  static Future<bool?> isEnabled() async {
    await init();
    final android =
        _plugin.resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();
    if (android != null) return android.areNotificationsEnabled();
    return null;
  }

  static Future<void> show({
    required int id,
    required String title,
    required String body,
  }) async {
    await init();
    final details = NotificationDetails(
      android: AndroidNotificationDetails(
        kAlertChannelId,
        kAlertChannelName,
        channelDescription: 'Alerts when the gateway or one of your backends goes down',
        importance: Importance.max,
        priority: Priority.high,
        styleInformation: BigTextStyleInformation(body),
      ),
      iOS: const DarwinNotificationDetails(
        presentAlert: true,
        presentBadge: true,
        presentSound: true,
      ),
    );
    await _plugin.show(id: id, title: title, body: body, notificationDetails: details);
  }
}
