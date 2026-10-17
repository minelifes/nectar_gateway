/// Background task identifier. On iOS it must also be listed in
/// Info.plist -> BGTaskSchedulerPermittedIdentifiers (tool/setup.sh does it).
const String kTaskId = 'dev.nectar.monitor';

const String kAlertChannelId = 'nectar_alerts';
const String kAlertChannelName = 'Outage alerts';

/// Per-request network timeout.
const Duration kRequestTimeout = Duration(seconds: 10);

/// Refresh the access token this long before it actually expires.
const Duration kAccessTokenSkew = Duration(seconds: 60);

/// Foreground auto-refresh period while the app is open.
const Duration kForegroundPoll = Duration(seconds: 20);

/// Check period of the optional Android foreground service ("fast monitoring").
const Duration kFastInterval = Duration(seconds: 60);
const int kFastServiceId = 4711;

/// Notification ids. A "recovered" notification reuses the id of its "down"
/// notification, so it replaces it instead of stacking.
const int kServerAlertId = 1;
const int kAuthAlertId = 2;
const int kRouteAlertBase = 1000;
