import 'package:flutter/material.dart';

import 'src/background.dart';
import 'src/fast_monitor.dart';
import 'src/notifier.dart';
import 'src/screens/home_screen.dart';
import 'src/screens/login_screen.dart';
import 'src/storage.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  FastMonitor.initPort();
  await Notifier.init();
  await BackgroundMonitor.init();
  runApp(const NectarApp());
}

class NectarApp extends StatefulWidget {
  const NectarApp({super.key});

  @override
  State<NectarApp> createState() => _NectarAppState();
}

class _NectarAppState extends State<NectarApp> {
  final _storage = Storage();
  bool? _loggedIn; // null while checking
  String? _loginNotice;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    final loggedIn = await _storage.isLoggedIn();
    if (loggedIn) {
      await BackgroundMonitor.schedule(); // make sure the periodic task exists
      await FastMonitor.sync(_storage); // and the 60 s service, if enabled
    }
    if (mounted) setState(() => _loggedIn = loggedIn);
  }

  Future<void> _onLoggedIn() async {
    await Notifier.requestPermission();
    await BackgroundMonitor.schedule();
    await FastMonitor.sync(_storage);
    if (mounted) {
      setState(() {
        _loggedIn = true;
        _loginNotice = null;
      });
    }
  }

  Future<void> _onSignedOut({String? notice}) async {
    await BackgroundMonitor.cancel();
    await FastMonitor.stop();
    if (mounted) {
      setState(() {
        _loggedIn = false;
        _loginNotice = notice;
      });
    }
  }

  ThemeData _theme(Brightness b) => ThemeData(
        useMaterial3: true,
        brightness: b,
        colorSchemeSeed: const Color(0xFFFFB300), // same amber as the web UI
      );

  @override
  Widget build(BuildContext context) {
    final Widget home;
    if (_loggedIn == null) {
      home = const Scaffold(body: Center(child: CircularProgressIndicator()));
    } else if (_loggedIn == true) {
      home = HomeScreen(onSignedOut: _onSignedOut);
    } else {
      home = LoginScreen(onLoggedIn: _onLoggedIn, notice: _loginNotice);
    }

    return MaterialApp(
      title: 'Nectar Gateway',
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: home,
    );
  }
}
