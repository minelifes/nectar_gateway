import 'package:flutter/material.dart';

import '../api_client.dart';
import '../storage.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key, required this.onLoggedIn, this.notice});

  final Future<void> Function() onLoggedIn;
  final String? notice;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _storage = Storage();
  final _url = TextEditingController();
  final _user = TextEditingController();
  final _pass = TextEditingController();
  bool _busy = false;
  bool _obscure = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _prefill();
  }

  Future<void> _prefill() async {
    final url = await _storage.serverUrl();
    final user = await _storage.username();
    if (!mounted) return;
    setState(() {
      if (url != null) _url.text = url;
      if (user != null) _user.text = user;
    });
  }

  @override
  void dispose() {
    _url.dispose();
    _user.dispose();
    _pass.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ApiClient(_storage).login(
        serverUrl: _url.text,
        username: _user.text.trim(),
        password: _pass.text,
      );
      await widget.onLoggedIn();
    } on FormatException catch (e) {
      _fail(e.message);
    } on ServerUnreachableException catch (e) {
      _fail('Cannot reach the server: ${e.message}');
    } on ApiException catch (e) {
      _fail(e.message);
    } catch (e) {
      _fail('$e');
    }
  }

  void _fail(String message) {
    if (!mounted) return;
    setState(() {
      _busy = false;
      _error = message;
    });
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final insecure = _url.text.trim().toLowerCase().startsWith('http://');

    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Center(
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(20),
                      child: Image.asset('assets/icon/logo.png', width: 88, height: 88),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text('Nectar Gateway',
                      textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineSmall),
                  const SizedBox(height: 4),
                  Text('Monitor your backends from your phone',
                      textAlign: TextAlign.center,
                      style: Theme.of(context)
                          .textTheme
                          .bodyMedium
                          ?.copyWith(color: scheme.onSurfaceVariant)),
                  const SizedBox(height: 28),
                  if (widget.notice != null) ...[
                    _Notice(text: widget.notice!, color: scheme.tertiaryContainer, onColor: scheme.onTertiaryContainer),
                    const SizedBox(height: 12),
                  ],
                  TextField(
                    controller: _url,
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    enabled: !_busy,
                    onChanged: (_) => setState(() {}),
                    decoration: const InputDecoration(
                      labelText: 'Admin URL',
                      hintText: 'https://admin.example.com',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.link),
                    ),
                  ),
                  if (insecure) ...[
                    const SizedBox(height: 8),
                    Text(
                      'Plain http:// sends your password and tokens unencrypted. '
                      'Use https:// (e.g. put the admin UI behind a domain in Nectar) unless this is a trusted LAN.',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(color: scheme.error),
                    ),
                  ],
                  const SizedBox(height: 14),
                  TextField(
                    controller: _user,
                    autocorrect: false,
                    enabled: !_busy,
                    autofillHints: const [AutofillHints.username],
                    decoration: const InputDecoration(
                      labelText: 'Username',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.person_outline),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _pass,
                    obscureText: _obscure,
                    enabled: !_busy,
                    autofillHints: const [AutofillHints.password],
                    onSubmitted: (_) => _busy ? null : _submit(),
                    decoration: InputDecoration(
                      labelText: 'Password',
                      border: const OutlineInputBorder(),
                      prefixIcon: const Icon(Icons.lock_outline),
                      suffixIcon: IconButton(
                        icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
                        onPressed: () => setState(() => _obscure = !_obscure),
                      ),
                    ),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 14),
                    _Notice(text: _error!, color: scheme.errorContainer, onColor: scheme.onErrorContainer),
                  ],
                  const SizedBox(height: 20),
                  FilledButton(
                    onPressed: _busy ? null : _submit,
                    style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
                    child: _busy
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Text('Sign in'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _Notice extends StatelessWidget {
  const _Notice({required this.text, required this.color, required this.onColor});

  final String text;
  final Color color;
  final Color onColor;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(8)),
        child: Text(text, style: TextStyle(color: onColor)),
      );
}
