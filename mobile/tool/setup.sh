#!/usr/bin/env bash
# One-time setup: generates the android/ and ios/ platform folders with
# `flutter create` (without touching lib/ or pubspec.yaml), patches them for
# notifications + background monitoring, and fetches dependencies.
#
#   cd mobile && ./tool/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

#command -v flutter >/dev/null 2>&1 || { echo "flutter is not on PATH - install it from https://docs.flutter.dev/get-started/install"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required for tool/patch_platforms.py"; exit 1; }

if [ ! -d android ] || [ ! -d ios ] || [ ! -d macos ]; then
  echo "Generating platform folders..."
  tmp="$(mktemp -d)"
  fvm flutter create --org dev.nectar --project-name nectar_mobile --platforms=android,ios,macos "$tmp" >/dev/null
  for d in android ios macos; do
    [ -d "$d" ] || cp -R "$tmp/$d" "$d"
  done
  [ -f .gitignore ] || cp "$tmp/.gitignore" .gitignore
  [ -f .metadata ] || cp "$tmp/.metadata" .metadata
  rm -rf "$tmp"
fi

python3 tool/patch_platforms.py .

fvm flutter pub get
echo
echo "Done. Run on a device:  flutter run"
echo "Release APK:            flutter build apk --release"
