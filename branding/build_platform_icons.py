#!/usr/bin/env python3
"""Generates every platform icon from the master design in build_icons.py and
writes them straight into the project (android/, ios/, macos/, web).

Run from anywhere:  python3 branding/build_platform_icons.py
Needs: pip install cairosvg pillow
"""
import io
import os

import cairosvg
from PIL import Image, ImageChops

import build_icons as b  # also refreshes the PNGs in branding/

ROOT = os.path.abspath(os.path.join(b.HERE, ".."))
MOBILE = os.path.join(ROOT, "mobile")
UI = os.path.join(ROOT, "ui")


def render(svg_text, size):
    png = cairosvg.svg2png(bytestring=svg_text.encode(), output_width=size, output_height=size)
    return Image.open(io.BytesIO(png)).convert("RGBA")


def save(img, path, flat=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if flat:  # no alpha (iOS requirement)
        img = img.convert("RGB")
    img.save(path)


# ---- source images (rendered once at 1024, downscaled with LANCZOS) ----
IOS = render(b.svg(b.SQUARE_BG), 1024)                      # square, OS applies the mask
ROUND = render(b.svg(b.ROUND_BG), 1024)                     # rounded tile (legacy android / web)
ANDROID_FG = render(b.svg("", 0.9), 1024)                   # adaptive foreground (safe zone)
ANDROID_BG = render(b.svg(b.SQUARE_BG.replace('<rect width="1024" height="1024" fill="url(#glow)"/>', '')).replace(b.MARK, ''), 1024)

# macOS icons are a rounded tile with ~10% transparent margin (Big Sur+ template)
MAC = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
inner = ROUND.resize((824, 824), Image.LANCZOS)
MAC.paste(inner, (100, 100), inner)

# monochrome silhouette for Android 13 themed icons (alpha only)
SIL = '<g fill="#fff">' + b.MARK.split("<g>")[1].split("</g>")[0] + "</g>"
def mono():
    shapes = (
        '<rect x="120" y="500" width="170" height="38" rx="19"/><rect x="160" y="573" width="130" height="38" rx="19"/>'
        '<rect x="120" y="646" width="170" height="38" rx="19"/>'
        '<path d="M512 250 C566 336 730 466 730 598 A218 218 0 0 1 294 598 C294 466 458 336 512 250 Z"/>'
    )
    stroke = 'fill="none" stroke="#fff" stroke-width="40" stroke-linecap="round" stroke-linejoin="round"'
    wrap = lambda body: (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">'
                         f'<g transform="translate(512 512) scale(0.9) translate(-512 -512)">{body}</g></svg>')
    a = render(wrap(f'<g fill="#fff">{shapes}</g><path d="M770 540 L830 598 L770 656" {stroke}/>'), 1024)
    cut = render(wrap('<path d="M440 520 L520 598 L440 676" %s/><path d="M540 520 L620 598 L540 676" %s/>' % (stroke, stroke)), 1024)
    alpha = ImageChops.subtract(a.getchannel("A"), cut.getchannel("A"))
    out = Image.new("RGBA", a.size, (255, 255, 255, 0))
    out.putalpha(alpha)
    return out
MONO = mono()

def scaled(img, px):
    return img.resize((px, px), Image.LANCZOS)

written = []
def put(img, rel, px, flat=False):
    p = os.path.join(rel)
    save(scaled(img, px), p, flat)
    written.append(os.path.relpath(p, ROOT))

# ---------------------------------------------------------------- iOS
ios_dir = os.path.join(MOBILE, "ios/Runner/Assets.xcassets/AppIcon.appiconset")
if os.path.isdir(ios_dir):
    import re
    for f in os.listdir(ios_dir):
        m = re.match(r"Icon-App-([\d.]+)x[\d.]+@(\d)x\.png", f)
        if m:
            put(IOS, os.path.join(ios_dir, f), round(float(m.group(1)) * int(m.group(2))), flat=True)

# ---------------------------------------------------------------- macOS
mac_dir = os.path.join(MOBILE, "macos/Runner/Assets.xcassets/AppIcon.appiconset")
if os.path.isdir(mac_dir):
    for px in (16, 32, 64, 128, 256, 512, 1024):
        put(MAC, os.path.join(mac_dir, f"app_icon_{px}.png"), px)

# ---------------------------------------------------------------- Android
res = os.path.join(MOBILE, "android/app/src/main/res")
if os.path.isdir(res):
    legacy = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
    adaptive = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
    for d, px in legacy.items():
        put(ROUND, os.path.join(res, f"mipmap-{d}/ic_launcher.png"), px)
    for d, px in adaptive.items():
        put(ANDROID_FG, os.path.join(res, f"drawable-{d}/ic_launcher_foreground.png"), px)
        put(ANDROID_BG, os.path.join(res, f"drawable-{d}/ic_launcher_background.png"), px)
        put(MONO, os.path.join(res, f"drawable-{d}/ic_launcher_monochrome.png"), px)
    anydpi = os.path.join(res, "mipmap-anydpi-v26")
    os.makedirs(anydpi, exist_ok=True)
    with open(os.path.join(anydpi, "ic_launcher.xml"), "w") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@drawable/ic_launcher_background"/>\n'
                '    <foreground android:drawable="@drawable/ic_launcher_foreground"/>\n'
                '    <monochrome android:drawable="@drawable/ic_launcher_monochrome"/>\n'
                '</adaptive-icon>\n')
    written.append("mobile/android/.../mipmap-anydpi-v26/ic_launcher.xml")
    # Play Store listing icon
    put(ROUND, os.path.join(MOBILE, "assets/icon/play-store-512.png"), 512)

# ---------------------------------------------------------------- Web (admin UI)
pub = os.path.join(UI, "public")
dist = os.path.join(UI, "dist")
for out in (pub, dist):
    if not os.path.isdir(out):
        continue
    put(ROUND, os.path.join(out, "icon-192.png"), 192)
    put(ROUND, os.path.join(out, "icon-512.png"), 512)
    put(IOS, os.path.join(out, "apple-touch-icon.png"), 180, flat=True)
    # maskable: full-bleed square with the mark inside the 80% safe zone
    mask = render(b.svg(b.SQUARE_BG).replace(b.MARK, ""), 1024)  # background only
    fg = scaled(ANDROID_FG, 820)
    mask.paste(fg, (102, 102), fg)
    put(mask, os.path.join(out, "icon-maskable-512.png"), 512)
    with open(os.path.join(out, "favicon.svg"), "w") as f:
        f.write(b.svg(b.ROUND_BG))
    sizes = [16, 32, 48]
    scaled(ROUND, 256).save(os.path.join(out, "favicon.ico"), sizes=[(s, s) for s in sizes])
    with open(os.path.join(out, "site.webmanifest"), "w") as f:
        f.write('{\n  "name": "Nectar Gateway",\n  "short_name": "Nectar",\n  "start_url": "/",\n  "display": "standalone",\n'
                '  "background_color": "#15151b",\n  "theme_color": "#FFB300",\n  "icons": [\n'
                '    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},\n'
                '    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},\n'
                '    {"src": "/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}\n  ]\n}\n')
    written.append(os.path.relpath(out, ROOT) + "/ (favicon.ico/svg, apple-touch, pwa icons, manifest)")

print("wrote:")
for w in written:
    print(" ", w)
