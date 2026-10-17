#!/usr/bin/env python3
"""Renders the Nectar Proxy icon set from the SVG below (needs: pip install cairosvg pillow)."""
import os
import cairosvg
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))

DEFS = """
<defs>
  <linearGradient id="amber" x1="0.2" y1="0" x2="0.8" y2="1">
    <stop offset="0" stop-color="#FFF03A"/><stop offset="0.45" stop-color="#FFB300"/><stop offset="1" stop-color="#F57200"/>
  </linearGradient>
  <linearGradient id="trail" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#FFB300" stop-opacity="0"/><stop offset="1" stop-color="#FFC21A" stop-opacity="1"/>
  </linearGradient>
  <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#1D1D26"/><stop offset="1" stop-color="#101014"/>
  </linearGradient>
  <radialGradient id="glow" cx="0.5" cy="0.55" r="0.5">
    <stop offset="0" stop-color="#FF9A00" stop-opacity="0.28"/><stop offset="1" stop-color="#FF9A00" stop-opacity="0"/>
  </radialGradient>
</defs>"""

# the mark: nectar drop + traffic flowing through it (many requests in, one out)
MARK = """
<g>
  <!-- incoming request lanes (fade in from the left) -->
  <rect x="120" y="500" width="170" height="38" rx="19" fill="url(#trail)"/>
  <rect x="160" y="573" width="130" height="38" rx="19" fill="url(#trail)"/>
  <rect x="120" y="646" width="170" height="38" rx="19" fill="url(#trail)"/>
  <!-- the drop -->
  <path d="M512 250 C566 336 730 466 730 598 A218 218 0 0 1 294 598 C294 466 458 336 512 250 Z" fill="url(#amber)"/>
  <path d="M512 250 C566 336 730 466 730 598 A218 218 0 0 1 512 816 C640 790 700 700 690 590 C680 480 590 380 512 250 Z" fill="#E86400" opacity="0.28"/>
  <!-- traffic passing through the drop -->
  <path d="M440 520 L520 598 L440 676" fill="none" stroke="#2A1600" stroke-width="40" stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/>
  <path d="M540 520 L620 598 L540 676" fill="none" stroke="#2A1600" stroke-width="40" stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/>
  <!-- highlight -->
  <ellipse cx="404" cy="430" rx="18" ry="58" transform="rotate(32 404 430)" fill="#FFFFFF" opacity="0.5"/>
  <!-- outgoing response -->
  <path d="M770 540 L830 598 L770 656" fill="none" stroke="#FFB300" stroke-width="40" stroke-linecap="round" stroke-linejoin="round"/>
</g>"""

def svg(bg, scale=1.0):
    body = MARK if scale == 1 else f'<g transform="translate(512 512) scale({scale}) translate(-512 -512)">{MARK}</g>'
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">{DEFS}{bg}{body}</svg>'

SQUARE_BG = '<rect width="1024" height="1024" fill="url(#bg)"/><rect width="1024" height="1024" fill="url(#glow)"/>'
ROUND_BG = '<rect x="0" y="0" width="1024" height="1024" rx="230" fill="url(#bg)"/><rect width="1024" height="1024" rx="230" fill="url(#glow)"/>'

def out(name, s, size):
    p = os.path.join(HERE, name)
    cairosvg.svg2png(bytestring=s.encode(), write_to=p, output_width=size, output_height=size)
    return p

# master SVGs
open(os.path.join(HERE, "nectar-icon.svg"), "w").write(svg(ROUND_BG))
open(os.path.join(HERE, "nectar-mark.svg"), "w").write(svg(""))

out("icon-rounded-1024.png", svg(ROUND_BG), 1024)             # presentation / store listing
ios = out("icon-ios-1024.png", svg(SQUARE_BG), 1024)           # iOS: square, no alpha (OS rounds it)
Image.open(ios).convert("RGB").save(ios)
out("icon-android-foreground.png", svg("", 0.9), 1024)          # adaptive foreground, inside the safe zone
out("icon-android-background.png", svg(SQUARE_BG.replace('<rect width="1024" height="1024" fill="url(#glow)"/>', '')).replace(MARK, ''), 1024)
out("icon-android-legacy-512.png", svg(ROUND_BG), 512)
out("favicon-512.png", svg(ROUND_BG), 512)
for n in (32, 192):
    out(f"favicon-{n}.png", svg(ROUND_BG), n)
print("ok")
