#!/usr/bin/env python3
"""Render a terminal transcript (e.g. `tmux capture-pane -p`) into a
dark-terminal PNG.

Theme matches opencsvnet's site: #0d1117 background, #e6edf3 text,
#f7931a accents (prompts, anchor txids, audit lines), green VERIFIED,
red REJECTED, subtle border. Rendered at 2x and downscaled with LANCZOS
for crisp text.

Usage:
  render-terminal.py [--input FILE] [--output FILE] [--width PX]
  tmux capture-pane -p | render-terminal.py -o shot.png

Defaults: stdin → stdout-required --output; --width 1322 (minimum image
width in px; widens automatically if a line would overflow).
"""

import argparse
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

BG = "#0d1117"
FG = "#e6edf3"
MUTED = "#9da7b3"
ACCENT = "#f7931a"
GREEN = "#3fb950"
RED = "#f85149"
BORDER = "#30363d"

SCALE = 2
FONT_PX = 16 * SCALE
PAD = 28 * SCALE
LINE_LEAD = 7 * SCALE

# Shell prompt prefixes that get the accent color.
PROMPTS = ("issuer $ ", "bob $ ", "alice $ ")

FONT_CANDIDATES = {
    "regular": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/local/share/fonts/DejaVuSansMono.ttf",
    ],
    "bold": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/local/share/fonts/DejaVuSansMono-Bold.ttf",
    ],
}


def find_font(kind):
    import os

    for path in FONT_CANDIDATES[kind]:
        if os.path.exists(path):
            return path
    if shutil.which("fc-match"):
        query = "DejaVu Sans Mono:style=Book" if kind == "regular" else "DejaVu Sans Mono:style=Bold"
        out = subprocess.run(
            ["fc-match", "-f", "%{file}", query],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if out:
            return out
    sys.exit(f"error: no monospace font found for {kind} (tried {FONT_CANDIDATES[kind]} + fc-match)")


def line_segments(line):
    """[(text, color, bold)] for one transcript line."""
    for p in PROMPTS:
        if line.startswith(p):
            return [(p, ACCENT, True), (line[len(p):], FG, False)]
    head = line.strip()
    if head.startswith("VERIFIED"):
        return [(line, GREEN, True)]
    if head.startswith("REJECTED"):
        return [(line, RED, True)]
    if head.startswith(("anchor broadcast", "supply ", "asset ")):
        return [(line, ACCENT, True)]
    if '"confirmations"' in line or '"txid"' in line:
        return [(line, ACCENT, False)]
    if head.startswith(("proving", "verifying", "stored ", "coin ", "consignment ",
                        "tip ", "key 0", "#")):
        return [(line, MUTED, False)]
    return [(line, FG, False)]


def render(text, out_path, min_width):
    lines = [l.rstrip() for l in text.splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        sys.exit("error: empty transcript")

    font = ImageFont.truetype(find_font("regular"), FONT_PX)
    bold = ImageFont.truetype(find_font("bold"), FONT_PX)
    asc, desc = font.getmetrics()
    line_h = asc + desc + LINE_LEAD

    probe = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    max_w = max(probe.textlength(line, font=font) for line in lines)
    w = max(int(max_w + 2 * PAD), (min_width - 4) * SCALE)
    h = int(line_h * len(lines) + 2 * PAD - LINE_LEAD)

    img = Image.new("RGB", (w + 4 * SCALE, h + 4 * SCALE), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle(
        [SCALE, SCALE, w + 3 * SCALE - 1, h + 3 * SCALE - 1],
        radius=12 * SCALE,
        outline=BORDER,
        width=2 * SCALE,
    )
    y = 2 * SCALE + PAD
    for line in lines:
        x = 2 * SCALE + PAD
        for text_seg, color, is_bold in line_segments(line):
            f = bold if is_bold else font
            d.text((x, y), text_seg, font=f, fill=color)
            x += d.textlength(text_seg, font=f)
        y += line_h

    img = img.resize((img.width // SCALE, img.height // SCALE), Image.LANCZOS)
    img.save(out_path)
    print(f"{out_path}: {img.width}x{img.height}, {len(lines)} lines", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", "-i", help="transcript file (default: stdin)")
    ap.add_argument("--output", "-o", required=True, help="PNG output path")
    ap.add_argument("--width", type=int, default=1322,
                    help="minimum image width in px (default: 1322; auto-widens to fit)")
    args = ap.parse_args()

    if args.input:
        with open(args.input) as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    render(text, args.output, args.width)


if __name__ == "__main__":
    main()
