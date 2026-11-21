"""Textless cover for the Policy Warden article: a policy sheet, three nested shield
layers, and a grid of resources with a few flagged under a magnifying glass.

    python3 docs/make_cover.py

Writes docs/devto-cover.<hash>.jpg (1376x578) and docs/builder-cover.<hash>.jpg
(1200x675), drawn at 2x and downsampled, named by a hash of their bytes.
"""

from __future__ import annotations

import hashlib
import io
import pathlib

from PIL import Image, ImageDraw

OUT = pathlib.Path(__file__).resolve().parent
SURFACE = (26, 26, 25)
PAPER = (236, 233, 222)
RULE = (58, 58, 55)
MUTED = (128, 127, 120)
BLUE = (57, 135, 229)
ORANGE = (217, 89, 38)


def sheet(d, x, y, w, h, s):
    """The policy: a page with ruled lines, each with a tick box."""
    d.rounded_rectangle([x, y, x + w, y + h], radius=14 * s, fill=PAPER)
    d.polygon([(x + w - 34 * s, y), (x + w, y + 34 * s), (x + w - 34 * s, y + 34 * s)], fill=(205, 201, 188))
    rows = 5
    gap = (h - 70 * s) / rows
    for i in range(rows):
        ry = y + 48 * s + i * gap
        b = 16 * s
        d.rounded_rectangle([x + 26 * s, ry, x + 26 * s + b, ry + b], radius=3 * s, outline=BLUE, width=3 * s)
        d.line([(x + 30 * s, ry + b * 0.55), (x + 26 * s + b * 0.45, ry + b - 4 * s), (x + 26 * s + b - 3 * s, ry + 3 * s)],
               fill=BLUE, width=3 * s)
        length = w - (80 + (i * 37) % 60) * s
        d.rounded_rectangle([x + 56 * s, ry + 4 * s, x + 56 * s + length - 40 * s, ry + 12 * s], radius=4 * s, fill=MUTED)


def shields(d, cx, cy, s):
    """Three nested shield outlines: the layers a request passes through."""
    for i, (scale, colour, width) in enumerate([(1.0, RULE, 10), (0.78, MUTED, 9), (0.56, BLUE, 9)]):
        w, h = 150 * s * scale, 190 * s * scale
        top = cy - h * 0.55
        pts = [
            (cx - w / 2, top + 18 * s * scale),
            (cx, top),
            (cx + w / 2, top + 18 * s * scale),
            (cx + w / 2, top + h * 0.48),
            (cx, top + h),
            (cx - w / 2, top + h * 0.48),
        ]
        d.line(pts + [pts[0]], fill=colour, width=width * s, joint="curve")
    d.ellipse([cx - 10 * s, cy - 10 * s, cx + 10 * s, cy + 10 * s], fill=BLUE)


def resources(d, x, y, s, flagged):
    """A grid of resource cubes; flagged ones are outlined orange."""
    size, gap = 54 * s, 18 * s
    for r in range(4):
        for c in range(5):
            bx, by = x + c * (size + gap), y + r * (size + gap)
            hit = (r, c) in flagged
            d.rounded_rectangle([bx, by, bx + size, by + size], radius=10 * s,
                                fill=(44, 44, 42), outline=ORANGE if hit else RULE, width=(6 if hit else 3) * s)
            d.line([(bx + 12 * s, by + 18 * s), (bx + size - 12 * s, by + 18 * s)], fill=ORANGE if hit else MUTED, width=4 * s)


def glass(d, cx, cy, r, s):
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=PAPER, width=10 * s)
    d.line([(cx + r * 0.7, cy + r * 0.7), (cx + r * 1.45, cy + r * 1.45)], fill=PAPER, width=18 * s)


def flow(d, x1, x2, y, s, colour):
    for x in range(int(x1), int(x2), int(22 * s)):
        d.ellipse([x - 4 * s, y - 4 * s, x + 4 * s, y + 4 * s], fill=colour)


def draw(width, height):
    s = 2
    W, H = width * s, height * s
    img = Image.new("RGB", (W, H), SURFACE)
    d = ImageDraw.Draw(img)
    u = H / 578 / s  # layout unit relative to the dev.to height
    cy = H / 2
    sx, sw, sh = W * 0.07, 230 * s * u, 290 * s * u
    sheet(d, sx, cy - sh / 2, sw, sh, round(s * u) or 1)
    gx = W * 0.58
    sheet_right = sx + sw
    scx = (sheet_right + gx) / 2  # shield centred between the policy and the resources
    shields(d, scx, cy + 12 * s * u, round(s * u) or 1)
    flagged = {(0, 3), (1, 1), (2, 4), (3, 0), (3, 2)}
    grid_h = 4 * 54 * s * u + 3 * 18 * s * u
    resources(d, gx, cy - grid_h / 2, round(s * u) or 1, flagged)
    flow(d, sheet_right + 24 * s * u, scx - 95 * s * u, cy, s, BLUE)
    flow(d, scx + 95 * s * u, gx - 18 * s * u, cy, s, BLUE)
    glass(d, gx + 1 * 72 * s * u + 27 * s * u, cy - grid_h / 2 + 1 * 72 * s * u + 27 * s * u, 58 * s * u, round(s * u) or 1)
    return img.resize((width, height), Image.LANCZOS)


def save(img, stem):
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90, optimize=True)
    data = buf.getvalue()
    name = f"{stem}.{hashlib.sha256(data).hexdigest()[:8]}.jpg"
    (OUT / name).write_bytes(data)
    print(f"wrote {name} {img.size[0]}x{img.size[1]} {len(data) // 1024} KB")


if __name__ == "__main__":
    save(draw(1376, 578), "devto-cover")
    save(draw(1200, 675), "builder-cover")
