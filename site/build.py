#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""Write site/index.html: the page (site/page.html) with the figures drawn here.

  python3 -I site/build.py           write site/index.html
  python3 -I site/build.py --check   fail when index.html is not what this writes

The figures are fixed-layout SVG, drawn with code: text positions are stated, the rope is a path
sampled into strands. Every number on the page marked data-measure is checked against the tree.
"""
import ast
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SPDX = "<!-- Written by site/build.py from site/page.html. Copyright and license: REUSE.toml. -->\n"


# ---------------------------------------------------------------- rope

def arc(cx, cy, r, a0, a1, n=None):
    n = n or max(6, int(abs(a1 - a0) / 6))
    return [(cx + r * math.cos(math.radians(a0 + (a1 - a0) * i / n)),
             cy + r * math.sin(math.radians(a0 + (a1 - a0) * i / n))) for i in range(n + 1)]


def bez(p0, p1, p2, p3, n=48):
    out = []
    for i in range(n + 1):
        t, u = i / n, 1 - i / n
        out.append(tuple(u**3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t**3 * d for a, b, c, d in zip(p0, p1, p2, p3)))
    return out


def path_d(pts):
    return "M" + "L".join(f"{x:.1f} {y:.1f}" for x, y in pts)


def along(pts, step, start=0.0):
    """Points every `step` along the line, with the unit tangent there."""
    out, want, run = [], start, 0.0
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        seg = math.hypot(x1 - x0, y1 - y0)
        if seg == 0:
            continue
        while want <= run + seg:
            t = (want - run) / seg
            out.append((x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, (x1 - x0) / seg, (y1 - y0) / seg))
            want += step
        run += seg
    return out


def rope(pts, w, cls="rope"):
    """A laid rope: a dark edge, a body, and one S-shaped strand line every half width."""
    d = path_d(pts)
    h, strands = w * 0.40, []
    for x, y, tx, ty in along(pts, w * 0.62, w * 0.3):
        nx, ny = -ty, tx
        a = (x - nx * h - tx * h * 0.75, y - ny * h - ty * h * 0.75)
        b = (x + nx * h + tx * h * 0.75, y + ny * h + ty * h * 0.75)
        c1 = (x - nx * h * 0.2 - tx * h * 0.9, y - ny * h * 0.2 - ty * h * 0.9)
        c2 = (x + nx * h * 0.2 + tx * h * 0.9, y + ny * h * 0.2 + ty * h * 0.9)
        strands.append(f"M{a[0]:.1f} {a[1]:.1f}C{c1[0]:.1f} {c1[1]:.1f} {c2[0]:.1f} {c2[1]:.1f} {b[0]:.1f} {b[1]:.1f}")
    return (f'<g class="{cls}"><path class="r0" d="{d}" stroke-width="{w:g}"/><path class="r1" d="{d}" stroke-width="{w * .82:.1f}"/>'
            f'<path class="r2" d="{"".join(strands)}" stroke-width="{max(1.2, w * .13):.1f}"/></g>')


def frayed(x, y, dx, w):
    """The cut end of a rope running along x; dx is +1 or -1."""
    out = []
    for i in range(5):
        t = (i - 2) / 2
        out.append(f"M{x:.1f} {y + t * w * .3:.1f}q{dx * w * .7:.1f} {t * w * .1:.1f} {dx * w * (1.25 - abs(t) * .3):.1f} {t * w * .85:.1f}")
    return f'<path class="fray" d="{"".join(out)}" stroke-width="{max(1.6, w * .16):.1f}"/>'


def wordmark():
    """goatrope, in one rope per stroke. x-height 80, baseline 120."""
    r, base, w = 36, 126, 20
    cy = base - r
    parts, x = [], 14

    def bowl(cx):
        return arc(cx, cy, r, 0, 360, 60)

    def stem(sx, y0, y1):
        return [(sx, y0), (sx, y1)]
    letters = []
    for ch in "goatrope":
        if ch == "g":
            c = x + r
            letters.append([bowl(c), stem(c + r, cy - r - 2, base + 14) + arc(c, base + 14, r, 0, 140)])
            x += 2 * r + 30
        elif ch == "o":
            letters.append([bowl(x + r)])
            x += 2 * r + 27
        elif ch == "a":
            c = x + r
            letters.append([bowl(c), stem(c + r, cy - r - 2, base + 8)])
            x += 2 * r + 26
        elif ch == "t":
            c = x + 30
            letters.append([stem(c, cy - r - 36, base - 18) + arc(c + 20, base - 18, 20, 180, 70), [(c - 22, cy - r + 4), (c + 28, cy - r + 4)]])
            x += 84
        elif ch == "r":
            letters.append([stem(x, cy - r - 2, base + 8), arc(x + 30, cy - 4, 30, 180, 312)])
            x += 72
        elif ch == "p":
            c = x + r
            letters.append([stem(x, cy - r - 2, base + 52), bowl(c)])
            x += 2 * r + 27
        elif ch == "e":
            c = x + r
            letters.append([[(c - r, cy + 2), (c + r, cy + 2)] + arc(c, cy, r, 2, -270, 48)
                           + bez((c, base), (c + 24, base), (c + 46, base + 2), (c + 70, base + 2), 20)
                           + bez((c + 70, base + 2), (c + 190, base + 2), (c + 240, base - 64), (c + 420, base - 64), 40)
                           + bez((c + 420, base - 64), (c + 600, base - 64), (c + 700, base - 8), (c + 2400, base - 8), 60)])
            x += 2 * r + 24
    for strokes in letters:
        for s in strokes:
            parts.append(rope(s, w))
    width = x - 6
    return (f'<svg class="wordmark" viewBox="0 8 {width:.0f} 186" role="img" aria-label="goatrope">{"".join(parts)}</svg>')


# ---------------------------------------------------------------- small drawing helpers

def text(x, y, s, cls="t", anchor="start"):
    return f'<text x="{x:g}" y="{y:g}" class="{cls}" text-anchor="{anchor}">{s}</text>'


def box(x, y, w, h, cls, rx=6):
    return f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{rx:g}" class="{cls}"/>'


def line(x0, y0, x1, y1, cls="wire"):
    return f'<path class="{cls}" d="M{x0:g} {y0:g}L{x1:g} {y1:g}"/>'


def packet(d, dur, begin=0.0, rev=False):
    keys = ' keyPoints="1;0" keyTimes="0;1" calcMode="linear"' if rev else ""
    return f'<circle class="pkt{" back" if rev else ""}" r="6"><animateMotion dur="{dur}s" begin="{-begin - .05:.2f}s" repeatCount="indefinite"{keys} path="{d}"/></circle>'


def ring(x, y, w):
    return f'<ellipse class="ring" cx="{x:g}" cy="{y:g}" rx="{w * .5:g}" ry="{w * 1.25:g}"/><ellipse class="ring2" cx="{x:g}" cy="{y:g}" rx="{w * .26:g}" ry="{w * .85:g}"/>'


# ---------------------------------------------------------------- figures

ALT_WORM = ("A controller site and two sensor sites, each with a goatrope machine, joined by one rope per sensor site. "
            "On the controller's link, goatrope answers at 192.0.2.101 for sensor 1 and 192.0.2.102 for sensor 2. "
            "Both sensor sites use 198.51.100.0/24; on each, goatrope answers at 198.51.100.200 for the controller.")


def worm_wide():
    o = [f'<svg class="fig wide" viewBox="0 0 1152 452" role="img" aria-label="{ALT_WORM}">']
    o += [box(2, 2, 396, 448, "site", 12), text(24, 36, "Controller site", "h"), text(24, 58, "192.0.2.0/24", "m")]
    o += [box(24, 192, 132, 76, "node"), text(90, 224, "controller", "b", "middle"), text(90, 246, "192.0.2.10", "m", "middle")]
    o += [line(188, 84, 188, 426), line(156, 230, 188, 230)]
    o += [box(222, 84, 154, 342, "gr"), text(299, 112, "goatrope", "b on", "middle")]
    for y, a, n in ((164, "101", "1"), (330, "102", "2")):
        o += [line(188, y, 236, y), box(236, y - 30, 126, 60, "ghost"), text(299, y - 5, f"192.0.2.{a}", "m", "middle"),
              text(299, y + 15, f"is sensor {n} here", "s", "middle")]
    for k, (y0, n) in enumerate(((2, "1"), (234, "2"))):
        o += [box(754, y0, 396, 216, "site", 12), text(1130, y0 + 34, f"Sensor site {n}", "h", "end"), text(1130, y0 + 56, "198.51.100.0/24", "m", "end")]
        c = y0 + 128
        o += [box(768, y0 + 60, 170, 136, "gr"), text(853, y0 + 86, "goatrope", "b on", "middle")]
        o += [box(780, c - 25, 146, 60, "ghost"), text(853, c, "198.51.100.200", "m", "middle"), text(853, c + 20, "is the controller", "s", "middle")]
        o += [line(964, y0 + 66, 964, y0 + 196), line(926, c + 5, 964, c + 5), line(964, c + 5, 996, c + 5)]
        o += [box(996, c - 33, 132, 76, "node"), text(1062, c - 1, f"sensor {n}", "b", "middle"), text(1062, c + 21, "198.51.100.10", "m", "middle")]
    ropes = [bez((376, 164), (520, 164), (620, 135), (768, 135)), bez((376, 330), (520, 330), (620, 367), (768, 367))]
    for p in ropes:
        o += [rope(p, 17)]
    for x, y in ((376, 164), (376, 330), (768, 135), (768, 367)):
        o += [ring(x, y, 22)]
    for i, p in enumerate(ropes):
        o += [packet(path_d(p), 3.2, i * .7), packet(path_d(p), 3.2, 1.6 + i * .7, True)]
    o += [text(576, 206, "one WireGuard tunnel per pair", "b", "middle"), text(576, 230, "only the declared addresses,", "s", "middle"),
          text(576, 250, "ports and directions cross", "s", "middle")]
    return "".join(o) + "</svg>"


def worm_narrow():
    o = [f'<svg class="fig narrow" viewBox="0 0 358 560" role="img" aria-label="{ALT_WORM}">']
    o += [box(1, 1, 356, 232, "site", 10), text(16, 28, "Controller site", "h"), text(342, 28, "192.0.2.0/24", "m", "end")]
    o += [box(113, 44, 132, 56, "node"), text(179, 68, "controller", "b", "middle"), text(179, 88, "192.0.2.10", "m", "middle")]
    o += [line(24, 118, 334, 118), line(179, 100, 179, 118)]
    o += [box(16, 136, 326, 86, "gr"), text(179, 158, "goatrope", "b on", "middle")]
    for cx, a, n in ((91, "101", "1"), (267, "102", "2")):
        o += [line(cx, 118, cx, 166), box(cx - 66, 166, 132, 46, "ghost"), text(cx, 186, f"192.0.2.{a}", "m", "middle"), text(cx, 203, f"is sensor {n} here", "s", "middle")]
    ropes = [bez((91, 222), (91, 270), (84, 280), (84, 330)), bez((267, 222), (267, 270), (274, 280), (274, 330))]
    o += [text(179, 262, "one WireGuard", "s", "middle"), text(179, 279, "tunnel per pair", "s", "middle")]
    for x, n in ((1, "1"), (183, "2")):
        c = x + 87
        o += [box(x, 310, 174, 249, "site", 10), box(x + 10, 330, 154, 92, "gr"), text(c, 352, "goatrope", "b on", "middle")]
        o += [box(x + 18, 362, 138, 50, "ghost"), text(c, 383, "198.51.100.200", "m", "middle"), text(c, 401, "is the controller", "s", "middle")]
        o += [line(x + 14, 440, x + 160, 440), line(c, 412, c, 440), line(c, 440, c, 456)]
        o += [box(x + 18, 456, 138, 52, "node"), text(c, 478, f"sensor {n}", "b", "middle"), text(c, 497, "198.51.100.10", "m", "middle")]
        o += [text(c, 530, f"Sensor site {n}", "h", "middle"), text(c, 548, "198.51.100.0/24", "m", "middle")]
    for p in ropes:
        o += [rope(p, 15)]
    for i, p in enumerate(ropes):
        o += [packet(path_d(p), 2.6, i * .6), packet(path_d(p), 2.6, 1.3 + i * .6, True)]
    return "".join(o) + "</svg>"


def role_tap():
    o = ['<svg class="fig" viewBox="0 0 340 170" role="img" aria-label="A tap device carries the link between A and B and hands goatrope a copy, which goatrope records in a ring of files.">']
    o += [rope([(58, 36), (282, 36)], 13), box(4, 14, 54, 44, "node"), text(31, 41, "A", "b", "middle"), box(282, 14, 54, 44, "node"), text(309, 41, "B", "b", "middle")]
    o += [box(146, 16, 48, 40, "ghost solid"), text(170, 41, "tap", "b", "middle")]
    o += [f'<path class="copy" d="M170 56L170 92"/><path class="head" d="M163 86L170 97L177 86z"/>', text(182, 80, "copy", "s")]
    o += [box(96, 98, 148, 62, "gr"), text(170, 122, "goatrope", "b on", "middle")]
    for i in range(6):
        o += [box(116 + i * 19, 132, 14, 18, "file" + ("" if i < 4 else " empty"), 2)]
    return "".join(o) + "</svg>"


def role_send():
    o = ['<svg class="fig" viewBox="0 0 340 170" role="img" aria-label="goatrope reads the tap\'s copy, keeps the datagrams a match names, optionally converts them, and sends them over UDP, TCP, HTTP or to a file.">']
    o += [text(4, 30, "the copy", "s")]
    for i, on in enumerate((1, 0, 1, 0, 0, 1)):
        o += [box(4, 40 + i * 19, 46, 13, "frame" + (" on" if on else ""), 2)]
    o += [line(58, 92, 84, 92, "copy"), '<path class="head" d="M80 85L91 92L80 99z"/>']
    o += [box(94, 56, 92, 72, "gr"), text(140, 80, "match", "b on", "middle"), text(140, 99, "reassemble", "s on", "middle"), text(140, 116, "convert", "s on", "middle")]
    for i, s in enumerate(("UDP", "TCP", "HTTP", "file")):
        y = 30 + i * 37
        o += [f'<path class="copy" d="M186 92C212 92 214 {y} 236 {y}"/><path class="head" d="M233 {y - 7}L244 {y}L233 {y + 7}z"/>',
              box(248, y - 14, 82, 28, "node"), text(289, y + 5, s, "b", "middle")]
    return "".join(o) + "</svg>"


def role_relay():
    o = ['<svg class="fig" viewBox="0 0 340 170" role="img" aria-label="A remote machine reaches goatrope through WireGuard. One rule carries its datagrams to one machine and port on the link; anything else is dropped.">']
    o += [rope([(68, 82), (150, 82)], 12), box(2, 54, 66, 56, "node"), text(35, 87, "remote", "b", "middle"), text(109, 62, "WireGuard", "s", "middle"), ring(150, 82, 16)]
    o += [box(152, 44, 76, 76, "gr"), text(190, 87, "goatrope", "b on", "middle")]
    o += [line(228, 64, 254, 64, "copy"), '<path class="head" d="M251 57L262 64L251 71z"/>', box(264, 42, 72, 44, "node"), text(300, 69, "target", "b", "middle")]
    o += [line(228, 104, 250, 104, "deny"), '<path class="x" d="M251 97L265 111M265 97L251 111"/>', text(273, 109, "dropped", "s")]
    o += [text(170, 152, "one rule: one address, one port, one way in", "s", "middle")]
    return "".join(o) + "</svg>"


def mode(kind, on):
    listen = kind == "listen"
    what = {("listen", True): "Listen, machine running: the link carries traffic and goatrope records a copy.",
            ("listen", False): "Listen, machine off: the link still carries traffic; only the recording has a gap.",
            ("inline", True): "Inline, machine running: every frame passes through goatrope, which records it.",
            ("inline", False): "Inline, machine off: the link is cut."}[(kind, on)]
    o = [f'<svg class="fig {"on" if on else "off"}" viewBox="0 0 356 200" role="img" aria-label="{what}">']
    ends = [box(4, 24, 62, 52, "node"), text(35, 55, "A", "b", "middle"), box(290, 24, 62, 52, "node"), text(321, 55, "B", "b", "middle")]
    if listen:
        p = [(66, 50), (290, 50)]
        o += [rope(p, 15), packet(path_d(p), 2.4), *ends, box(146, 28, 64, 44, "ghost solid"), text(178, 55, "tap", "b", "middle")]
        o += [f'<path class="{"copy" if on else "deny"}" d="M178 72L178 112"/>']
        if on:
            o += ['<path class="head" d="M171 106L178 117L185 106z"/>']
        o += [box(108, 118, 140, 54, "gr" if on else "gr dead"), text(178, 142, "goatrope", "b on" if on else "b", "middle"), text(178, 161, "recording" if on else "off", "s on" if on else "s", "middle")]
    else:
        if on:
            p = [(66, 50), (290, 50)]
            o += [rope(p, 15), packet(path_d(p), 2.4), *ends, box(118, 22, 120, 58, "gr"), text(178, 46, "goatrope", "b on", "middle"), text(178, 66, "bridging", "s on", "middle")]
        else:
            o += [rope([(66, 50), (92, 50)], 15), frayed(92, 50, 1, 15), rope([(264, 50), (290, 50)], 15), frayed(264, 50, -1, 15)]
            o += ends + [box(128, 22, 100, 58, "gr dead"), text(178, 46, "goatrope", "b", "middle"), text(178, 66, "off", "s", "middle")]
        o += [text(178, 124, "every frame passes through", "s", "middle"), text(178, 143, "the machine" if on else "a machine that is not there", "s", "middle")]
    return "".join(o) + "</svg>"


# ---------------------------------------------------------------- numbers

def read(p):
    with open(os.path.join(REPO, p), encoding="utf-8") as f:
        return f.read()


def outside_stdlib():
    n = set()
    for f in sorted(os.listdir(os.path.join(REPO, "goatrope"))):
        if f.endswith(".py"):
            for node in ast.walk(ast.parse(read(f"goatrope/{f}"))):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
                n |= {m.split(".")[0] for m in mods if m.split(".")[0] not in sys.stdlib_module_names}
    return len(n)


def measures():
    t = read("tests/netns/test_tap.py")
    for need in ("inline: 500 of 500 datagrams a -> b arrived", "inline: 500 of 500 datagrams b -> a arrived",
                 "listen: no frame sent on either listen port (install, traffic, provocation, restarts)",
                 "deploy: a second inline run loses no ping through the bridge", '"-c", "400"'):
        if need not in t:
            sys.exit(f"site: the page quotes a test that is not there: {need}")
    return {"inline": "500 of 500", "listen": "0", "ping": "400 of 400", "deps": str(outside_stdlib())}


def build():
    page = read("site/page.html")
    figs = {"wordmark": wordmark(), "worm-wide": worm_wide(), "worm-narrow": worm_narrow(), "role-tap": role_tap(),
            "role-send": role_send(), "role-relay": role_relay(), "listen-on": mode("listen", True), "listen-off": mode("listen", False),
            "inline-on": mode("inline", True), "inline-off": mode("inline", False),
            "divider": f'<svg class="divider" viewBox="0 0 1152 22" preserveAspectRatio="xMidYMid slice" aria-hidden="true">{rope([(0, 11), (1152, 11)], 14)}</svg>',
            "mark": f'<svg class="mark" viewBox="0 0 40 40" aria-hidden="true">{rope(arc(20, 20, 13, 0, 360, 40), 10)}</svg>'}
    for k, v in figs.items():
        if f"{{{{{k}}}}}" not in page:
            sys.exit(f"site: page.html does not use the figure {k}")
        page = page.replace(f"{{{{{k}}}}}", v)
    if "{{" in page:
        sys.exit("site: page.html names a figure that is not drawn: " + page.split("{{")[1][:40])
    for k, v in measures().items():
        got = re.findall(rf'data-measure="{k}">([^<]*)<', page)
        if not got or any(g != v for g in got):
            sys.exit(f"site: data-measure {k} is {got} on the page and {v} in the tree")
    for href in re.findall(r'https://github\.com/USAREUR-AF/goatrope/blob/main/([^"#]+)', page):
        if not os.path.exists(os.path.join(REPO, href)):
            sys.exit(f"site: the page links to {href}, which is not in the tree")
    if re.search(r'(?:src|href)="(?!https://github\.com/|#|data:)', page):
        sys.exit("site: the page loads something from elsewhere")
    return page.replace("<!doctype html>\n", "<!doctype html>\n" + SPDX, 1)


if __name__ == "__main__":
    out, html = os.path.join(HERE, "index.html"), build()
    if "--check" in sys.argv:
        with open(out, encoding="utf-8") as f:
            if f.read() != html:
                sys.exit("site/index.html is not current: python3 -I site/build.py")
        print("site: current")
    else:
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"site: {len(html):,} bytes")
