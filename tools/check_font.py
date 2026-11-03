"""Check the embedded icon font covers every icon the pages name.

    python3 tools/check_font.py

Any icon the pages use but the subset lacks renders as its ligature name
("KEYBOARD_ARROW_DOWN") instead of a glyph, which is what the panel used to do.
"""
import os
import re
import sys

from fontTools.ttLib import TTFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT = os.path.join(ROOT, "assets/fonts/material-symbols-rounded-subset.woff2")
PAGES = ("panel", "login", "error")

ICON_RE = re.compile(r'class="[^"]*material-symbols-rounded[^"]*"[^>]*>\s*([a-z0-9_]+)\s*<')
CREATE_RE = re.compile(r"createIcon\('([a-z0-9_]+)'\)")


def icons_in_use():
    used = set()
    for page in PAGES:
        path = os.path.join(ROOT, "assets", page, "index.html")
        if not os.path.exists(path):
            continue
        html = open(path, encoding="utf-8").read()
        used.update(ICON_RE.findall(html))
        used.update(CREATE_RE.findall(html))
    return used


def ligature_names(font):
    """Ligature names rebuilt from codepoints, not glyph names: the underscore
    glyph is called "underscore", so glyph-name concatenation never matches."""
    choices = {}
    for cp, name in (font.getBestCmap() or {}).items():
        choices.setdefault(name, []).append(chr(cp))
    rev = {}
    for name, chars in choices.items():
        if "_" in chars:
            rev[name] = "_"
        elif any(c.islower() for c in chars):
            rev[name] = next(c for c in chars if c.islower())
        else:
            rev[name] = chars[0]

    out = set()
    for lookup in font["GSUB"].table.LookupList.Lookup:
        for sub in lookup.SubTable:
            table = sub
            if getattr(table, "LookupType", 0) == 7 and hasattr(table, "ExtSubTable"):
                table = table.ExtSubTable
            for first, ligs in getattr(table, "ligatures", {}).items():
                for lig in ligs:
                    out.add(rev.get(first, "?") + "".join(rev.get(c, "?") for c in lig.Component))
    return out


def main():
    font = TTFont(FONT)
    have, want = ligature_names(font), icons_in_use()
    missing = sorted(want - have)
    print("font:      %s" % FONT)
    print("  size=%d bytes glyphs=%d ligatures=%d"
          % (os.path.getsize(FONT), len(font.getGlyphOrder()), len(have)))
    print("  icons used by pages: %d" % len(want))
    if missing:
        print("  MISSING: " + ", ".join(missing))
        return 1
    print("  all page icons render")
    return 0


if __name__ == "__main__":
    sys.exit(main())
