"""Regenerate the embedded Material Symbols subset from the icons the pages use.

    python3 tools/build_font.py [--embed]

Needs the full variable font (not the pruned one): download
MaterialSymbolsRounded[FILL,GRAD,opsz,wght].ttf from google/material-design-icons
and point MS_FONT at it, or drop it next to this script. The variable font is
15 MB and is NOT committed -- only the 6 KB subset it produces.

The icon list is read from the pages themselves, so it cannot drift from what
is rendered: an icon that no page names is a glyph the binary would carry for
nothing, and an icon a page names but the font lacks renders as its ligature
name ("KEYBOARD_ARROW_DOWN"), which is the bug this script exists to prevent.
"""
import os
import re
import sys
from fontTools.ttLib import TTFont
from fontTools.subset import Subsetter, Options
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.environ.get("MS_FONT", os.path.join(ROOT, "tools/MaterialSymbolsRounded.ttf"))
OUT = os.path.join(ROOT, "assets/fonts/material-symbols-rounded-subset.woff2")
PAGES = ("panel", "login", "error")

ICON_RE = re.compile(r'class="[^"]*material-symbols-rounded[^"]*"[^>]*>\s*([a-z0-9_]+)\s*<')
CREATE_RE = re.compile(r"createIcon\('([a-z0-9_]+)'\)")


def icons_in_use():
    used = set()
    for page in PAGES:
        p = os.path.join(ROOT, "assets", page, "index.html")
        if not os.path.exists(p):
            continue
        html = open(p, encoding="utf-8").read()
        used.update(ICON_RE.findall(html))
        used.update(CREATE_RE.findall(html))
    return used


def reverse_cmap(font):
    choices = {}
    for cp, name in font.getBestCmap().items():
        choices.setdefault(name, []).append(chr(cp))
    rev = {}
    for name, chars in choices.items():
        if "_" in chars:
            rev[name] = "_"
        elif any(c.islower() for c in chars):
            rev[name] = next(c for c in chars if c.islower())
        else:
            rev[name] = chars[0]
    return rev


def main():
    want = icons_in_use()
    font = TTFont(SRC)
    rev = reverse_cmap(font)

    keep, drop, keep_names = [], [], []
    for lookup in font["GSUB"].table.LookupList.Lookup:
        for sub in lookup.SubTable:
            target = sub
            if getattr(sub, "LookupType", 0) == 7 and hasattr(sub, "ExtSubTable"):
                target = sub.ExtSubTable
            for first, ligs in list(getattr(target, "ligatures", {}).items()):
                for lig in list(ligs):
                    name = rev.get(first, "?") + "".join(rev.get(c, "?") for c in lig.Component)
                    (keep if name in want else drop).append((target, first, lig))
                    if name in want:
                        keep_names.append(name)

    missing = sorted(want - set(keep_names))
    if missing:
        print("ERROR: font lacks these icons: " + ", ".join(missing))
        return 1

    # Only now remove the unused ligatures (a mutation during iteration raises).
    for target, first, lig in drop:
        ligs = target.ligatures.get(first)
        if not ligs:
            continue
        if lig in ligs:
            ligs.remove(lig)
        if not ligs:
            del target.ligatures[first]
    print("icons kept: %d, ligatures dropped: %d" % (len(keep_names), len(drop)))

    chars = set("abcdefghijklmnopqrstuvwxyz0123456789_")
    cmap = font.getBestCmap()
    glyphs = {cmap[ord(c)] for c in chars if ord(c) in cmap}
    for target, first, lig in keep:
        glyphs.add(first)
        glyphs.update(lig.Component)

    opts = Options()
    opts.layout_features = ["*"]
    opts.drop_tables = []
    opts.name_IDs = ["*"]
    opts.notdef_outline = True
    opts.desubroutinize = True
    sub = Subsetter(options=opts)
    sub.populate(unicodes=[ord(c) for c in chars], glyphs=list(glyphs))
    sub.subset(font)

    if "fvar" in font:
        defaults = {a.axisTag: a.defaultValue for a in font["fvar"].axes}
        font = instantiateVariableFont(font, defaults, inplace=False, updateFontNames=False)

    font.flavor = "woff2"
    font.save(OUT)
    print("wrote %s: %d bytes, %d glyphs" % (OUT, os.path.getsize(OUT), len(font.getGlyphOrder())))
    return 0


if __name__ == "__main__":
    sys.exit(main())