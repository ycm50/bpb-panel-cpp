"""Embed assets/fonts/*.woff2 into the pages' @font-face rules.

The font is inlined as a data: URL so a lone binary needs no extra files, which
means replacing the font is a two-step job: rebuild the woff2, then run this and
regenerate src/assets_gen.cpp.
"""
import base64
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONT = os.path.join(ROOT, "assets/fonts/material-symbols-rounded-subset.woff2")
PAGES = ("panel", "login", "error")


def main():
    b64 = base64.b64encode(open(FONT, "rb").read()).decode()
    print("font %d bytes -> %d base64 chars" % (os.path.getsize(FONT), len(b64)))
    for page in PAGES:
        path = os.path.join(ROOT, "assets", page, "index.html")
        html = open(path, encoding="utf-8").read()
        m = re.search(r"src:\s*url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)", html)
        if not m:
            print("  %s: no embedded font (page uses no icons)" % page)
            continue
        old = len(m.group(1))
        html = html[:m.start(1)] + b64 + html[m.end(1):]
        open(path, "w", encoding="utf-8", newline="\n").write(html)
        print("  %s: %d -> %d chars" % (page, old, len(b64)))


if __name__ == "__main__":
    main()
