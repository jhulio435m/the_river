#!/usr/bin/env python3
"""Finds click targets in a screenshot of an 800x620 the_river_client window.

  locate.py last-line   shot.png [N] -> x y of the last chat line in the feed
                                        (fails unless at least N chat lines)
  locate.py first-button shot.png -> x y of the leftmost button of a modal

Used by record_demo.sh so the clicks do not depend on hard-coded line counts.
Colours come from app_ui.cpp (BBS palette): lime (0,255,0) / magenta
(255,0,255) text, buttons filled with (0,0,168).
"""
import sys
from PIL import Image

HEADER, FOOTER, BAND = 42, 42, 84


def is_chat_colour(p):
    r, g, b = p
    lime = g > 150 and r < 80 and b < 80
    magenta = r > 150 and b > 150 and g < 80
    return lime or magenta


def main():
    mode, path = sys.argv[1], sys.argv[2]
    im = Image.open(path).convert("RGB")
    w, h = im.size
    px = im.load()
    top, bottom = HEADER + 2, h - FOOTER - BAND - 2
    if mode == "last-line":
        x0 = int(w * 0.18) + 6
        rows = [y for y in range(top, bottom)
                if any(is_chat_colour(px[x, y]) for x in range(x0, w - 10))]
        if not rows:
            sys.exit("no chat line found")
        # group consecutive rows into text lines, take the last group
        groups, start, prev = [], rows[0], rows[0]
        for y in rows[1:]:
            if y > prev + 3:
                groups.append((start, prev))
                start = y
            prev = y
        groups.append((start, prev))
        need = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        if len(groups) < need:
            sys.exit("not enough chat lines yet")
        a, b = groups[-1]
        print(x0 + 140, (a + b) // 2)
    elif mode == "first-button":
        for y in range(top, bottom):
            xs = [x for x in range(w) if px[x, y] == (0, 0, 168)]
            if len(xs) > 60:
                run_start = xs[0]
                run_end = run_start
                for x in xs[1:]:
                    if x != run_end + 1:
                        break
                    run_end = x
                print((run_start + run_end) // 2, y + 10)
                return
        sys.exit("no button found")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
