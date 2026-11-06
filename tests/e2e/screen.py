#!/usr/bin/env python3
"""Rendert ein Mitschnitt der seriellen Konsole (VT100/screen) zu Bildschirmtext.

    screen.py <logdatei>          aktuellen Bildschirm ausgeben
    screen.py --sig <logdatei>    Pruefsumme des Inhalts (ohne Status-/Uhrzeile)
"""
import hashlib
import re
import sys

import pyte


def render(path: str, cols: int = 80, rows: int = 25) -> list[str]:
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    with open(path, "rb") as fh:
        stream.feed(fh.read())
    return [line.rstrip() for line in screen.display]


def main() -> None:
    sig = sys.argv[1] == "--sig"
    path = sys.argv[-1]
    try:
        lines = render(path)
    except FileNotFoundError:
        lines = []
    if sig:
        content = [l for l in lines if not re.search(r"\d\d:\d\d \]|installer\)", l)]
        print(hashlib.sha256("\n".join(content).encode()).hexdigest())
    else:
        while lines and not lines[-1].strip():
            lines.pop()
        print("+" + "-" * 80 + "+")
        for line in lines:
            print("|" + line.ljust(80) + "|")
        print("+" + "-" * 80 + "+")


if __name__ == "__main__":
    main()
