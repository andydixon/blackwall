#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025-2026 Andy Dixon

"""Report overflowing text frames in an open Scribus user-guide document."""

import sys

try:
    import scribus
except ImportError:
    print("This script must be run through the Scribus scripting interface.")
    sys.exit(1)


def main():
    if not scribus.haveDoc():
        raise RuntimeError("Open BlackWall-User-Guide.sla before running this script")
    overflowing = []
    for page in range(1, scribus.pageCount() + 1):
        scribus.gotoPage(page)
        for item in scribus.getPageItems():
            name = item[0]
            try:
                if scribus.textOverflows(name):
                    text = scribus.getAllText(name).replace("\n", " ")[:100]
                    overflowing.append((page, name, text))
            except Exception:
                # Non-text frames deliberately do not support textOverflows().
                continue
    if overflowing:
        print("OVERFLOWING_TEXT_FRAMES={}".format(len(overflowing)))
        for page, name, text in overflowing:
            print("page={} frame={} text={!r}".format(page, name, text))
    else:
        print("OVERFLOWING_TEXT_FRAMES=0")
    print("PAGES={}".format(scribus.pageCount()))


if __name__ == "__main__":
    main()
