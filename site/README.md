<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# site

The landing page. `index.html` is one self-contained file, light and dark, with no request to
another host; `.github/workflows/pages.yml` publishes it.

| File | What it is |
|---|---|
| `page.html` | the text, styles and script |
| `build.py` | draws the figures and writes `index.html`; `--check` fails when it is not current, when a number marked `data-measure` is not what the tree says, when a test the page quotes is gone, or when a linked file is missing |
| `fitcheck.py` | loads the page in headless Chrome at 1440 and 390 px and fails when a command box is cut off or the page scrolls sideways |

Edit `page.html` or `build.py`, then `python3 -I site/build.py`. The rope is drawn by
`build.py`: a path, a body and one strand line every few units. State is drawn (whole, frayed,
crossed, dashed), never only coloured.
