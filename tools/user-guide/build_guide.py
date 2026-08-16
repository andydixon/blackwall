#!/usr/bin/env python3
"""Build the editable Scribus and PDF editions of the BlackWall user guide.

Run this script through Scribus rather than a standalone Python interpreter:

    xvfb-run -a scribus -g -py tools/user-guide/build_guide.py

The content is read from docs/MANUAL.md. Screenshots are generated separately
by capture_screenshots.sh from real BlackWall templates and synthetic data.
"""

import math
import os
import re
import sys
import textwrap

try:
    import scribus
except ImportError:
    print("This script must be run through the Scribus scripting interface.")
    sys.exit(1)


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCE = os.path.join(ROOT, "docs", "MANUAL.md")
GUIDE_DIR = os.path.join(ROOT, "docs", "user-guide")
SCREENSHOT_DIR = os.path.join(GUIDE_DIR, "screenshots")
SLA_PATH = os.path.join(GUIDE_DIR, "BlackWall-User-Guide.sla")
PDF_PATH = os.path.join(GUIDE_DIR, "BlackWall-User-Guide.pdf")
LOGO_PATH = os.path.join(ROOT, "internal", "templates", "web", "static", "blackwall.svg")

PAGE_WIDTH = 595.28
PAGE_HEIGHT = 841.89
INNER_MARGIN = 67.0
OUTER_MARGIN = 52.0
TOP = 57.0
BOTTOM = 52.0
CONTENT_BOTTOM = PAGE_HEIGHT - BOTTOM
TOC_FIRST_PAGE = 3
TOC_LAST_PAGE = 6
CONTENT_FIRST_PAGE = 7

COLOURS = {
    "GuideNavy": (10, 18, 35),
    "GuidePanel": (19, 31, 52),
    "GuideBlue": (53, 119, 255),
    "GuideBlueSoft": (188, 210, 255),
    "GuideInk": (24, 31, 43),
    "GuideMuted": (89, 101, 119),
    "GuideRule": (210, 218, 231),
    "GuidePaper": (249, 250, 252),
    "GuideCode": (238, 242, 248),
    "GuideWhite": (255, 255, 255),
}

SCREENSHOTS = {
    "What is Blackwall?": [("home", "The Blackwall public home page and its principal entry points.")],
    "Authentication Posture": [("portal-login", "The passwordless portal sign-in page.")],
    "Installing Blackwall": [("admin-login", "The administrator sign-in page after a successful deployment.")],
    "Bootstrapping the First Administrator": [("organisation-signup", "The organisation registration experience.")],
    "The Admin Console": [
        ("dashboard", "The administrator dashboard, including build and vulnerability-scan provenance."),
        ("documentation", "Task-oriented documentation is available inside the admin console."),
    ],
    "Managing Organisations": [("organisations", "The organisation directory and creation controls.")],
    "Managing Projects": [("projects", "Projects are isolated security and policy boundaries.")],
    "Users, Enrolment, and Authenticators": [("users", "User lifecycle and organisation membership at a glance.")],
    "Project Licences": [("licences", "Licence issuance, renewal reminders, status and revocation in one project view.")],
    "CryptBin Encrypted Sharing": [("cryptbin-create", "CryptBin creates encrypted, expiring text and file shares.")],
    "The End-User Portal": [("portal", "The end-user portal exposes projects and registered passkeys.")],
    "Registering an OAuth Client": [("oauth-clients", "Confidential and public OAuth clients within a project.")],
    "The Authorisation Code Flow with PKCE": [("oauth-consent", "A consent decision uses the calling site's favicon when it can be fetched safely.")],
    "The Audit Log": [("audit-log", "The searchable, exportable audit trail.")],
}


def clean_inline(value):
    """Convert common Markdown inline notation into readable print text."""
    value = re.sub(r"!\[([^]]*)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"\[([^]]+)\]\(([^)]+)\)", r"\1 (\2)", value)
    value = value.replace("**", "").replace("__", "")
    value = value.replace("`", "").replace("~~", "")
    value = re.sub(r"(?<!\w)[*_](.+?)[*_](?!\w)", r"\1", value)
    return value.strip()


def parse_markdown(path):
    """Parse the manual into print-oriented blocks without losing code."""
    with open(path, "r", encoding="utf-8") as source:
        lines = source.read().splitlines()

    # The printed guide supplies its own cover and contents pages.
    start = next(index for index, line in enumerate(lines) if line.startswith("# Part I "))
    lines = lines[start:]
    blocks = []
    paragraph = []
    code = []
    in_code = False
    code_language = ""

    def flush_paragraph():
        if paragraph:
            blocks.append(("paragraph", clean_inline(" ".join(paragraph))))
            paragraph.clear()

    def flush_code():
        if code:
            blocks.append(("code", "\n".join(code), code_language))
            code.clear()

    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
                code_language = ""
            else:
                flush_paragraph()
                in_code = True
                code_language = line[3:].strip()
            index += 1
            continue
        if in_code:
            code.append(line.rstrip())
            index += 1
            continue
        if not line.strip():
            flush_paragraph()
            index += 1
            continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            flush_paragraph()
            blocks.append(("heading" + str(len(heading.group(1))), clean_inline(heading.group(2))))
            index += 1
            continue
        if line.startswith("> "):
            flush_paragraph()
            blocks.append(("quote", clean_inline(line[2:])))
            index += 1
            continue
        if re.match(r"^\s*([-*+] |\d+\. )", line):
            flush_paragraph()
            list_lines = []
            while index < len(lines) and re.match(r"^\s*([-*+] |\d+\. )", lines[index]):
                item = re.sub(r"^\s*[-*+]\s+", "• ", lines[index])
                list_lines.append(clean_inline(item))
                index += 1
            blocks.append(("list", "\n".join(list_lines)))
            continue
        if line.lstrip().startswith("|"):
            flush_paragraph()
            table_lines = []
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                if not re.match(r"^\s*\|?\s*:?-{3,}", lines[index]):
                    cells = [clean_inline(cell.strip()) for cell in lines[index].strip().strip("|").split("|")]
                    table_lines.append("  |  ".join(cells))
                index += 1
            blocks.append(("table", "\n".join(table_lines)))
            continue
        if re.match(r"^[-*_]{3,}\s*$", line):
            flush_paragraph()
            blocks.append(("rule", ""))
            index += 1
            continue
        paragraph.append(line.strip())
        index += 1
    flush_paragraph()
    flush_code()
    return blocks


class GuideBuilder:
    """Lay out the guide with deterministic, editable Scribus frames."""

    def __init__(self):
        self.page = 1
        self.y = TOP
        self.page_has_content = False
        self.current_part = ""
        self.pending_part = ""
        self.chapter_entries = []
        self.fonts = set(scribus.getFontNames())
        self.body_font = self.pick_font("Lato Regular", "DejaVu Sans Book", "DejaVu Sans")
        self.bold_font = self.pick_font("Lato Bold", "DejaVu Sans Bold", self.body_font)
        self.mono_font = self.pick_font("Noto Sans Mono Regular", "DejaVu Sans Mono Book", "DejaVu Sans Mono")

    def pick_font(self, *names):
        for name in names:
            if name in self.fonts:
                return name
        return sorted(self.fonts)[0]

    def margins(self):
        if self.page % 2 == 1:
            return INNER_MARGIN, OUTER_MARGIN
        return OUTER_MARGIN, INNER_MARGIN

    def content_geometry(self):
        left, right = self.margins()
        return left, PAGE_WIDTH - left - right

    def add_text(self, text, x, y, width, height, font=None, size=9.5,
                 colour="GuideInk", align=scribus.ALIGN_LEFT, leading=None,
                 fill="None", inset=0.0):
        frame = scribus.createText(x, y, width, max(height, 4.0))
        if fill != "None":
            scribus.setFillColor(fill, frame)
        else:
            scribus.setFillColor("None", frame)
        scribus.setLineColor("None", frame)
        if inset:
            scribus.setTextDistances(inset, inset, inset, inset, frame)
        scribus.setText(text, frame)
        scribus.setFont(font or self.body_font, frame)
        scribus.setFontSize(size, frame)
        scribus.setTextColor(colour, frame)
        scribus.setTextAlignment(align, frame)
        if leading:
            scribus.setLineSpacing(leading, frame)
        return frame

    def add_rect(self, x, y, width, height, fill, radius=0):
        frame = scribus.createRect(x, y, width, height)
        scribus.setFillColor(fill, frame)
        scribus.setLineColor(fill, frame)
        if radius and hasattr(scribus, "setCornerRadius"):
            scribus.setCornerRadius(radius, frame)
        return frame

    def create_document(self):
        os.makedirs(GUIDE_DIR, exist_ok=True)
        scribus.newDocument(
            scribus.PAPER_A4,
            (INNER_MARGIN, OUTER_MARGIN, TOP, BOTTOM),
            scribus.PORTRAIT,
            1,
            scribus.UNIT_POINTS,
            scribus.FACINGPAGES,
            scribus.FIRSTPAGERIGHT,
            1,
        )
        for name, colour in COLOURS.items():
            scribus.defineColorRGB(name, *colour)
        scribus.setInfo(
            "Andy Dixon",
            "BlackWall User Guide",
            "Feature-complete guide to BlackWall authentication, licensing, administration, integration and operations.",
        )
        self.draw_cover()
        for number in range(2, CONTENT_FIRST_PAGE + 1):
            scribus.newPage(-1)
            self.page = number
            if number == 2:
                self.draw_dedication()
            elif TOC_FIRST_PAGE <= number <= TOC_LAST_PAGE:
                self.draw_front_matter_page(number)
        scribus.gotoPage(CONTENT_FIRST_PAGE)
        self.page = CONTENT_FIRST_PAGE
        self.y = TOP
        self.page_has_content = False

    def draw_cover(self):
        self.add_rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, "GuideNavy")
        self.add_rect(0, 0, 18, PAGE_HEIGHT, "GuideBlue")
        logo = scribus.createImage(68, 62, 54, 54)
        scribus.loadImage(LOGO_PATH, logo)
        scribus.setScaleImageToFrame(True, True, logo)
        scribus.setLineColor("None", logo)
        self.add_text("BLACKWALL", 135, 76, 340, 24, self.bold_font, 13, "GuideBlueSoft", leading=16)
        self.add_text("BlackWall\nUser Guide", 67, 235, 455, 150, self.bold_font, 43, "GuideWhite", leading=49)
        self.add_rect(68, 405, 104, 5, "GuideBlue")
        self.add_text("Passwordless authentication, project licensing,\nsecure operations and integration", 68, 432, 450, 58, self.body_font, 15, "GuideBlueSoft", leading=22)
        self.add_text("Author: Andy Dixon", 68, 687, 300, 26, self.bold_font, 12, "GuideWhite", leading=16)
        self.add_text("August 2026 edition", 68, 718, 300, 22, self.body_font, 10, "GuideBlueSoft", leading=14)

    def draw_dedication(self):
        self.add_rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, "GuidePaper")
        self.add_text("Dedication", 72, 212, 450, 38, self.bold_font, 24, "GuideInk", leading=29)
        self.add_rect(72, 266, 72, 4, "GuideBlue")
        dedication = (
            "Dedicated to everyone who builds digital systems that people can trust — "
            "and to the administrators, developers and operators whose careful work keeps them secure."
        )
        self.add_text(dedication, 72, 306, 440, 118, self.body_font, 14, "GuideMuted", leading=22)
        self.add_text("Andy Dixon", 72, 445, 250, 24, self.bold_font, 10, "GuideInk", leading=14)

    def draw_front_matter_page(self, page):
        self.add_rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, "GuidePaper")
        self.add_footer(page, "Contents")

    def add_footer(self, page=None, label=None):
        page = page or self.page
        left, width = self.content_geometry()
        line = scribus.createLine(left, PAGE_HEIGHT - 38, left + width, PAGE_HEIGHT - 38)
        scribus.setLineColor("GuideRule", line)
        scribus.setLineWidth(0.5, line)
        self.add_text(label or "BlackWall User Guide", left, PAGE_HEIGHT - 31, width - 35, 14,
                      self.body_font, 7.5, "GuideMuted", leading=9)
        self.add_text(str(page), left + width - 32, PAGE_HEIGHT - 31, 32, 14,
                      self.bold_font, 8, "GuideMuted", scribus.ALIGN_RIGHT, leading=9)

    def add_running_header(self):
        left, width = self.content_geometry()
        self.add_text("BLACKWALL USER GUIDE", left, 28, width / 2, 12,
                      self.bold_font, 6.8, "GuideMuted", leading=8)
        if self.current_part:
            self.add_text(self.current_part.upper(), left + width / 2, 28, width / 2, 12,
                          self.body_font, 6.8, "GuideMuted", scribus.ALIGN_RIGHT, leading=8)

    def new_page(self, blank=False):
        scribus.newPage(-1)
        self.page += 1
        self.y = TOP
        self.page_has_content = False
        self.add_footer()
        if blank:
            self.add_text("This page is intentionally blank.", 95, PAGE_HEIGHT / 2, PAGE_WIDTH - 190, 18,
                          self.body_font, 8, "GuideMuted", scribus.ALIGN_CENTERED, leading=10)
        else:
            self.add_running_header()

    def advance_to_right_page(self):
        if self.page_has_content:
            self.new_page()
        if self.page % 2 == 0:
            if not self.page_has_content:
                self.add_text("This page is intentionally blank.", 95, PAGE_HEIGHT / 2, PAGE_WIDTH - 190, 18,
                              self.body_font, 8, "GuideMuted", scribus.ALIGN_CENTERED, leading=10)
            self.new_page()

    def ensure_space(self, height, minimum_following=0):
        if self.y + height + minimum_following > CONTENT_BOTTOM:
            self.new_page()

    def start_chapter(self, title):
        self.advance_to_right_page()
        if self.pending_part:
            self.current_part = self.pending_part
            self.pending_part = ""
        self.chapter_entries.append((self.current_part, title, self.page))
        left, width = self.content_geometry()
        if self.current_part:
            self.add_text(self.current_part.upper(), left, self.y, width, 15,
                          self.bold_font, 7.3, "GuideBlue", leading=9)
            self.y += 24
        display = re.sub(r"^Chapter\s+\d+:\s*", "", title)
        wrapped = textwrap.wrap(display, 36) or [display]
        height = len(wrapped) * 31 + 8
        self.add_text("\n".join(wrapped), left, self.y, width, height,
                      self.bold_font, 25, "GuideInk", leading=30)
        self.y += height + 12
        self.add_rect(left, self.y, 68, 4, "GuideBlue")
        self.y += 25
        self.page_has_content = True
        for screenshot, caption in SCREENSHOTS.get(display, []):
            self.add_screenshot(screenshot, caption)

    def add_screenshot(self, name, caption):
        path = os.path.join(SCREENSHOT_DIR, name + ".png")
        if not os.path.isfile(path):
            raise RuntimeError("Missing guide screenshot: " + path)
        left, width = self.content_geometry()
        image_height = width * 0.625
        required = image_height + 34
        self.ensure_space(required)
        frame = scribus.createImage(left, self.y, width, image_height)
        scribus.loadImage(path, frame)
        scribus.setScaleImageToFrame(True, True, frame)
        scribus.setLineColor("GuideRule", frame)
        scribus.setLineWidth(0.6, frame)
        self.y += image_height + 7
        self.add_text(caption, left, self.y, width, 20, self.body_font, 7.5, "GuideMuted", leading=10)
        self.y += 28
        self.page_has_content = True

    def estimate_lines(self, text, font_size, width, preserve=False):
        # Markdown tables contain explicit separators as well as long values.
        # A deliberately conservative monospace estimate prevents clipped rows.
        characters = max(24, int(width / (font_size * (0.78 if preserve else 0.50))))
        total = 0
        for line in text.splitlines() or [""]:
            if preserve:
                total += max(1, math.ceil(max(1, len(line.expandtabs(4))) / characters))
            else:
                total += max(1, len(textwrap.wrap(line, characters, break_long_words=True)) or 1)
        return total

    def split_code(self, text, available_lines, characters=104):
        visual = []
        for original in text.splitlines():
            expanded = original.expandtabs(4)
            if len(expanded) <= characters:
                visual.append(expanded)
                continue
            wrapped = textwrap.wrap(expanded, characters, replace_whitespace=False,
                                    drop_whitespace=False, subsequent_indent="  ↳ ")
            visual.extend(wrapped or [""])
        return visual[:available_lines], visual[available_lines:]

    def add_code(self, text, language=""):
        remaining = text.splitlines()
        if not remaining:
            return
        while remaining:
            left, width = self.content_geometry()
            available_height = CONTENT_BOTTOM - self.y
            available_lines = int((available_height - 24) / 9.0)
            if available_lines < 6:
                self.new_page()
                continue
            chunk, rest = self.split_code("\n".join(remaining), available_lines)
            height = len(chunk) * 9.0 + 22
            label = (language or "code").upper()
            self.add_text(label, left + 9, self.y + 7, width - 18, 10,
                          self.bold_font, 6.2, "GuideBlue", leading=7)
            self.add_text("\n".join(chunk), left, self.y, width, height,
                          self.mono_font, 6.8, "GuideInk", leading=9.0,
                          fill="GuideCode", inset=9)
            self.y += height + 10
            self.page_has_content = True
            remaining = rest
            if remaining:
                self.new_page()

    def add_block(self, kind, text, language=""):
        left, width = self.content_geometry()
        if kind == "code":
            self.add_code(text, language)
            return
        if kind == "rule":
            self.ensure_space(18)
            line = scribus.createLine(left, self.y + 6, left + width, self.y + 6)
            scribus.setLineColor("GuideRule", line)
            scribus.setLineWidth(0.7, line)
            self.y += 18
            return
        settings = {
            "heading3": (13.0, 17.0, self.bold_font, "GuideInk", 11.0),
            "paragraph": (9.3, 13.1, self.body_font, "GuideInk", 7.0),
            "list": (9.1, 13.0, self.body_font, "GuideInk", 8.0),
            "quote": (9.3, 14.0, self.body_font, "GuideMuted", 14.0),
            "table": (7.2, 10.2, self.mono_font, "GuideInk", 9.0),
        }
        size, leading, font, colour, gap = settings.get(kind, settings["paragraph"])
        lines = self.estimate_lines(text, size, width - (20 if kind in ("quote", "table") else 0), kind == "table")
        if kind == "table":
            # Allow for Scribus's word-boundary wrapping and the frame inset.
            lines = int(math.ceil(lines * 1.25)) + 3
        height = lines * leading + (16 if kind in ("quote", "table") else 4)
        if height > CONTENT_BOTTOM - TOP:
            # Oversized prose/table blocks are split into printable line groups.
            raw_lines = text.splitlines()
            if len(raw_lines) == 1:
                raw_lines = textwrap.wrap(text, 84)
            midpoint = max(1, len(raw_lines) // 2)
            self.add_block(kind, "\n".join(raw_lines[:midpoint]))
            self.add_block(kind, "\n".join(raw_lines[midpoint:]))
            return
        self.ensure_space(height, 20 if kind == "heading3" else 0)
        fill = "GuideCode" if kind == "table" else "None"
        inset = 9 if kind == "table" else 0
        x = left + (12 if kind == "quote" else 0)
        block_width = width - (12 if kind == "quote" else 0)
        if kind == "quote":
            self.add_rect(left, self.y, 3, height, "GuideBlue")
        self.add_text(text, x, self.y, block_width, height, font, size, colour,
                      leading=leading, fill=fill, inset=inset)
        self.y += height + gap
        self.page_has_content = True

    def flow(self, blocks):
        for block in blocks:
            kind = block[0]
            text = block[1]
            if kind == "heading1" and text.startswith("Part "):
                self.pending_part = text
                continue
            if kind == "heading2" and text.startswith("Chapter "):
                self.start_chapter(text)
                continue
            if kind == "heading2":
                kind = "heading3"
            if kind == "heading1":
                kind = "heading3"
            language = block[2] if len(block) > 2 else ""
            self.add_block(kind, text, language)

    def draw_toc(self):
        entries = self.chapter_entries
        per_page = int(math.ceil(len(entries) / float(TOC_LAST_PAGE - TOC_FIRST_PAGE + 1)))
        for offset, page in enumerate(range(TOC_FIRST_PAGE, TOC_LAST_PAGE + 1)):
            scribus.gotoPage(page)
            left = INNER_MARGIN if page % 2 else OUTER_MARGIN
            width = PAGE_WIDTH - INNER_MARGIN - OUTER_MARGIN
            start = offset * per_page
            end = min(len(entries), start + per_page)
            self.add_text("Contents" if page == TOC_FIRST_PAGE else "Contents continued",
                          left, 62, width, 40, self.bold_font, 24, "GuideInk", leading=29)
            y = 124
            last_part = ""
            for part, title, destination in entries[start:end]:
                if part != last_part:
                    part_name = re.sub(r"^Part\s+[IVX]+\s+[—-]\s*", "", part)
                    self.add_text(part_name.upper(), left, y, width, 13,
                                  self.bold_font, 6.5, "GuideBlue", leading=8)
                    y += 17
                    last_part = part
                chapter = re.sub(r"^Chapter\s+\d+:\s*", "", title)
                number = re.match(r"^Chapter\s+(\d+):", title)
                label = (number.group(1) + ". " if number else "") + chapter
                self.add_text(label, left, y, width - 38, 22,
                              self.body_font, 8.2, "GuideInk", leading=10)
                self.add_text(str(destination), left + width - 34, y, 34, 22,
                              self.bold_font, 8.2, "GuideMuted", scribus.ALIGN_RIGHT, leading=10)
                y += 25
        scribus.gotoPage(self.page)

    def finish(self):
        self.draw_toc()
        scribus.saveDocAs(SLA_PATH)
        pdf = scribus.PDFfile()
        pdf.file = PDF_PATH
        pdf.version = 16
        pdf.compress = True
        pdf.compressmtd = 0
        pdf.quality = 95
        pdf.resolution = 300
        pdf.save()
        print("Created {} pages".format(self.page))
        print(SLA_PATH)
        print(PDF_PATH)


def main():
    builder = GuideBuilder()
    builder.create_document()
    scribus.setRedraw(False)
    builder.flow(parse_markdown(SOURCE))
    builder.finish()
    scribus.setRedraw(True)


if __name__ == "__main__":
    main()
