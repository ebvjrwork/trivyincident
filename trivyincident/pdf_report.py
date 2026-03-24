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
        data.append([Paragraph(str(c), S_TD) for c in row])

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
    story.append(Paragraph("CVE-2026-33634", S_SUBTITLE))
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
    story.append(Paragraph(
        "On March 19, 2026, the Aqua Security Trivy ecosystem was compromised for the second "
        "time in three weeks by threat group <b>TeamPCP</b> (also known as PCPcat, Persy_PCP, "
        "ShellForce, and DeadCatx3), a significant threat to cloud-native infrastructure that "
        "emerged in late 2025. This was a continuation of the February 28, 2026 incident where "
        "an autonomous bot (<b>hackerbot-claw</b>) exploited a <font name='Courier'>pull_request_target</font> "
        "workflow in aquasecurity/trivy to steal a Personal Access Token (PAT). Aqua Security's "
        "containment of the first incident was incomplete, allowing the attacker to strike again. "
        "This incident has been assigned <b>CVE-2026-33634</b>.",
        S_BODY,
    ))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "The second compromise affected <b>trivy</b> (malicious v0.69.4 binary published via "
        "release automation), <b>trivy-action</b> (credential stealer injected via imposter "
        "commits into all tags from 0.0.1 through 0.34.2), and <b>setup-trivy</b> (similarly "
        "compromised via imposter commits). The malicious payload harvested Runner process "
        "environment variables, read GitHub Actions Runner.Worker process memory to extract "
        "secrets marked <font name='Courier'>isSecret: true</font>, and exfiltrated encrypted "
        "data to the typosquat C2 domain <font name='Courier'>scan.aquasecurtiy.org</font> "
        "(note: 'securtiy' — a deliberate typo of 'security').",
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

    story.append(Paragraph("2.1 Precursor: First Compromise (February 27, 2026)", S_H2))
    story.append(Paragraph(
        "On February 27, autonomous bot <b>hackerbot-claw</b> (account <b>MegaGame10418</b>) executed a Pwn Request against "
        "Trivy's CI, exploiting a vulnerable <font name='Courier'>pull_request_target</font> "
        "workflow to exfiltrate the <font name='Courier'>aqua-bot</font> Personal Access Token "
        "(PAT). Using the stolen PAT, the attacker privatized the repository, deleted all "
        "GitHub Releases between v0.27.0 and v0.69.1, and pushed a suspicious artifact to the "
        "Trivy VSCode extension on Open VSX. Aqua Security disclosed the incident and remediated "
        "the immediate damage, but <b>credential rotation was not atomic</b> — the attacker may "
        "have been privy to refreshed tokens.",
        S_BODY,
    ))

    story.append(Paragraph("2.2 Second Compromise (March 19, 2026)", S_H2))
    story.append(Paragraph(
        "Three weeks later, using credentials retained from the incomplete first remediation, "
        "the attacker launched a coordinated multi-phase supply-chain attack:",
        S_BODY,
    ))

    story.append(Spacer(1, 6))
    story.append(Paragraph("2.3 Attack Phases", S_H2))

    story.append(Paragraph("<b>Phase 1 — Imposter Commits &amp; Malicious Release</b>", S_H3))
    story.append(Paragraph(
        "The attacker created <b>imposter commits</b> — malicious commits pushed via forks that "
        "don't belong to any branch on the target repository. An imposter commit in "
        "<font name='Courier'>actions/checkout</font> (impersonating Guillermo Rauch) fetched "
        "malicious Go files from the typosquat C2 <font name='Courier'>scan.aquasecurtiy.org</font>. "
        "A second imposter commit in <font name='Courier'>aquasecurity/trivy</font> (impersonating "
        "contributor DmitriyLewen) referenced this malicious checkout action. "
        "The <font name='Courier'>v0.69.4</font> tag was then pushed pointing to the malicious "
        "commit, triggering automated release workflows that distributed compromised binaries to "
        "GitHub Releases, GHCR, Docker Hub, ECR Public, APT/RPM repos, and get.trivy.dev.",
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 2 — Lateral Movement via aqua-bot</b>", S_H3))
    story.append(Paragraph(
        "Using the compromised <font name='Courier'>aqua-bot</font> identity, the attacker "
        "injected malicious workflows into <font name='Courier'>aquasecurity/tfsec</font>, "
        "<font name='Courier'>aquasecurity/traceeshark</font>, and "
        "<font name='Courier'>aquasecurity/trivy-action</font> to dump secrets via a "
        "Cloudflare Tunnel exfiltration endpoint. These workflows posted collected credentials "
        "(including GITHUB_TOKEN, Docker Hub tokens, GPG keys, and Slack webhooks) to "
        "<font name='Courier'>plug-tab-protective-relay.trycloudflare.com/exfil</font>.",
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 3 — Malicious Action Tags Published</b>", S_H3))
    story.append(Paragraph(
        "Using compromised credentials, the attacker published malicious tags for "
        "<font name='Courier'>trivy-action</font> (all tags from 0.0.1 through 0.34.2) and "
        "<font name='Courier'>setup-trivy</font> (all tags). Tags were pointed to imposter "
        "commits containing a three-stage credential stealer injected into "
        "<font name='Courier'>entrypoint.sh</font> and <font name='Courier'>action.yaml</font>.",
        S_BODY,
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 4 — Obfuscation: Spam Flood</b>", S_H3))
    story.append(Paragraph(
        "When community members opened discussion #10420 to report the compromise, "
        "<b>96 spam accounts</b> posted generic praise comments within ~30 seconds to bury the "
        "technical discussion. Two accounts posted taunts referencing 'teampcp'. The original "
        "incident discussion #10265 was also deleted by the attacker to slow response.",
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
        "<font name='Courier'>/proc/*/environ</font>. Read "
        "<font name='Courier'>Runner.Worker</font> process memory via "
        "<font name='Courier'>/proc/&lt;pid&gt;/mem</font>, searching for the pattern "
        '<font name=\'Courier\'>{"value":"&lt;secret&gt;","isSecret":true}</font>. '
        "On non-Linux platforms, ran a comprehensive credential stealer targeting SSH keys, "
        "Git credentials, AWS/GCP/Azure credentials, Kubernetes secrets, Docker configs, "
        "database credentials, Terraform state, crypto wallets (Solana, Bitcoin, Ethereum, "
        "Cardano), and SSL private keys.",
        "<b>Encrypt:</b> All collected data was encrypted with a hardcoded RSA-4096 public key "
        "using hybrid encryption (AES-256-CBC + RSA-OAEP), bundled as "
        "<font name='Courier'>tpcp.tar.gz</font>.",
        "<b>Exfiltrate:</b> Encrypted payload was sent via HTTPS POST to the typosquat C2 domain "
        "<font name='Courier'>scan.aquasecurtiy.org</font> (45.148.10.212, TECHOFF SRV LIMITED, "
        "Amsterdam, NL). Fallback: if the C2 was unreachable and a GitHub PAT was available, "
        "the payload created a public repository called <font name='Courier'>tpcp-docs</font> "
        "on the victim's GitHub account and uploaded the stolen data as a release asset.",
    ]
    for ps in payload_stages:
        story.append(Paragraph(f"\u2022 {ps}", S_BULLET))
        story.append(Spacer(1, 3))

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
        "that container registry credentials were also compromised.",
        "<b>npm Worm — CanisterWorm (Mar 20):</b> Using stolen npm tokens from compromised CI "
        "runners, a self-propagating worm infected 28+ packages across multiple npm scopes "
        "(@EmilGroup, @opengov, and others) in under 60 seconds. The worm shared C2 "
        "infrastructure (ICP canister) with the Trivy payload.",
        "<b>kamikaze.sh Payloads (Mar 22):</b> The ICP canister fallback C2 served evolving "
        "payloads targeting Kubernetes environments (privileged DaemonSets, host escape), "
        "SSH/Docker worm spreading, and an Iran-targeted destructive wiper.",
        "<b>Internal Aqua Repos Defaced (Mar 22):</b> Using a compromised service account, the "
        "attacker renamed 44 repositories in Aqua's internal <font name='Courier'>aquasec-com</font> "
        "GitHub org with a <font name='Courier'>tpcp-docs-</font> prefix.",
        "<b>Checkmarx KICS Compromised (Mar 23):</b> Same TTPs applied to Checkmarx ecosystem — "
        "35 KICS action versions redirected to malicious commits, with C2 at "
        "<font name='Courier'>checkmarx.zone</font>.",
    ]
    for item in subsequent:
        story.append(Paragraph(f"\u2022 {item}", S_BULLET))
        story.append(Spacer(1, 2))

    story.append(Paragraph("2.6 Impact", S_H2))
    story.append(Paragraph(
        "Only secrets explicitly referenced in the workflow (via <font name='Courier'>"
        "${{ secrets.* }}</font>) are loaded into Runner.Worker memory. "
        "However, any secret the runner had access to should be assumed captured, including:",
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

    story.append(PageBreak())

    # ── 3. ATTACK FLOW DIAGRAM ────────────────────────────────────────────
    story.append(Paragraph("3. Attack Flow Diagram", S_H1))
    story.append(Spacer(1, 8))
    story.append(_build_attack_flow_diagram())
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "The diagram above illustrates the supply-chain attack flow. The attacker exploited "
        "incomplete remediation from the February 28 incident to gain access to the release "
        "automation, published a malicious trivy v0.69.4 binary, and injected credential stealers "
        "into trivy-action and setup-trivy via imposter commits originating from forks. "
        "Downstream CI/CD pipelines that consumed these components had their secrets harvested "
        "from Runner.Worker process memory and exfiltrated to the C2 domain.",
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
         "All tags prior to 0.35.0; version: latest during trivy window",
         "@0.35.0; SHA-pinned refs since 2025-04-09",
         "2026-03-19 ~17:43 – 2026-03-20 ~05:40",
         "~12 hours"],
        ["setup-trivy",
         "All releases",
         "SHA-pinned references",
         "2026-03-19 ~17:43 – ~21:44",
         "~4 hours"],
    ]
    story.append(_make_table(ew_headers, ew_rows, col_widths=[60, 130, 110, 120, 50]))
    story.append(PageBreak())

    # ── 5. TIMELINE ───────────────────────────────────────────────────────
    story.append(Paragraph("5. Timeline &amp; Findings", S_H1))
    story.append(Spacer(1, 8))
    story.append(_build_timeline_diagram(findings))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Key Timeline Events", S_H2))
    timeline_events = [
        ("2026-03-19 ~17:43 UTC", "aqua-bot pushes to v0.69.4 branch; trivy-action and setup-trivy compromised via imposter commits."),
        ("2026-03-19 ~17:51 UTC", "aqua-bot deletes v0.70.0 tag."),
        ("2026-03-19 ~18:22 UTC", "Compromised trivy v0.69.4 binary published to all registries."),
        ("2026-03-19 ~18:30 UTC", "Automated helm chart bump PR opened for v0.69.4."),
        ("2026-03-19 ~21:07 UTC", "nikpivkin deletes compromised setup-trivy v0.2.5 tag."),
        ("2026-03-19 ~21:43 UTC", "simar7 publishes clean setup-trivy v0.2.6."),
        ("2026-03-19 ~23:05 UTC", "Homebrew emergency downgrade PR filed to revert to v0.69.3."),
        ("2026-03-19 ~23:13 UTC", "knqyf263 deletes compromised trivy v0.69.4 tag."),
        ("2026-03-19 ~23:56 UTC", "bored-engineer confirms v0.69.4 compromised and shares IOCs."),
        ("2026-03-20 ~05:40 UTC", "trivy-action fully remediated (last malicious tag removed)."),
        ("2026-03-22", "Attacker pushes malicious trivy v0.69.4, v0.69.5, v0.69.6 images to Docker Hub, GCR.io, and AWS ECR Public."),
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
    ]
    for item in immediate:
        story.append(Paragraph(f"• {item}", S_BULLET))

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
    for title, url in refs:
        story.append(Paragraph(f'• <b>{title}</b><br/><font color="#1565c0">{url}</font>', S_BULLET))
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
