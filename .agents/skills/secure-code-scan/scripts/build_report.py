#!/usr/bin/env python3
"""Step 6 - Build the Excel (.xlsx) report. Standard library only (no openpyxl needed).

Inputs (defaults under security-report/work/):
  findings.validated.json  (from validate_findings.py)   - required
  deps.json                (from deps.py)                 - optional
  inventory.json           (from inventory.py)            - optional
  candidates.json          (from candidates.py)           - optional
  scan-notes.json          (written by the agent)         - optional: {"limitations": [...],
                           "manual_checks": [{"check": "...", "result": "..."}], "not_reviewed": [...]}
Output: security-report/vulnerability-report.xlsx

Sheets: Summary | Vulnerabilities | Remediation Plan | Dependencies | Dependency Inventory | Coverage
Usage:
  python3 build_report.py [--work security-report/work] [--out security-report/vulnerability-report.xlsx]
"""
import argparse
import datetime
import json
import os
import re
import sys
import zipfile
from xml.sax.saxutils import escape

ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
SEV_STYLE = {"Critical": 3, "High": 4, "Medium": 5, "Low": 6, "Info": 7, "Unrated": 7}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
PRIO_STYLE = {"P1": 3, "P2": 4, "P3": 5, "P4": 6}
PRIORITIES = ["P1 - Fix immediately", "P2 - Fix this sprint", "P3 - Fix next sprint", "P4 - Backlog / hardening"]
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unrated": 5}


def parse_ver(v):
    nums = re.findall(r"\d+", str(v).split("+")[0])
    return tuple(int(n) for n in nums[:4]) if nums else None


def recommend_upgrade(current, advisories):
    """Smallest version that fixes every advisory: for each advisory pick the lowest fixed version
    above the current one (preferring the same major), then take the highest of those."""
    cur = parse_ver(current)
    picks, nofix = [], False
    for v in advisories:
        fv = str(v.get("fixed_versions", ""))
        if fv.lower().startswith(("none", "no fix")):
            nofix = True
            continue
        fixed = [f.strip() for f in fv.split(",") if parse_ver(f.strip())]
        cands = [f for f in fixed if cur is None or parse_ver(f) > cur]
        if not cands:
            nofix = True
            continue
        same_major = [f for f in cands if cur and parse_ver(f)[0] == cur[0]]
        picks.append(min(same_major or cands, key=parse_ver))
    if not picks:
        return "No fixed version published - replace the package or mitigate", True
    best = max(picks, key=parse_ver)
    major = cur is not None and parse_ver(best)[0] != cur[0]
    note = " (MAJOR upgrade - check breaking changes)" if major else ""
    if nofix:
        note += "; some advisories have no fix - review"
    return ">= " + best + note, major


# ------------------------------------------------------------------------------- xlsx writer
def col_letter(n):
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def cell_xml(ref, value, style):
    if value is None or value == "":
        return '<c r="%s" s="%d"/>' % (ref, style)
    if isinstance(value, bool):
        value = "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return '<c r="%s" s="%d"><v>%s</v></c>' % (ref, style, value)
    text = ILLEGAL.sub("", str(value))
    if len(text) > 32000:
        text = text[:32000] + " ...[truncated]"
    return '<c r="%s" s="%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (
        ref, style, escape(text, {'"': "&quot;"}))


class Sheet:
    def __init__(self, name, widths=None, freeze=False, autofilter=False):
        self.name = name[:31]
        self.rows = []          # list of list of (value, style)
        self.widths = widths or []
        self.freeze = freeze
        self.autofilter = autofilter
        self.header_cols = 0

    def add(self, values, style=2, styles=None):
        self.rows.append([(v, (styles[i] if styles and i < len(styles) and styles[i] is not None else style))
                          for i, v in enumerate(values)])

    def header(self, values):
        self.header_cols = len(values)
        self.add(values, style=1)

    def xml(self):
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
               'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">']
        maxc = max([len(r) for r in self.rows] + [1])
        out.append('<dimension ref="A1:%s%d"/>' % (col_letter(maxc), max(len(self.rows), 1)))
        if self.freeze:
            out.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
                       'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
        else:
            out.append('<sheetViews><sheetView workbookViewId="0"/></sheetViews>')
        out.append('<sheetFormatPr defaultRowHeight="15"/>')
        if self.widths:
            out.append("<cols>" + "".join('<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i, i, w)
                                          for i, w in enumerate(self.widths, 1)) + "</cols>")
        out.append("<sheetData>")
        for r, row in enumerate(self.rows, 1):
            out.append('<row r="%d">' % r + "".join(cell_xml("%s%d" % (col_letter(c), r), v, s)
                                                     for c, (v, s) in enumerate(row, 1)) + "</row>")
        out.append("</sheetData>")
        if self.autofilter and self.header_cols and len(self.rows) > 1:
            out.append('<autoFilter ref="%s"/>' % self.filter_ref())
        out.append('<pageMargins left="0.5" right="0.5" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>')
        out.append("</worksheet>")
        return "".join(out)

    def filter_ref(self):
        return "A1:%s%d" % (col_letter(self.header_cols), len(self.rows))


STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="6">
<font><sz val="10"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="10"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="16"/><color rgb="FF1F3864"/><name val="Calibri"/><family val="2"/></font>
<font><sz val="9"/><color rgb="FF1E4620"/><name val="Consolas"/><family val="3"/></font>
</fonts>
<fills count="8">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1F3864"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC00000"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFF4B084"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFE699"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFEDEDED"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="2">
<border><left/><right/><top/><bottom/><diagonal/></border>
<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right><top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border>
</borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="12">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="3" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="6" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="7" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="2" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="top"/></xf>
<xf numFmtId="0" fontId="5" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


def write_xlsx(path, sheets):
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
          '<Default Extension="xml" ContentType="application/xml"/>',
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
          '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>']
    ct += ['<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % i
           for i in range(1, len(sheets) + 1)]
    ct.append("</Types>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>')
    defined = "".join('<definedName name="_xlnm._FilterDatabase" localSheetId="%d" hidden="1">\'%s\'!%s</definedName>'
                      % (i, escape(s.name.replace("'", "''")),
                         "$A$1:$%s$%d" % (col_letter(s.header_cols), len(s.rows)))
                      for i, s in enumerate(sheets) if s.autofilter and s.header_cols and len(s.rows) > 1)
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<bookViews><workbookView xWindow="0" yWindow="0" windowWidth="28800" windowHeight="15000"/></bookViews><sheets>'
          + "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (escape(s.name, {'"': "&quot;"}), i, i)
                    for i, s in enumerate(sheets, 1))
          + "</sheets>" + ("<definedNames>%s</definedNames>" % defined if defined else "") + "</workbook>")
    wbrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i, i)
                        for i in range(1, len(sheets) + 1))
              + '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (len(sheets) + 1)
              + "</Relationships>")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:title>Source Code Vulnerability Report</dc:title><dc:creator>secure-code-scan</dc:creator>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>'
            '<dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified></cp:coreProperties>' % (now, now))
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>secure-code-scan</Application></Properties>')
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "".join(ct))
        z.writestr("_rels/.rels", rels)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wbrels)
        z.writestr("xl/styles.xml", STYLES)
        for i, s in enumerate(sheets, 1):
            z.writestr("xl/worksheets/sheet%d.xml" % i, s.xml())


# ------------------------------------------------------------------------------- report
def load(path, default):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return default


SECRET_CWES = {"CWE-798", "CWE-321", "CWE-259", "CWE-522", "CWE-256", "CWE-312"}
_TOKEN = re.compile(r"(AKIA|ASIA|ghp_|gho_|github_pat_|glpat-|xox[abposr]-|sk_live_|rk_live_|sk-|AIza|SG\.|hf_|eyJ)[A-Za-z0-9_\-./+=]{6,}")
_ASSIGN = re.compile(r"""((?:=|:|=>|:=)\s*['"]?|\s(?=[^\s=]{8,}\s*$))([^'"\s,;)}]{4,})""")
_URLCRED = re.compile(r"(://[^:/\s'\"]+:)([^@\s'\"]{3,})(@)")
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.S)


def _mask_value(v):
    return v[:4] + "*" * 8 + (v[-2:] if len(v) > 10 else "")


def mask_secrets(text):
    """Mask credential values so the shared report never contains live secrets."""
    if not text:
        return text
    if _PEM.search(text):
        return _PEM.sub("-----BEGIN PRIVATE KEY----- [redacted]", text)
    text = _URLCRED.sub(lambda m: m.group(1) + "****" + m.group(3), text)
    text = _TOKEN.sub(lambda m: _mask_value(m.group(0)), text)
    return _ASSIGN.sub(lambda m: m.group(1) + (m.group(2) if "*" * 8 in m.group(2) else _mask_value(m.group(2))), text)


def mask_secret_line(text):
    """mask_secrets + fallback: a bare secret (no key=value form) gets its long tokens masked."""
    if not text:
        return text
    masked = mask_secrets(text)
    # any quoted literal without spaces, >= 8 chars, is treated as a secret value
    masked = re.sub(r"(['\"`])([^\s'\"`]{8,})\1",
                    lambda m: m.group(1) + (m.group(2) if "*" * 8 in m.group(2) else _mask_value(m.group(2))) + m.group(1), masked)
    if masked == text:
        masked = re.sub(r"[^\s'\"`,;:=(){}\[\]]{12,}", lambda m: _mask_value(m.group(0)), text)
    return masked


def is_secret_finding(f):
    return f.get("cwe") in SECRET_CWES or f.get("category") == "hardcoded-secret"


def path_text(f):
    steps = f.get("path") or []
    if not steps:
        return "" if f.get("flow") != "taint" else "%s:%s -> %s:%s" % (
            f["source"]["file"], f["source"]["line"], f["sink"]["file"], f["sink"]["line"])
    parts = ["[source] %s:%s" % (f["source"]["file"], f["source"]["line"])]
    for st in steps:
        parts.append("%s:%s%s" % (st["file"], st["line"], (" - " + st["note"]) if st.get("note") else ""))
    parts.append("[sink] %s:%s" % (f["sink"]["file"], f["sink"]["line"]))
    return "\n-> ".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default="security-report/work")
    ap.add_argument("--out", default="security-report/vulnerability-report.xlsx")
    a = ap.parse_args()
    w = a.work
    vf = load(os.path.join(w, "findings.validated.json"), None)
    if vf is None:
        sys.exit("Missing %s - run validate_findings.py first." % os.path.join(w, "findings.validated.json"))
    findings = vf.get("findings", [])
    deps = load(os.path.join(w, "deps.json"), {})
    inv = load(os.path.join(w, "inventory.json"), {})
    cand = load(os.path.join(w, "candidates.json"), {})
    notes = load(os.path.join(w, "scan-notes.json"), {})
    dvulns = deps.get("vulnerabilities", [])

    # ---------------- Vulnerabilities
    vs = Sheet("Vulnerabilities", [11, 34, 40, 9, 40, 9, 10, 11, 18, 10, 30, 30, 10, 34, 44, 50, 60, 60, 60, 45, 34, 14],
               freeze=True, autofilter=True)
    vs.header(["ID", "Vulnerability Name", "Source File Path", "Source Line", "Sink File Path", "Sink Line",
               "Severity", "Confidence", "Fix Priority", "CWE", "OWASP Top 10 2025", "OWASP Top 10 2021", "Flow Type",
               "Source (untrusted input)", "Sink (vulnerable code)", "Data-flow Path", "Description",
               "Remediation", "Secure Code Example", "How to Verify Fix", "References", "Triage Status"])
    for f in findings:
        src, snk = f["source"], f["sink"]
        src_txt = src.get("expression") or src.get("code", "")
        snk_txt = snk.get("code", "")
        if snk.get("expression") and snk["expression"] not in snk_txt:
            snk_txt = snk["expression"] + "\n" + snk_txt
        if is_secret_finding(f):
            src_txt, snk_txt = mask_secret_line(src_txt), mask_secret_line(snk_txt)
        desc = f.get("description", "")
        if f.get("evidence"):
            desc += "\n\nEvidence: " + f["evidence"]
        prio = f.get("fix_priority", "")
        vs.add([f["id"], f["title"], src["file"], src["line"], snk["file"], snk["line"], f["severity"],
                f["confidence"], prio, f["cwe"], f.get("owasp_2025", ""), f.get("owasp_2021", ""),
                "Taint (source->sink)" if f["flow"] == "taint" else "Single-point",
                src_txt, snk_txt, path_text(f), desc, f.get("remediation", ""),
                f.get("secure_example", ""), f.get("verification", ""),
                "\n".join(f.get("references") or []), ""],
               styles=[10, 9, None, 10, None, 10, SEV_STYLE.get(f["severity"], 2), 10, PRIO_STYLE.get(prio[:2], 2), 10,
                       None, None, None, 11, 11, None, None, None, 11])

    # ---------------- Dependencies
    # per-package upgrade recommendation
    by_pkg = {}
    for v in dvulns:
        by_pkg.setdefault((v["ecosystem"], v["package"], v["version"], v["manifest"]), []).append(v)
    upgrade = {k: recommend_upgrade(k[2], vs_) for k, vs_ in by_pkg.items()}

    ds = Sheet("Dependencies", [11, 30, 14, 11, 22, 18, 10, 8, 50, 22, 34, 36, 9, 9, 40], freeze=True, autofilter=True)
    ds.header(["ID", "Package", "Installed Version", "Ecosystem", "Vulnerability ID", "CVE", "Severity", "CVSS",
               "Summary", "Fixed In", "Recommended Upgrade (fixes all advisories)", "Manifest File Path",
               "Manifest Line", "Scope", "Advisory URL"])
    for n, v in enumerate(dvulns, 1):
        ver = v["version"] + ("" if v.get("pinned", True) else " (declared range - verify)")
        rec = upgrade[(v["ecosystem"], v["package"], v["version"], v["manifest"])][0]
        ds.add(["DEP-%04d" % n, v["package"], ver, v["ecosystem"], v["id"], v.get("cve", ""), v["severity"],
                v.get("cvss_score") if v.get("cvss_score") is not None else "", v.get("summary", ""),
                v.get("fixed_versions", ""), rec, v["manifest"], v["line"], v.get("scope", ""), v.get("url", "")],
               styles=[10, 9, 10, 10, None, None, SEV_STYLE.get(v["severity"], 2), 10, None, None, 9, None, 10, 10])
    if not dvulns:
        ds.add(["-", "No vulnerable dependencies reported", "", "", "", "", "", "", deps.get("osv_status", "deps.py not run"),
                "", "", "", "", "", ""])

    # ---------------- Remediation Plan
    rp = Sheet("Remediation Plan", [22, 36, 10, 11, 12, 46, 70, 60])
    rp.add(["Remediation Plan"], styles=[8])
    rp.add(["Code fixes grouped by vulnerability type, highest priority first. Each row lists the affected "
            "findings; full per-finding fix, secure code example and verification are on the Vulnerabilities sheet."],
           styles=[0])
    rp.add([""], style=0)
    rp.header(["Fix Priority", "Vulnerability", "Severity", "Count", "Effort", "Affected Findings (ID - sink location)",
               "Fix Guideline", "How to Verify"])
    groups = {}
    for f in findings:
        groups.setdefault(f["title"], []).append(f)

    def grp_key(item):
        fs = item[1]
        return (min(PRIORITIES.index(f.get("fix_priority", PRIORITIES[-1])) if f.get("fix_priority") in PRIORITIES else 3
                    for f in fs), min(SEV_RANK.get(f["severity"], 9) for f in fs), -len(fs))
    for title, fs in sorted(groups.items(), key=grp_key):
        fs = sorted(fs, key=lambda f: (f.get("fix_priority", "P4"), SEV_RANK.get(f["severity"], 9)))
        top = fs[0]
        prio = top.get("fix_priority", "")
        sev = min((f["severity"] for f in fs), key=lambda s: SEV_RANK.get(s, 9))
        efforts = sorted({f.get("effort") for f in fs if f.get("effort")})
        locs = "\n".join("%s - %s:%s" % (f["id"], f["sink"]["file"], f["sink"]["line"]) for f in fs)
        guide = top.get("remediation", "")
        if len(fs) > 1:
            guide = "[from %s] %s" % (top["id"], guide)
        rp.add([prio, title, sev, len(fs), "/".join(efforts), locs, guide, top.get("verification", "")],
               styles=[PRIO_STYLE.get(prio[:2], 2), 9, SEV_STYLE.get(sev, 2), 10, 10])
    if not findings:
        rp.add(["-", "No code findings", "", 0, "", "", "", ""])
    rp.add([""], style=0)
    rp.header(["Fix Priority", "Package (Ecosystem)", "Severity", "Advisories", "Current", "Manifest File (line)",
               "Recommended Upgrade", "Notes"])
    pkg_rows = []
    for (eco, name, ver, man), vs_ in by_pkg.items():
        sev = min((v["severity"] for v in vs_), key=lambda s: SEV_RANK.get(s, 9))
        prio = PRIORITIES[0] if sev == "Critical" else PRIORITIES[1] if sev == "High" else PRIORITIES[2] if sev == "Medium" else PRIORITIES[3]
        rec, major = upgrade[(eco, name, ver, man)]
        cves = sorted({c.strip() for v in vs_ for c in v.get("cve", "").split(",") if c.strip()})
        pnote = ("CVEs: " + ", ".join(cves[:8]) + (" ..." if len(cves) > 8 else "")) if cves else ""
        if not vs_[0].get("pinned", True):
            pnote += ("; " if pnote else "") + "declared range - commit a lockfile and confirm installed version"
        pkg_rows.append((PRIORITIES.index(prio), SEV_RANK.get(sev, 9), [prio, "%s (%s)" % (name, eco), sev, len(vs_), ver,
                         "%s (%s)" % (man, vs_[0]["line"]), rec, pnote]))
    for _, _, row in sorted(pkg_rows, key=lambda r: (r[0], r[1], -r[2][3])):
        rp.add(row, styles=[PRIO_STYLE.get(row[0][:2], 2), 9, SEV_STYLE.get(row[2], 2), 10, 10])
    if not pkg_rows:
        rp.add(["-", "No vulnerable dependencies", "", "", "", "", "", deps.get("osv_status", "")])

    inv_s = Sheet("Dependency Inventory", [36, 16, 11, 40, 9, 10, 9], freeze=True, autofilter=True)
    inv_s.header(["Package", "Version", "Ecosystem", "Manifest File Path", "Line", "Scope", "Pinned"])
    for p in deps.get("packages", []):
        inv_s.add([p["name"], p["version"] or "(unpinned)", p["ecosystem"], p["manifest"], p["line"], p.get("scope", ""),
                   "Yes" if p.get("pinned") else "No"], styles=[None, None, 10, None, 10, 10, 10])

    # ---------------- Summary
    sm = Sheet("Summary", [40, 70, 20, 12])
    sm.add(["Source Code Vulnerability Report"], styles=[8])
    sm.add([""], style=0)
    meta = [("Project", inv.get("project_name") or inv.get("project_root", "")),
            ("Scan date", inv.get("scanned_at") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("Files analysed", inv.get("total_files_analyzed", "")),
            ("Lines of code", inv.get("total_lines", "")),
            ("Languages", ", ".join("%s (%d files)" % (k, v["files"]) for k, v in (inv.get("languages") or {}).items())),
            ("Frameworks detected", ", ".join(inv.get("frameworks_detected") or []) or "none detected"),
            ("Method", "Agent-driven manual taint analysis + pattern hotspot index + OSV dependency lookup "
                       "(OWASP Secure Coding Practices / ASVS / Top 10 / CWE Top 25 guidelines)"),
            ("Dependency lookup", deps.get("osv_status", "not run"))]
    for k, v in meta:
        sm.add([k, v], styles=[9, 2])
    sm.add([""], style=0)
    sm.header(["Severity", "Code findings", "Dependency findings", "Total"])
    for s in SEVERITIES + ["Unrated"]:
        c = sum(1 for f in findings if f["severity"] == s)
        d = sum(1 for v in dvulns if v["severity"] == s)
        if s == "Unrated" and not d:
            continue
        sm.add([s, c, d, c + d], styles=[SEV_STYLE[s], 10, 10, 10])
    sm.add(["Total", len(findings), len(dvulns), len(findings) + len(dvulns)], styles=[9, 10, 10, 10])
    sm.add([""], style=0)
    sm.header(["Remediation roadmap", "Code findings (IDs)", "Vulnerable packages", "Total"])
    pkg_prio = {}
    for row in pkg_rows:
        pkg_prio[PRIORITIES[row[0]]] = pkg_prio.get(PRIORITIES[row[0]], 0) + 1
    for p in PRIORITIES:
        ids = [f["id"] for f in findings if f.get("fix_priority") == p]
        shown = ", ".join(ids[:15]) + (" ... (+%d)" % (len(ids) - 15) if len(ids) > 15 else "")
        sm.add([p, ("%d: %s" % (len(ids), shown)) if ids else 0, pkg_prio.get(p, 0), len(ids) + pkg_prio.get(p, 0)],
               styles=[PRIO_STYLE[p[:2]], 2, 10, 10])
    sm.add([""], style=0)
    sm.header(["Vulnerability type", "Count", "Highest severity"])
    by_title = {}
    for f in findings:
        t = by_title.setdefault(f["title"], [0, "Info"])
        t[0] += 1
        if SEVERITIES.index(f["severity"]) < SEVERITIES.index(t[1]):
            t[1] = f["severity"]
    for t, (c, s) in sorted(by_title.items(), key=lambda kv: (SEVERITIES.index(kv[1][1]), -kv[1][0])):
        sm.add([t, c, s], styles=[2, 10, SEV_STYLE[s]])
    sm.add([""], style=0)
    sm.header(["OWASP Top 10 2025 category", "Count"])
    by_ow = {}
    for f in findings:
        by_ow[f.get("owasp_2025", "")] = by_ow.get(f.get("owasp_2025", ""), 0) + 1
    if dvulns:
        k = "A03:2025-Software Supply Chain Failures (dependencies)"
        by_ow[k] = by_ow.get(k, 0) + len(dvulns)
    for k in sorted(by_ow):
        sm.add([k, by_ow[k]], styles=[2, 10])

    # ---------------- Coverage
    cv = Sheet("Coverage", [36, 90])
    cv.header(["Item", "Detail"])
    cv.add(["Project root", inv.get("project_root", "")], styles=[9])
    cv.add(["Files analysed / lines", "%s files / %s lines" % (inv.get("total_files_analyzed", "?"), inv.get("total_lines", "?"))], styles=[9])
    cv.add(["Skipped (by reason)", ", ".join("%s: %d" % kv for kv in (inv.get("skipped_summary") or {}).items()) or "none"], styles=[9])
    excl = sorted({s["path"] for s in inv.get("skipped", []) if s["reason"] == "excluded-dir"})
    cv.add(["Excluded directories", ", ".join(excl[:200]) + (" ..." if len(excl) > 200 else "") or "none"], styles=[9])
    cv.add(["Manifests found", ", ".join(inv.get("manifests") or []) or "none"], styles=[9])
    cv.add(["Hotspot index", "%s pattern hits across %s files (%s patterns)" % (
        len(cand.get("hits", [])), cand.get("files_scanned", "?"), cand.get("patterns_loaded", "?"))], styles=[9])
    confirmed = {}
    for f in findings:
        confirmed[f.get("category") or f["cwe"]] = confirmed.get(f.get("category") or f["cwe"], 0) + 1
    for catg, n in (cand.get("counts_by_category") or {}).items():
        cv.add(["Hotspots: " + catg, "%d candidate lines reviewed -> %d confirmed finding(s)" % (n, confirmed.get(catg, 0))], styles=[9])
    cv.add(["Findings rejected by validator", str(len(vf.get("rejected", [])))], styles=[9])
    cv.add(["Dependency manifests parsed", ", ".join("%s (%d)" % (m["manifest"], m["packages"]) for m in deps.get("manifests_parsed", [])) or "none"], styles=[9])
    cv.add(["Unpinned / range dependencies", str(len(deps.get("unpinned", [])))], styles=[9])
    for mc in notes.get("manual_checks", []):
        cv.add(["Check: " + str(mc.get("check", "")), str(mc.get("result", ""))], styles=[9])
    for nr in notes.get("not_reviewed", []):
        cv.add(["Not reviewed", str(nr)], styles=[9])
    for lim in notes.get("limitations", []) or [
            "Static review only - no code was executed; runtime configuration and deployed infrastructure were not tested.",
            "Pattern hotspots guide the review; flows not matching any pattern rely on the agent's entry-point review.",
            "Findings marked Confidence=Low need manual confirmation before remediation work is prioritised."]:
        cv.add(["Limitation", str(lim)], styles=[9])

    write_xlsx(a.out, [sm, vs, rp, ds, inv_s, cv])
    print("Report written: %s" % os.path.abspath(a.out))
    print("  Vulnerabilities: %d   Dependency vulns: %d   Packages: %d" % (len(findings), len(dvulns), len(deps.get("packages", []))))


if __name__ == "__main__":
    main()
