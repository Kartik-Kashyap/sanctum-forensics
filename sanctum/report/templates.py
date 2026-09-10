"""
Report rendering templates.

Kept apart from the builder so the presentation can be restyled without
touching report logic - and so the HTML is auditable as markup rather than
assembled from concatenated strings in the middle of data handling.

The stylesheet is inline and dependency-free: a report must open correctly on
an air-gapped examiner's workstation with no network and no assets to fetch.
It is also print-ready, so "Export to PDF" is the browser's own print dialog
rather than a heavyweight PDF toolchain.
"""

from __future__ import annotations

STYLESHEET = """
:root {
  --ink: #14181f; --muted: #5b6572; --line: #d9dee6; --bg: #ffffff;
  --panel: #f6f8fb; --accent: #1f5f8b; --accent-soft: #e8f1f8;
  --ok: #1c7a4a; --ok-soft: #e6f5ec; --warn: #9a6400; --warn-soft: #fdf3e0;
  --bad: #a52121; --bad-soft: #fdeceb;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 40px 32px 64px; background: var(--bg); color: var(--ink);
  font: 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; }
header.report-head { border-bottom: 3px solid var(--accent); padding-bottom: 20px; margin-bottom: 28px; }
.brand { font-size: 12px; letter-spacing: .16em; text-transform: uppercase; color: var(--accent); font-weight: 700; }
h1 { font-size: 25px; margin: 8px 0 6px; letter-spacing: -0.01em; }
h2 { font-size: 16px; margin: 34px 0 12px; padding-bottom: 7px; border-bottom: 1px solid var(--line); }
h3 { font-size: 13px; margin: 20px 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; }
.sub { color: var(--muted); font-size: 13px; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; margin: 18px 0 4px; }
.meta { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 11px 13px; }
.meta .k { font-size: 11px; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }
.meta .v { font-size: 14px; font-weight: 600; margin-top: 3px; word-break: break-word; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--panel); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.hash { word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }
.pill { display: inline-block; padding: 2px 9px; border-radius: 11px; font-size: 11px; font-weight: 700; letter-spacing: .03em; }
.pill.ok { background: var(--ok-soft); color: var(--ok); }
.pill.warn { background: var(--warn-soft); color: var(--warn); }
.pill.bad { background: var(--bad-soft); color: var(--bad); }
.pill.info { background: var(--accent-soft); color: var(--accent); }
.callout { border-left: 4px solid var(--accent); background: var(--accent-soft); padding: 13px 16px; border-radius: 0 6px 6px 0; margin: 14px 0; }
.callout.warn { border-color: var(--warn); background: var(--warn-soft); }
.callout.bad { border-color: var(--bad); background: var(--bad-soft); }
.callout.ok { border-color: var(--ok); background: var(--ok-soft); }
.callout p { margin: 5px 0; }
ul.limits { margin: 8px 0; padding-left: 20px; }
ul.limits li { margin: 5px 0; }
footer.report-foot { margin-top: 44px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
@media print {
  body { padding: 0; font-size: 11.5px; }
  h2 { page-break-after: avoid; }
  table { page-break-inside: auto; }
  tr { page-break-inside: avoid; }
  .no-print { display: none; }
}
"""


def html_escape(value) -> str:
    """Minimal HTML escaping for interpolated values."""
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def pill(label: str, tone: str = "info") -> str:
    """A small status chip."""
    return f'<span class="pill {tone}">{html_escape(label)}</span>'


def document(title: str, body: str, *, subtitle: str = "", footer: str = "") -> str:
    """Wrap rendered sections in a complete, self-contained HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html_escape(title)}</title>
<style>{STYLESHEET}</style>
</head>
<body>
<div class="wrap">
<header class="report-head">
  <div class="brand">SANCTUM &middot; Digital Forensics &amp; Data Sanitization</div>
  <h1>{html_escape(title)}</h1>
  {f'<div class="sub">{html_escape(subtitle)}</div>' if subtitle else ''}
</header>
{body}
<footer class="report-foot">{footer or 'Generated by SANCTUM'} &middot; This report is machine-generated from a tamper-evident audit chain.</footer>
</div>
</body>
</html>
"""


def meta_grid(items: dict) -> str:
    """A responsive grid of key/value cards."""
    cells = "".join(
        f'<div class="meta"><div class="k">{html_escape(k)}</div>'
        f'<div class="v">{html_escape(v)}</div></div>'
        for k, v in items.items()
    )
    return f'<div class="meta-grid">{cells}</div>'


def table(headers: list[str], rows: list[list[str]], *, numeric_columns: set[int] | None = None) -> str:
    """Render a data table. Cell values are escaped unless marked as raw HTML."""
    numeric_columns = numeric_columns or set()
    head = "".join(
        f'<th class="{"num" if i in numeric_columns else ""}">{html_escape(h)}</th>'
        for i, h in enumerate(headers)
    )
    body_rows = []
    for row in rows:
        cells = "".join(
            f'<td class="{"num" if i in numeric_columns else ""}">{cell}</td>'
            for i, cell in enumerate(row)
        )
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        f"<table><thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )


def callout(title: str, body: str, tone: str = "info") -> str:
    return (
        f'<div class="callout {tone}"><strong>{html_escape(title)}</strong>'
        f"<p>{body}</p></div>"
    )
