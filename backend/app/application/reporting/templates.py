"""F5 — Reporting Subsystem : HTML/CSV template generators.

Provides reusable HTML template strings and CSV header/row builders
for each report type.
"""
import csv
import io
from datetime import datetime


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt.tzinfo else dt.strftime("%Y-%m-%d %H:%M:%S")


def _fmt_delta_ms(ms: int | None) -> str:
    if ms is None:
        return "—"
    return f"{ms}ms"


# ── HTML templates ────────────────────────────────────────────

HTML_HEADER = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; color: #333; }}
h1 {{ color: #1a5276; border-bottom: 2px solid #1a5276; padding-bottom: 8px; }}
h2 {{ color: #2c3e50; margin-top: 24px; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
th, td {{ border: 1px solid #bdc3c7; padding: 8px 12px; text-align: left; }}
th {{ background: #1a5276; color: white; }}
tr:nth-child(even) {{ background: #f9f9f9; }}
.status-success {{ color: #27ae60; font-weight: bold; }}
.status-failed {{ color: #e74c3c; font-weight: bold; }}
.status-pending {{ color: #f39c12; font-weight: bold; }}
.footer {{ margin-top: 32px; color: #7f8c8d; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Rapport généré le {generated_at} | Tenant: {tenant_id} | Type: {report_type}</p>
{body}
<div class="footer">
<p>Rapport {report_id} | Généré par {generated_by}</p>
</div>
</body>
</html>"""


def render_html_report(title: str, report_type: str, tenant_id: str,
                        generated_at: str, body: str,
                        report_id: int, generated_by: str) -> str:
    """Render a complete HTML report page."""
    return HTML_HEADER.format(
        title=title,
        report_type=report_type,
        tenant_id=tenant_id,
        generated_at=generated_at,
        body=body,
        report_id=report_id,
        generated_by=generated_by,
    )


# ── Daily report HTML body builder ────────────────────────────

def build_daily_html_body(rows: list[dict], summary: dict) -> str:
    """Build HTML table rows for a daily report."""
    if not rows:
        body = "<p>Aucune donnée pour la période sélectionnée.</p>"
    else:
        cols = set().union(*(r.keys() for r in rows))
        col_names = sorted(cols)
        header = "".join(f"<th>{c}</th>" for c in col_names)
        tr_rows = ""
        for r in rows:
            cells = "".join(
                f"<td>{r.get(c, '—')}</td>"
                for c in col_names
            )
            tr_rows += f"<tr>{cells}</tr>"
        body = (
            f"<table><thead><tr>{header}</tr></thead>"
            f"<tbody>{tr_rows}</tbody></table>"
        )

    summary_html = "<h2>Résumé</h2><ul>"
    for k, v in summary.items():
        summary_html += f"<li><strong>{k}:</strong> {v}</li>"
    summary_html += "</ul>"

    return body + summary_html


# ── Trends report HTML body builder ───────────────────────────

def build_trends_html_body(trends: list[dict], summary: dict) -> str:
    """Build HTML table rows for a trends report."""
    if not trends:
        body = "<p>Aucune donnée de tendance disponible.</p>"
    else:
        cols = set().union(*(r.keys() for r in trends))
        col_names = sorted(cols)
        header = "".join(f"<th>{c}</th>" for c in col_names)
        tr_rows = "".join(
            "<tr>" + "".join(f"<td>{r.get(c, '—')}</td>" for c in col_names) + "</tr>"
            for r in trends
        )
        body = f"<table><thead><tr>{header}</tr></thead><tbody>{tr_rows}</tbody></table>"

    summary_html = "<h2>Résumé des tendances</h2><ul>"
    for k, v in summary.items():
        summary_html += f"<li><strong>{k}:</strong> {v}</li>"
    summary_html += "</ul>"

    return body + summary_html


# ── Case closure HTML body builder ────────────────────────────

def build_case_closure_html_body(case_data: dict, alerts: list[dict],
                                   summary: dict) -> str:
    """Build HTML for a case_closure report."""
    body = "<h2>Détails de l'affaire</h2><table>"
    for k, v in case_data.items():
        body += f"<tr><td>{k}</td><td>{v}</td></tr>"
    body += "</table>"

    if alerts:
        body += "<h2>Alertes associées</h2><table>"
        cols = set().union(*(a.keys() for a in alerts))
        header = "".join(f"<th>{c}</th>" for c in sorted(cols))
        body += f"<thead><tr>{header}</tr></thead><tbody>"
        for a in alerts:
            body += "<tr>" + "".join(f"<td>{a.get(c, '—')}</td>" for c in sorted(cols)) + "</tr>"
        body += "</tbody></table>"

    body += "<h2>Résumé</h2><ul>"
    for k, v in summary.items():
        body += f"<li><strong>{k}:</strong> {v}</li>"
    body += "</ul>"

    return body


# ── CSV builders ──────────────────────────────────────────────

def build_csv(rows: list[dict], title: str) -> str:
    """Build CSV content from a list of dict rows."""
    output = io.StringIO()
    if not rows:
        output.write(f"{title}\nNo data.\n")
        return output.getvalue()

    cols = sorted(set().union(*(r.keys() for r in rows)))
    writer = csv.DictWriter(output, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()})

    return output.getvalue()


def build_case_closure_csv(case_data: dict, alerts: list[dict]) -> str:
    """Build CSV for a case closure report."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Case Closure Report"])
    writer.writerow([])
    writer.writerow(["Case Details"])
    for k, v in case_data.items():
        writer.writerow([k, v])
    writer.writerow([])
    writer.writerow(["Associated Alerts"])
    if alerts:
        alert_cols = sorted(set().union(*(a.keys() for a in alerts)))
        writer.writerow(alert_cols)
        for a in alerts:
            writer.writerow([a.get(c, "—") for c in alert_cols])
    else:
        writer.writerow(["No alerts"])
    return output.getvalue()
