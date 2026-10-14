"""PDF export using xhtml2pdf (pure Python, no system deps)."""
import io
import logging
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "templates" / "reports"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))


def render_pdf_from_html(html_content: str) -> bytes:
    """Render HTML to PDF bytes using xhtml2pdf."""
    from xhtml2pdf import pisa
    buf = io.BytesIO()
    pisa_status = pisa.CreatePDF(io.StringIO(html_content), dest=buf)
    if pisa_status.err:
        logger.warning("PDF rendering had %d errors", pisa_status.err)
    return buf.getvalue()


def export_alerts_pdf(alerts: list) -> bytes:
    """Render alert list as PDF."""
    template = _env.get_template("alert_report.html")
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    html = template.render(alerts=alerts, generated_at=now)
    return render_pdf_from_html(html)


def export_case_markdown(case, alerts: list) -> str:
    """Render case as Markdown string."""
    template = _env.get_template("case_report.md")
    return template.render(case=case, alerts=alerts)
