"""CSV export with StreamingResponse."""
import csv
import io

from fastapi.responses import StreamingResponse


def export_alerts_csv(alerts: list, filename: str = "alerts.csv") -> StreamingResponse:
    """Export alerts as CSV with BOM for Excel."""
    def generate():
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(["\ufeffID", "Timestamp", "Severity", "Description", "Source IP", "Agent ID", "Source"])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for a in alerts:
            w.writerow([
                a.id,
                a.timestamp.isoformat() if a.timestamp else "",
                a.severity,
                a.description or "",
                a.src_ip or "",
                a.agent_id or "",
                a.pipeline_source or "",
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(
        generate(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def export_suricata_csv(alerts: list, filename: str = "suricata_alerts.csv") -> StreamingResponse:
    """Export Suricata alerts as CSV."""
    def generate():
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\r\n")
        w.writerow(["\ufeffID", "Timestamp", "Severity", "Event Type", "Alert Message", "Source IP", "Dest IP", "Proto"])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for a in alerts:
            w.writerow([
                a.id,
                a.timestamp.isoformat() if a.timestamp else "",
                a.severity,
                a.event_type or "",
                a.alert_msg or "",
                a.src_ip or "",
                a.dest_ip or "",
                a.proto or "",
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(
        generate(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
