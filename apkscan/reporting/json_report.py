"""JSON report serialization."""

from apkscan.schema import ReportDocument


def render_json(report: ReportDocument, *, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def render_json_bytes(report: ReportDocument) -> bytes:
    return render_json(report).encode("utf-8")
