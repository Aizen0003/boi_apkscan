"""Report generation (T0.14 / AC6): build a ReportDocument, render JSON + PDF."""

from apkscan.reporting.builder import build_report_document
from apkscan.reporting.json_report import render_json
from apkscan.reporting.pdf_report import render_pdf

__all__ = ["build_report_document", "render_json", "render_pdf"]
