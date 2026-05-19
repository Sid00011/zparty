import json
import logging
import re
from pathlib import Path
import jinja2

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Map CSS variable names to literal values for PDF renderers that don't
# support custom properties (xhtml2pdf)
_CSS_VARS = {
    "--critical": "#dc2626",
    "--high":     "#ea580c",
    "--medium":   "#d97706",
    "--low":      "#65a30d",
    "--info":     "#2563eb",
    "--bg":       "#ffffff",   # white for print
    "--surface":  "#f1f5f9",
    "--border":   "#cbd5e1",
    "--text":     "#0f172a",
    "--muted":    "#475569",
}


def _resolve_css_vars(html: str) -> str:
    """Replace var(--name) with literal values so xhtml2pdf renders colours."""
    def replacer(m: re.Match) -> str:
        name = m.group(1).strip()
        return _CSS_VARS.get(name, m.group(0))
    return re.sub(r"var\((--[\w-]+)\)", replacer, html)


def generate_report(data: dict, session: Path) -> dict:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
    )

    report_dir = session / "report"
    paths = {}

    # Render HTML
    try:
        tmpl = env.get_template("report.html")
        html_content = tmpl.render(**data)
        html_path = report_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        paths["html"] = str(html_path)
        logger.info(f"HTML report: {html_path}")
    except Exception as e:
        logger.error(f"HTML render failed: {type(e).__name__}: {e}")

    # Convert to PDF
    pdf_path = report_dir / "report.pdf"
    if "html" in paths:
        _render_pdf(paths["html"], pdf_path, paths)

    # JSON export
    try:
        json_path = report_dir / "report.json"
        json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        paths["json"] = str(json_path)
        logger.info(f"JSON report: {json_path}")
    except Exception as e:
        logger.error(f"JSON export failed: {type(e).__name__}: {e}")

    return paths


def _render_pdf(html_path: str, pdf_path: Path, paths: dict) -> None:
    # Attempt 1: xhtml2pdf (pure Python — no system DLLs, works on Windows)
    try:
        from xhtml2pdf import pisa
        import logging as _log
        # Suppress xhtml2pdf's noisy warnings
        _log.getLogger("xhtml2pdf").setLevel(_log.ERROR)
        html_content = _resolve_css_vars(
            Path(html_path).read_text(encoding="utf-8")
        )
        with open(str(pdf_path), "wb") as pdf_file:
            result = pisa.CreatePDF(html_content, dest=pdf_file, encoding="utf-8")
        if pdf_path.exists() and pdf_path.stat().st_size > 500:
            paths["pdf"] = str(pdf_path)
            logger.info(f"PDF report (xhtml2pdf): {pdf_path}")
            return
        if result.err:
            logger.warning(f"xhtml2pdf: {result.err} error(s) during PDF creation")
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"xhtml2pdf PDF failed: {type(e).__name__}: {e}")

    # Attempt 2: WeasyPrint
    try:
        from weasyprint import HTML as WP_HTML
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            WP_HTML(filename=html_path).write_pdf(str(pdf_path))
        paths["pdf"] = str(pdf_path)
        logger.info(f"PDF report (WeasyPrint): {pdf_path}")
        return
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"WeasyPrint PDF failed: {type(e).__name__}: {e}")

    # Attempt 3: pdfkit (needs wkhtmltopdf installed separately)
    try:
        import pdfkit
        pdfkit.from_file(html_path, str(pdf_path))
        paths["pdf"] = str(pdf_path)
        logger.info(f"PDF report (pdfkit): {pdf_path}")
        return
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"pdfkit PDF failed: {type(e).__name__}: {e}")

    logger.warning(
        "PDF generation skipped — xhtml2pdf, WeasyPrint, and pdfkit all failed. "
        "HTML and JSON reports are fully functional."
    )
