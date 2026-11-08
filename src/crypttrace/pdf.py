"""PDF output: a Unicode font and a page set up for printing.

PDF is what an exchange's compliance team or a police officer asks for. It is
built with fpdf2 (pure Python, the `pdf` extra) using a TrueType font found on
the system, so Russian text and arrows print correctly:

    Windows  Arial / Segoe UI          macOS  Arial (Supplemental)
    Linux    DejaVu Sans, Liberation Sans or Noto Sans

CRYPTTRACE_PDF_FONT (and optionally CRYPTTRACE_PDF_FONT_BOLD) points to any
other .ttf. Addresses and transaction hashes use the built-in Courier: they are
plain ASCII, and a fixed-width face keeps them readable.
"""
import os
from pathlib import Path
from typing import Optional, Tuple

CANDIDATES = [
    ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
    ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf"),
    ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
     "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"),
]
INSTALL_HINT = 'PDF needs the pdf extra: pip install "crypttrace[pdf]" (or crypttrace[web])'


class PdfError(RuntimeError):
    pass


def available() -> bool:
    try:
        import fpdf  # noqa: F401
    except ImportError:
        return False
    return True


def fonts() -> Tuple[str, Optional[str]]:
    """(regular, bold or None) TrueType files with Cyrillic, or PdfError."""
    env = os.environ.get("CRYPTTRACE_PDF_FONT")
    if env:
        if not Path(env).is_file():
            raise PdfError(f"CRYPTTRACE_PDF_FONT points to {env}, which is not a file")
        bold = os.environ.get("CRYPTTRACE_PDF_FONT_BOLD")
        return env, bold if bold and Path(bold).is_file() else None
    for regular, bold in CANDIDATES:
        if Path(regular).is_file():
            return regular, bold if Path(bold).is_file() else None
    raise PdfError("no TrueType font with Cyrillic was found for the PDF; install DejaVu Sans "
                   "(fonts-dejavu-core) or set CRYPTTRACE_PDF_FONT to a .ttf file")


def document(title: str):
    """An A4 FPDF with the Unicode font registered as "body" (regular and bold)."""
    if not available():
        raise PdfError(INSTALL_HINT)
    from fpdf import FPDF

    regular, bold = fonts()

    class _Doc(FPDF):
        def footer(self):
            self.set_y(-12)
            self.set_font("body", size=8)
            self.set_text_color(110)
            self.cell(0, 6, f"{title} · {self.page_no()}/{{nb}}", align="C")
            self.set_text_color(0)

    pdf = _Doc(format="A4")
    pdf.set_title(title)
    pdf.set_creator("crypttrace")
    pdf.add_font("body", "", regular)
    pdf.add_font("body", "B", bold or regular)
    pdf.set_margins(18, 16, 18)
    pdf.set_auto_page_break(True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("body", size=10.5)
    return pdf
