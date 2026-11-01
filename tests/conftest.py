from __future__ import annotations

import pytest

from stripii import Scrubber, get_profile


def _crypto_available() -> bool:
    """Whether vault encryption can actually run here.

    Not importlib.util.find_spec: a half-installed `cryptography` (missing cffi
    backend, ABI mismatch) is found but fails on import, and it fails from its
    Rust bindings as a BaseException rather than an ImportError.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except (KeyboardInterrupt, SystemExit):  # pragma: no cover
        raise
    except BaseException:
        return False
    return True


#: Applied per-test, never at module level: a module-level importorskip would
#: take the whole file with it, and most vault tests (file permissions, the
#: plaintext round trip, the refusals) have nothing to do with encryption.
requires_crypto = pytest.mark.skipif(
    not _crypto_available(), reason="needs a working stripii[crypto] install"
)

HEALTH_REPORT = """NORTHSIDE MEDICAL CENTER - DISCHARGE SUMMARY

Patient Name: Margaret Ellen Whitfield
MRN: 4471982
Date of Birth: 03/14/1934
Age: 91 years old
Address: 1847 Oakmont Drive, Apt 3B, Springfield, IL 62704
Phone: (217) 555-0142
Email: m.whitfield@example.com
SSN: 412-88-9031
Member ID: XHP449182736
Admission Date: 2025-08-02   Discharge Date: 2025-08-09

Attending: Dr. Robert Chen, MD  (NPI 1234567893)
Interpreted by Priya Sharma, MD

ASSESSMENT
Complete Blood Count showed Hemoglobin 10.2 g/dL (low), Hematocrit 31%.
Comprehensive Metabolic Panel: Glucose 142 mg/dL, Creatinine 1.8 mg/dL.
Diagnosis: Type 2 Diabetes Mellitus (E11.9), Hypertension (I10).
Chest X-Ray negative for acute process. Echocardiogram showed EF 45%.
Plan: continue metformin 1000 mg BID, follow up in Cardiology in 2 weeks.
"""

#: Every string in the report that must not survive scrubbing.
HEALTH_IDENTIFIERS = [
    "Margaret Ellen Whitfield",
    "Margaret",
    "Whitfield",
    "4471982",
    "03/14/1934",
    "1847 Oakmont Drive",
    "Springfield",
    "62704",
    "555-0142",
    "m.whitfield@example.com",
    "412-88-9031",
    "XHP449182736",
    "Robert Chen",
    "Priya Sharma",
    "1234567893",
]

#: Clinical content that must survive, or the redacted report is worthless.
HEALTH_MUST_KEEP = [
    "Hemoglobin 10.2 g/dL",
    "Hematocrit 31%",
    "Glucose 142 mg/dL",
    "Creatinine 1.8 mg/dL",
    "E11.9",
    "I10",
    "Type 2 Diabetes Mellitus",
    "Hypertension",
    "metformin 1000 mg BID",
    "EF 45%",
    "Cardiology",
    "Complete Blood Count",
    "Chest X-Ray",
]

FINANCE_STATEMENT = """FIRST MERIDIAN BANK - ACCOUNT STATEMENT
Statement Period: 07/01/2025 to 07/31/2025

Account Holder: Michael J. Rodriguez
Address: 4120 Bellevue Ave, Seattle, WA 98105
Account Number: 483920175
Routing Number: 021000021
Card ending: 4111 1111 1111 1111  Exp 11/27  CVV 837
IBAN: GB82 WEST 1234 5698 7654 32
Contact: mrodriguez@example.net / (206) 555-0199
Tax ID (SSN): 412-88-9031

TRANSACTIONS
07/03/2025  Payroll Deposit - ACME CORP        +4,820.55
07/08/2025  Mortgage Payment                   -2,150.00
07/15/2025  Grocery Purchase                     -184.32
Closing Balance                                 14,209.87
"""

FINANCE_IDENTIFIERS = [
    "Michael J. Rodriguez",
    "Rodriguez",
    "4120 Bellevue Ave",
    "Seattle",
    "98105",
    "483920175",
    "021000021",
    "4111 1111 1111 1111",
    "GB82 WEST 1234 5698 7654 32",
    "mrodriguez@example.net",
    "555-0199",
    "412-88-9031",
]

#: A finance profile that destroyed the numbers would defeat the purpose.
FINANCE_MUST_KEEP = [
    "07/03/2025",
    "07/15/2025",
    "+4,820.55",
    "-2,150.00",
    "-184.32",
    "14,209.87",
    "Payroll Deposit",
    "Mortgage Payment",
]


@pytest.fixture
def health_text() -> str:
    return HEALTH_REPORT


@pytest.fixture
def finance_text() -> str:
    return FINANCE_STATEMENT


@pytest.fixture
def scrub():
    """Scrub text under a named profile, returning ``(text, result, vault)``."""

    def _scrub(text: str, profile: str = "default"):
        result, vault = Scrubber(get_profile(profile)).scrub(text)
        return result.text, result, vault

    return _scrub


def _module_available(name: str) -> bool:
    try:
        __import__(name)
    except (KeyboardInterrupt, SystemExit):  # pragma: no cover
        raise
    except BaseException:
        return False
    return True


requires_pdf = pytest.mark.skipif(
    not _module_available("pypdf"), reason="needs a working stripii[pdf] install"
)

requires_pdf_tables = pytest.mark.skipif(
    not _module_available("pdfplumber"), reason="needs pdfplumber for table extraction"
)

requires_docx = pytest.mark.skipif(
    not _module_available("docx"), reason="needs a working stripii[docx] install"
)

requires_xlsx = pytest.mark.skipif(
    not _module_available("openpyxl"), reason="needs a working stripii[xlsx] install"
)

#: One lab panel, used across the reader tests so each format can be compared
#: against the same expected grid.
LAB_ROWS = [
    ["Test", "Result", "Ref Range", "Flag"],
    ["Hemoglobin", "10.2", "12.0-15.5", "LOW"],
    ["Glucose", "142", "70-99", "HIGH"],
    ["Creatinine", "1.8", "0.6-1.1", "HIGH"],
]
LAB_HEADING = "Patient: Margaret Whitfield   MRN: 4471982"


def write_docx_with_table(path) -> None:
    import docx

    document = docx.Document()
    document.add_paragraph(LAB_HEADING)
    table = document.add_table(rows=len(LAB_ROWS), cols=len(LAB_ROWS[0]))
    for r, row in enumerate(LAB_ROWS):
        for c, value in enumerate(row):
            table.cell(r, c).text = value
    document.save(str(path))


def write_xlsx_with_table(path) -> None:
    import openpyxl

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Labs"
    for row in LAB_ROWS:
        sheet.append(row)
    book.save(str(path))


def blank_pdf_bytes() -> bytes:
    """A valid one-page PDF with no text operators -- i.e. what a scan looks like."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    start = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{start}\n%%EOF\n"
    ).encode()
    return bytes(out)


def _tesseract_ready() -> bool:
    from stripii.ocr import tesseract_available

    return _module_available("pytesseract") and _module_available("pypdfium2") and (
        _module_available("PIL") and tesseract_available()
    )


def _vision_ready() -> bool:
    from stripii.ocr import vision_available

    return vision_available() and _module_available("pypdfium2") and _module_available("PIL")


requires_ocr = pytest.mark.skipif(
    not (_tesseract_ready() and _module_available("reportlab")),
    reason="needs stripii[ocr], the tesseract engine on PATH, and reportlab",
)

requires_any_ocr = pytest.mark.skipif(
    not ((_tesseract_ready() or _vision_ready()) and _module_available("reportlab")),
    reason="needs an OCR engine (stripii[ocr] + tesseract, or stripii[vision] on macOS) and reportlab",
)

requires_heif = pytest.mark.skipif(
    not _module_available("pillow_heif"), reason="needs stripii[photo] (pillow-heif)"
)


def ocr_backends() -> list[str]:
    """Every OCR engine that can run here, so each test runs on all of them."""
    available = []
    if _vision_ready():
        available.append("vision")
    if _tesseract_ready():
        available.append("tesseract")
    return available

OCR_LINES = [
    "NORTHSIDE MEDICAL CENTER",
    "Patient Name: Margaret Whitfield",
    "MRN: 4471982",
    "SSN: 412-88-9031",
    "Email: m.whitfield@example.com",
    "Phone: (217) 555-0142",
    "Hemoglobin 10.2 g/dL, Glucose 142 mg/dL.",
]


def write_scanned_pdf(path) -> None:
    """A PDF with no text layer: rendered to a raster, exactly like a scan."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate

    from stripii import ocr

    source = path.with_name("_source.pdf")
    style = getSampleStyleSheet()["Normal"]
    SimpleDocTemplate(str(source), pagesize=letter).build(
        [Paragraph(line, style) for line in OCR_LINES]
    )
    ocr.save_pdf(ocr.render_pdf(source), path)


def write_photo(path, *, orientation: int = 1, size=(1400, 1000)) -> None:
    """A "photo" of the same lines, optionally stored sideways with an EXIF tag.

    ``orientation`` is the EXIF value: 1 is upright; 6 means the pixels are
    stored rotated 90 degrees anticlockwise and a viewer must turn them
    clockwise -- the way an iPhone held upright stores a portrait shot.
    """
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 34)
    except OSError:
        font = ImageFont.load_default(34)
    for index, line in enumerate(OCR_LINES):
        draw.text((60, 60 + index * 70), line, fill="black", font=font)

    suffix = path.suffix.lower()
    if suffix in {".heic", ".heif"}:
        import pillow_heif

        pillow_heif.register_heif_opener()
    options = {}
    if orientation == 6:
        image = image.rotate(90, expand=True)
        exif = Image.Exif()
        exif[0x0112] = orientation
        options["exif"] = exif.tobytes()
    elif suffix in {".jpg", ".jpeg"}:
        # GPS and a camera serial: what a redacted photo must not carry out.
        exif = Image.Exif()
        exif[0x010F] = "ACME"
        exif[0x0110] = "Phone 15"
        options["exif"] = exif.tobytes()
    image.save(str(path), **options)


# --------------------------------------------------------------------------
# PDFs whose text layer does not describe everything on the page
# --------------------------------------------------------------------------

#: What is on the card image, the searchable scan and the annotation: never in
#: any text layer, so only reading the pixels finds it.
IMAGE_SECRETS = ["Harold Pennington", "219-09-9999"]


def _font(size: int):
    from PIL import ImageFont

    try:
        return ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", size)
    except OSError:
        return ImageFont.load_default(size)


def write_mixed_pdf(path) -> None:
    """A text-layer report with a photographed insurance card pasted onto it."""
    from PIL import Image, ImageDraw
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    card = Image.new("RGB", (900, 200), "white")
    draw = ImageDraw.Draw(card)
    draw.text((20, 20), "Insured: Harold Pennington", fill="black", font=_font(48))
    draw.text((20, 110), "SSN 219-09-9999", fill="black", font=_font(48))
    card_path = path.with_name("_card.png")
    card.save(card_path)

    c = canvas.Canvas(str(path), pagesize=letter)
    y = 740
    for line in ["Patient Name: Margaret Whitfield", "MRN: 4471982",
                 "The patient was seen today for a routine follow-up visit and is doing well.",
                 "Plan: continue current medication and return in six months."]:
        c.drawString(72, y, line)
        y -= 18
    c.drawImage(str(card_path), 72, 420, width=450, height=100)
    c.acroForm.textfield(name="kin", value="Next of kin: Theodore Ashcombe 555-867-5309",
                         x=72, y=300, width=450, height=24, borderWidth=0, fontSize=12)
    c.save()


def write_searchable_pdf(path) -> None:
    """A scanner app's "searchable PDF": a page image under an invisible OCR layer
    that misread the SSN's digits, so the layer alone hides it from detection."""
    from PIL import Image, ImageDraw
    from reportlab.pdfgen import canvas

    lines = ["Patient Name: Harold Pennington", "SSN: 219-09-9999",
             "The patient was seen today for a routine visit.",
             "Plan: continue current medication."]
    scan = Image.new("RGB", (1700, 2200), "white")
    draw = ImageDraw.Draw(scan)
    for index, line in enumerate(lines):
        draw.text((150, 200 + index * 90), line, fill="black", font=_font(44))
    scan_path = path.with_name("_scan.png")
    scan.save(scan_path)

    c = canvas.Canvas(str(path), pagesize=(612, 792))
    c.drawImage(str(scan_path), 0, 0, width=612, height=792)
    layer = c.beginText()
    layer.setTextRenderMode(3)                       # invisible, as OCR layers are
    layer.setFont("Helvetica", 16)
    misread = [lines[0], "SSN: 2l9-O9-99g9", lines[2], lines[3]]
    for index, line in enumerate(misread):
        layer.setTextOrigin(54, 792 - (200 + index * 90) * 0.36 - 14)
        layer.textLine(line)
    c.drawText(layer)
    c.save()


def write_annotated_pdf(path) -> None:
    """A text-layer page with a free-text annotation drawn by its own appearance
    stream: rendered onto the page, absent from the text layer."""
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        FloatObject,
        NameObject,
        NumberObject,
        StreamObject,
        TextStringObject,
    )
    from reportlab.pdfgen import canvas

    base = path.with_name("_base.pdf")
    c = canvas.Canvas(str(base))
    y = 740
    for line in ["Patient Name: Margaret Whitfield", "MRN: 4471982",
                 "The patient was seen today for a routine follow-up visit and is doing well.",
                 "Plan: continue current medication and return in six months."]:
        c.drawString(72, y, line)
        y -= 18
    c.save()

    writer = PdfWriter(clone_from=PdfReader(base))
    font = DictionaryObject({
        NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
    })
    appearance = StreamObject()
    appearance.set_data(b"BT /F1 18 Tf 0 0 0 rg 4 12 Td (Call Harold Pennington SSN 219-09-9999) Tj ET")
    appearance.update({
        NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
        NameObject("/BBox"): ArrayObject([FloatObject(0), FloatObject(0), FloatObject(450),
                                          FloatObject(40)]),
        NameObject("/Resources"): DictionaryObject({NameObject("/Font"): DictionaryObject(
            {NameObject("/F1"): writer._add_object(font)})}),
    })
    writer.add_annotation(page_number=0, annotation=DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/FreeText"),
        NameObject("/Rect"): ArrayObject([FloatObject(72), FloatObject(500), FloatObject(522),
                                          FloatObject(540)]),
        NameObject("/Contents"): TextStringObject("Call Harold Pennington SSN 219-09-9999"),
        NameObject("/DA"): TextStringObject("/Helv 18 Tf 0 g"),
        NameObject("/AP"): DictionaryObject({NameObject("/N"): writer._add_object(appearance)}),
        NameObject("/F"): NumberObject(4),
    }))
    writer.write(str(path))


def write_label_value_pdf(path) -> None:
    """The invented discharge summary as a plain text-layer PDF: "Label: value"
    lines, left-aligned, no ruling lines. Alignment-based table detection once
    read this as a two-column table and cut words at the column boundary
    ("I | L 62704", "2025 | -08-09"), and the broken values got past detection."""
    from pathlib import Path

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    text = (Path(__file__).resolve().parents[1] / "examples" / "discharge-summary.txt").read_text()
    c = canvas.Canvas(str(path), pagesize=letter)
    y = letter[1] - 60
    for line in text.splitlines():
        c.setFont("Helvetica", 10)
        c.drawString(54, y, line[:110])
        y -= 14
    c.save()


requires_reportlab = pytest.mark.skipif(
    not _module_available("reportlab"), reason="needs reportlab to build the PDF"
)
