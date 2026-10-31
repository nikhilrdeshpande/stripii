"""Text-layer PDFs that also carry images: the text layer is not the page.

A PDF can have a perfectly good text layer and still show things that are not
in it: a photographed ID card pasted onto a statement, a scanner app's
"searchable PDF" whose invisible OCR layer misread the digits, a free-text
annotation drawn by its own appearance stream. Redacting from the text layer
alone left all of those on the output page -- and graded it "ready". These
tests read every output back with OCR and require that none of it survives,
on every engine installed here.
"""

from __future__ import annotations

import pytest

from stripii import redact_file
from stripii.document import GREEN, RED, legible

from .conftest import (
    IMAGE_SECRETS,
    ocr_backends,
    requires_any_ocr,
    requires_pdf,
    requires_pdf_tables,
)

pytestmark = [requires_any_ocr, requires_pdf_tables, requires_pdf, pytest.mark.slow]

each_engine = pytest.mark.parametrize("engine", ocr_backends())


@pytest.fixture
def mixed(tmp_path):
    from .conftest import write_mixed_pdf

    path = tmp_path / "mixed.pdf"
    write_mixed_pdf(path)
    return path


@pytest.fixture
def searchable(tmp_path):
    from .conftest import write_searchable_pdf

    path = tmp_path / "searchable.pdf"
    write_searchable_pdf(path)
    return path


@pytest.fixture
def annotated(tmp_path):
    from .conftest import write_annotated_pdf

    path = tmp_path / "annotated.pdf"
    write_annotated_pdf(path)
    return path


def _still_legible(result, engine, values) -> list[str]:
    from stripii import ocr

    back = ocr.read_images(result.pages, backend=engine).text
    return [v for v in values if legible(v, back)]


def _check(result, engine, values):
    """The promise: whatever the grade, a green holds nothing legible."""
    assert _still_legible(result, engine, values) == []
    text = result.text.lower()
    assert not [v for v in values if v.lower() in text]
    if result.grade == GREEN:
        assert result.verified and not result.spots


@each_engine
def test_an_image_on_a_text_layer_page_is_read_and_redacted(mixed, engine):
    result = redact_file(mixed, profile="health", outputs=("text", "pdf"), ocr=engine)
    assert result.source == f"text layer + {engine}"
    _check(result, engine, [*IMAGE_SECRETS, "Margaret Whitfield", "4471982"])
    # what was on the card is now in the text output, redacted
    assert "Insured" in result.text
    assert result.grade != RED


@each_engine
def test_a_searchable_scan_is_redacted_from_its_pixels_not_its_invisible_layer(searchable,
                                                                                engine):
    result = redact_file(searchable, profile="health", outputs=("text", "pdf"), ocr=engine)
    _check(result, engine, IMAGE_SECRETS)
    # the layer's misreading of the SSN is gone from the text output too
    assert "2l9-O9-99g9" not in result.text
    assert result.grade != RED


@each_engine
def test_a_drawn_annotation_is_read_and_redacted(annotated, engine):
    result = redact_file(annotated, profile="health", outputs=("pdf",), ocr=engine)
    _check(result, engine, [*IMAGE_SECRETS, "Margaret Whitfield"])


@each_engine
def test_reading_back_catches_what_the_first_pass_never_saw(mixed, engine, monkeypatch):
    """Even with the image left unread, the output cannot be green: reading it
    back runs every detector over the page, not just a search for the values
    found the first time."""
    from stripii import ocr

    original = ocr.read_text_layer

    def blind(*args, **kwargs):
        read = original(*args, **kwargs)
        read.pages_needing_ocr = []
        return read

    monkeypatch.setattr(ocr, "read_text_layer", blind)
    result = redact_file(mixed, profile="health", outputs=("pdf",), ocr=engine)
    assert result.grade == RED
    assert any(s.legible for s in result.spots)
    assert result.still_legible >= 1
    legible_values = {s.value for s in result.spots if s.legible}
    assert legible_values & {"219-09-9999", "Harold Pennington", "SSN 219-09-9999"} or any(
        "219-09-9999" in v or "Pennington" in v for v in legible_values
    )


def test_images_that_no_engine_can_read_are_red(mixed, monkeypatch):
    from stripii import ocr

    def unavailable(*args, **kwargs):
        raise ocr.OcrUnavailable("no engine")

    monkeypatch.setattr(ocr, "read_some_pages", unavailable)
    result = redact_file(mixed, profile="health", outputs=("pdf",), verify=False)
    assert result.grade == RED
    assert result.unreadable_pages == [1]


def test_a_pure_text_pdf_keeps_the_fast_path(tmp_path, monkeypatch):
    """No images, no annotations: nothing is OCR'd before the read-back."""
    from reportlab.pdfgen import canvas

    from stripii import ocr

    path = tmp_path / "letter.pdf"
    c = canvas.Canvas(str(path))
    c.drawString(72, 740, "Patient Name: Margaret Whitfield, MRN 4471982, seen today.")
    c.save()

    def must_not_run(*args, **kwargs):
        raise AssertionError("a text-only page was OCR'd while reading")

    monkeypatch.setattr(ocr, "read_some_pages", must_not_run)
    result = redact_file(path, profile="health", outputs=("pdf",), verify=False)
    assert result.source == "text layer"
    assert "Whitfield" not in result.text


@each_engine
def test_force_ocr_reads_a_text_layer_pdf_with_ocr(mixed, engine):
    result = redact_file(mixed, profile="health", outputs=("pdf",), ocr=engine, force_ocr=True)
    assert result.source == engine
    _check(result, engine, [*IMAGE_SECRETS, "Margaret Whitfield"])


def test_the_output_keeps_no_annotation_form_text_layer_or_metadata(annotated, mixed):
    import io

    from pypdf import PdfReader

    for path in (annotated, mixed):
        result = redact_file(path, profile="health", outputs=("pdf",), verify=False)
        reader = PdfReader(io.BytesIO(result.outputs["pdf"]))
        assert not any("/Annots" in page for page in reader.pages)
        assert "/AcroForm" not in reader.trailer["/Root"]
        assert "".join(page.extract_text() or "" for page in reader.pages).strip() == ""
        metadata = " ".join(str(v) for v in (reader.metadata or {}).values())
        assert "Whitfield" not in metadata


def test_the_cli_ocr_flag_forces_ocr_for_a_pdf_output(mixed, tmp_path, capsys):
    from stripii.cli import main

    out = tmp_path / "out.pdf"
    assert main(["scrub", str(mixed), "-p", "health", "--ocr", "-o", str(out)]) == 0
    err = capsys.readouterr().err
    assert "read with text layer" not in err
    assert out.exists()


def test_the_cli_warns_when_text_output_misses_a_pdf_image(mixed, capsys):
    from stripii.cli import main

    assert main(["scrub", str(mixed), "-p", "health", "--stdout"]) == 0
    captured = capsys.readouterr()
    assert "carry images" in captured.err and "--ocr" in captured.err
    assert "Whitfield" not in captured.out
