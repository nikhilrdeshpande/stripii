"""Local OCR, and redaction painted onto the page.

The claim being tested is stronger than "the text came out right": after
redaction, running OCR *again* over the produced image must not find the
identifiers. That is the only way to show the ink is really on the page rather
than a rectangle sitting over a still-readable text layer.
"""

from __future__ import annotations

import pytest

from stripii import Scrubber, get_profile
from stripii.ocr import (
    OcrUnavailable,
    Word,
    get_backend,
    read_document,
    read_images,
    redact_images,
    save_pdf,
)

from .conftest import ocr_backends, requires_any_ocr

pytestmark = [requires_any_ocr, pytest.mark.slow]

#: Every page-reading test runs once per engine that is installed here, so a
#: Mac exercises Vision and Tesseract and a Linux CI box Tesseract alone.
each_engine = pytest.mark.parametrize("engine", ocr_backends())

IDENTIFIERS = ["Margaret Whitfield", "4471982", "412-88-9031",
               "m.whitfield@example.com", "555-0142"]


@pytest.fixture
def scanned(tmp_path):
    from .conftest import write_scanned_pdf

    path = tmp_path / "scan.pdf"
    write_scanned_pdf(path)
    return path


@each_engine
def test_ocr_reads_a_scanned_pdf(scanned, engine):
    result = read_document(scanned, backend=engine)
    assert "NORTHSIDE MEDICAL CENTER" in result.text
    assert "Margaret Whitfield" in result.text
    assert result.words


@each_engine
def test_every_word_has_a_box_and_an_offset(scanned, engine):
    result = read_document(scanned, backend=engine)
    for word in result.words:
        assert result.text[word.start:word.end] == word.text
        left, top, right, bottom = word.box
        assert right > left and bottom > top


@each_engine
def test_split_email_addresses_are_rejoined(scanned, engine):
    """Tesseract routinely emits "name @example.com"; the detector needs it whole."""
    result = read_document(scanned, backend=engine)
    assert "m.whitfield@example.com" in result.text


@each_engine
def test_identifiers_are_detected_in_ocr_output(scanned, engine):
    result = read_document(scanned, backend=engine)
    scrubbed, _ = Scrubber(get_profile("health")).scrub(result.text)
    for identifier in IDENTIFIERS:
        assert identifier not in scrubbed.text
    assert "Hemoglobin 10.2 g/dL" in scrubbed.text


@each_engine
def test_redaction_is_painted_onto_the_image(scanned, tmp_path, engine):
    """Re-OCR the redacted output: nothing identifying may come back."""
    result = read_document(scanned, backend=engine)
    scrubbed, _ = Scrubber(get_profile("health")).scrub(result.text)
    spans = [(r.detection.start, r.detection.end) for r in scrubbed.replacements]
    assert spans

    out = tmp_path / "redacted.pdf"
    save_pdf(redact_images(result, spans), out)

    recovered = read_document(out, backend=engine).text
    for identifier in IDENTIFIERS:
        assert identifier not in recovered, f"{identifier!r} survived on the page"
    # and the clinical content is still legible
    assert "Hemoglobin" in recovered


@each_engine
def test_redaction_leaves_untouched_pages_alone(scanned, engine):
    result = read_document(scanned, backend=engine)
    assert redact_images(result, [])[0].tobytes() == result.images[0].tobytes()


def test_words_in_finds_overlapping_words_only():
    words = [
        Word("alpha", 0, 0, 0, 10, 10, 90.0, 0, 5),
        Word("beta", 0, 20, 0, 10, 10, 90.0, 6, 10),
        Word("gamma", 0, 40, 0, 10, 10, 90.0, 11, 16),
    ]
    from stripii.ocr import OcrResult

    result = OcrResult(text="alpha beta gamma", words=words, images=[])
    assert [w.text for w in result.words_in(6, 10)] == ["beta"]
    assert [w.text for w in result.words_in(0, 16)] == ["alpha", "beta", "gamma"]
    assert result.words_in(5, 6) == []


def test_saving_no_pages_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="no pages"):
        save_pdf([], tmp_path / "empty.pdf")


def test_ocr_unavailable_is_a_clear_message():
    assert issubclass(OcrUnavailable, RuntimeError)


def test_a_page_ocr_cannot_read_is_reported_not_counted_as_clean():
    """A photographed ID card came back as three words of watermark and "0 findings"."""
    from PIL import Image

    blank = Image.new("RGB", (1200, 1600), "white")
    for engine in ocr_backends():
        result = read_images([blank], backend=engine)
        assert result.unreadable_pages == [1], engine


@each_engine
def test_a_legible_page_is_not_reported_as_unreadable(scanned, engine):
    assert read_document(scanned, backend=engine).unreadable_pages == []


@each_engine
def test_a_redacted_pdf_keeps_the_original_page_size(scanned, tmp_path, engine):
    """Pillow assumes 72 dpi unless told; pages came out 2.8 times too large."""
    import pypdfium2

    result = read_document(scanned, backend=engine)
    out = tmp_path / "redacted.pdf"
    save_pdf(redact_images(result, []), out)
    original = pypdfium2.PdfDocument(str(scanned))[0].get_size()
    redacted = pypdfium2.PdfDocument(str(out))[0].get_size()
    assert abs(redacted[0] - original[0]) < 2
    assert abs(redacted[1] - original[1]) < 2


def test_auto_picks_an_installed_engine():
    engine = get_backend("auto")
    assert engine.name in ocr_backends()
    assert get_backend(engine) is engine           # an instance passes straight through


def test_unknown_engine_names_are_refused():
    with pytest.raises(ValueError, match="unknown OCR backend"):
        get_backend("abbyy")


def test_an_engine_that_cannot_run_here_says_why(monkeypatch):
    from stripii import ocr

    monkeypatch.setattr(ocr, "vision_available", lambda: False)
    monkeypatch.setattr(ocr, "tesseract_available", lambda: False)
    with pytest.raises(OcrUnavailable, match="no OCR engine"):
        get_backend("auto")
    with pytest.raises(OcrUnavailable, match="Tesseract"):
        get_backend("tesseract")


@each_engine
def test_the_result_says_which_engine_read_it(scanned, engine):
    assert read_document(scanned, backend=engine).source == engine


# --------------------------------------------------------------------------
# a crafted document cannot make us rasterise without limit
# --------------------------------------------------------------------------

def _pdf(path, pages, size=(612, 792)):
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(str(path), pagesize=size)
    for _ in range(pages):
        c.drawString(72, 72, "Plan: continue current medication.")
        c.showPage()
    c.save()
    return path


def test_too_many_pages_are_refused_before_rendering(tmp_path, monkeypatch):
    from stripii import ocr

    monkeypatch.setattr(ocr, "MAX_PAGES", 3)
    with pytest.raises(ocr.DocumentTooLarge, match="pages"):
        ocr.render_pdf(_pdf(tmp_path / "long.pdf", 4))
    assert len(ocr.render_pdf(_pdf(tmp_path / "short.pdf", 3))) == 3


def test_an_enormous_page_is_refused(tmp_path):
    from stripii import ocr

    # 200 inches square, the largest page PDF allows: 1.6 billion pixels at 200 dpi
    path = _pdf(tmp_path / "huge.pdf", 1, size=(14400, 14400))
    with pytest.raises(ocr.DocumentTooLarge, match="pixels"):
        ocr.render_pdf(path)


@pytest.mark.parametrize("dpi", [10, 601, 2400])
def test_an_absurd_dpi_is_refused(tmp_path, dpi):
    from stripii import ocr

    with pytest.raises(ValueError, match="dpi"):
        ocr.render_pdf(_pdf(tmp_path / "a.pdf", 1), dpi)


def test_an_image_bomb_is_refused_from_its_header(tmp_path):
    from PIL import Image

    from stripii import ocr

    path = tmp_path / "bomb.png"
    Image.new("1", (10_000, 10_000)).save(path)      # 100 M pixels, a few KB on disk
    with pytest.raises(ocr.DocumentTooLarge):
        ocr.load_image(path)
