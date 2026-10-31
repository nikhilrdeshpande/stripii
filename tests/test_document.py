"""``redact_file``: one file in, a graded result out.

The grade is the product's promise, so these tests pin down what earns each
colour: green only when the output was read back and nothing detected can be
read on it; red when something can, or a page could not be read at all; amber
when the finding rests on a weak signal or nothing was found.
"""

from __future__ import annotations

import pytest

from stripii import RedactionResult, Vault, redact_file, scrub_text
from stripii.document import AMBER, GREEN, RED, Spot, build_policy, legible, shape
from stripii.readers import UnsupportedDocument

from .conftest import (
    HEALTH_IDENTIFIERS,
    HEALTH_MUST_KEEP,
    HEALTH_REPORT,
    ocr_backends,
    requires_any_ocr,
    requires_pdf_tables,
)

# --------------------------------------------------------------------------
# text files: no pages, the output is its own proof
# --------------------------------------------------------------------------

def test_a_text_file_gets_text_output_and_a_green_grade(tmp_path):
    source = tmp_path / "report.txt"
    source.write_text(HEALTH_REPORT, encoding="utf-8")
    result = redact_file(source, profile="health")
    assert isinstance(result, RedactionResult)
    assert result.kind == "text" and result.source == "text"
    assert set(result.outputs) == {"text"}
    text = result.outputs["text"].decode("utf-8")
    assert text == result.text
    for identifier in HEALTH_IDENTIFIERS:
        assert identifier not in text
    for kept in HEALTH_MUST_KEEP:
        assert kept in text
    assert result.grade == GREEN
    assert result.verified and result.reasons == []
    assert result.total == sum(result.counts.values()) > 10


def test_nothing_found_is_amber_not_green(tmp_path):
    source = tmp_path / "notes.txt"
    source.write_text("Hemoglobin 10.2 g/dL. Follow up in two weeks.", encoding="utf-8")
    result = redact_file(source, profile="health")
    assert result.total == 0
    assert result.grade == AMBER
    assert any("nothing was detected" in r for r in result.reasons)


def test_a_weak_name_is_amber(tmp_path):
    """A lone given name is redacted, but only a list said it was a name."""
    source = tmp_path / "chat.txt"
    source.write_text("Margaret said the results looked fine.\n", encoding="utf-8")
    result = redact_file(source, profile="paranoid")
    assert "Margaret" not in result.text
    assert result.grade == AMBER
    assert any("weak signal" in r for r in result.reasons)


def test_page_outputs_need_a_pdf_or_image(tmp_path):
    source = tmp_path / "report.txt"
    source.write_text(HEALTH_REPORT, encoding="utf-8")
    with pytest.raises(UnsupportedDocument):
        redact_file(source, outputs=("pdf",))
    with pytest.raises(ValueError, match="unknown output"):
        redact_file(source, outputs=("docx",))


def test_structure_is_kept_for_csv_and_json(tmp_path):
    csv = tmp_path / "patients.csv"
    csv.write_text("name,mrn,result\nMargaret Whitfield,4471982,10.2\n", encoding="utf-8")
    result = redact_file(csv, profile="health")
    lines = result.text.splitlines()
    assert lines[0] == "name,mrn,result"
    assert lines[1].endswith(",10.2") and "Whitfield" not in lines[1]

    js = tmp_path / "patient.json"
    js.write_text('{"name": "Margaret Whitfield", "mrn": "4471982"}', encoding="utf-8")
    result = redact_file(js, profile="health")
    assert '"name"' in result.text and "Whitfield" not in result.text


def test_identifiers_are_always_redacted(tmp_path):
    """A surname that is an English word, unlabelled and lower-case, survives
    every detector; the user's own list catches it."""
    source = tmp_path / "chat.txt"
    source.write_text("thanks hunter, see you at 4\nsent to 5544 3322 1100 9\n", encoding="utf-8")
    plain = redact_file(source, profile="paranoid")
    assert "hunter" in plain.text
    listed = redact_file(source, profile="paranoid", identifiers=["Hunter", "5544-3322-1100-9"])
    assert "hunter" not in listed.text
    assert "5544" not in listed.text
    assert listed.counts.get("PERSON") == 1 and listed.counts.get("IDENTIFIER") == 1


def test_styles_rewrite_only_redactions():
    result, _ = scrub_text("SSN: 412-88-9031, DOB 03/14/1934", profile="health", style="mask")
    assert "412-88-9031" not in result.text
    assert "9031" in result.text          # masked keeps the tail
    with pytest.raises(ValueError, match="unknown style"):
        build_policy("health", "sparkle")
    assert build_policy("health").name == "health"


def test_scrub_text_returns_a_vault():
    result, vault = scrub_text(HEALTH_REPORT, profile="health")
    assert isinstance(vault, Vault) and len(vault) > 0
    assert "Whitfield" not in result.text


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def test_shape_hides_the_value():
    assert shape("ABCDE1234F") == "XXXXX9999X"
    assert shape("Margaret Whitfield") == "Xxxxxxxx Xxxxxxxxx"
    assert shape("x" * 100) == "x" * 32


def test_legible_tolerates_ocr_spacing():
    assert legible("412-88-9031", "ssn 412 88 9031 here")
    assert legible("m.whitfield@example.com", "M.WHITFIELD @ EXAMPLE.COM")
    assert not legible("4471982", "44719820")
    assert not legible("---", "anything")


def test_spot_knows_when_it_is_a_leak():
    assert Spot(1, (0, 0, 1, 1), "9999", "still legible").legible
    assert not Spot(1, (0, 0, 1, 1), "Xxxx", "low-confidence name").legible


# --------------------------------------------------------------------------
# pages: PDFs, scans and photos, on every engine that runs here
# --------------------------------------------------------------------------

IDENTIFIERS = ["Margaret Whitfield", "4471982", "412-88-9031",
               "m.whitfield@example.com", "555-0142"]


@pytest.fixture
def scanned(tmp_path):
    from .conftest import write_scanned_pdf

    path = tmp_path / "scan.pdf"
    write_scanned_pdf(path)
    return path


@pytest.fixture
def text_pdf(scanned):
    return scanned.with_name("_source.pdf")  # the PDF the scan was rendered from


@requires_any_ocr
@requires_pdf_tables
@pytest.mark.slow
@pytest.mark.parametrize("engine", ocr_backends())
def test_a_text_layer_pdf_is_redacted_from_its_words_and_read_back(text_pdf, engine):
    result = redact_file(text_pdf, profile="health", outputs=("text", "pdf"), ocr=engine)
    assert result.source == "text layer"
    assert result.page_count == 1 and len(result.pages) == 1
    assert result.outputs["pdf"].startswith(b"%PDF")
    for identifier in IDENTIFIERS:
        assert identifier not in result.text
    assert result.verified and result.checked == len(IDENTIFIERS)
    assert result.still_legible == 0
    assert result.grade == GREEN, result.reasons
    assert {"read", "redact", "verify"} <= set(result.timings_ms)


@requires_any_ocr
@pytest.mark.slow
@pytest.mark.parametrize("engine", ocr_backends())
def test_a_scan_is_read_with_ocr_and_graded_on_the_output(scanned, engine):
    result = redact_file(scanned, profile="health", outputs=("text", "pdf"), ocr=engine)
    assert result.source == engine
    for identifier in IDENTIFIERS:
        assert identifier not in result.text
    assert "Hemoglobin" in result.text
    assert result.grade == GREEN, result.reasons


@requires_any_ocr
@pytest.mark.slow
@pytest.mark.parametrize("engine", ocr_backends())
def test_a_page_that_survives_redaction_is_red_with_spots(scanned, engine, monkeypatch):
    """Draw nothing, and the read-back must catch every value still on the page."""
    from stripii import ocr

    monkeypatch.setattr(ocr, "redact_images", lambda read, spans, **kw: list(read.images))
    result = redact_file(scanned, profile="health", outputs=("pdf",), ocr=engine)
    assert result.grade == RED
    assert result.still_legible >= 4
    leaks = [s for s in result.spots if s.legible]
    assert leaks and all(s.page == 1 for s in leaks)
    for spot in leaks:
        left, top, right, bottom = spot.box
        assert right > left and bottom > top
        assert not any(ch.isalpha() and ch not in "Xx" for ch in spot.shape)
    assert any("still be read" in r for r in result.reasons)


@requires_any_ocr
@pytest.mark.slow
def test_an_unreadable_page_is_red(tmp_path):
    from PIL import Image

    blank = tmp_path / "blank.png"
    Image.new("RGB", (1200, 1600), "white").save(blank)
    result = redact_file(blank, profile="health", outputs=("image",), ocr=ocr_backends()[0])
    assert result.unreadable_pages == [1]
    assert result.grade == RED
    assert any("could not be read" in r for r in result.reasons)


@requires_any_ocr
@pytest.mark.slow
def test_not_reading_back_is_never_green(scanned):
    result = redact_file(scanned, profile="health", outputs=("pdf",),
                         ocr=ocr_backends()[0], verify=False)
    assert not result.verified
    assert result.grade == AMBER
    assert any("not read back" in r for r in result.reasons)


@requires_any_ocr
@pytest.mark.slow
def test_progress_is_reported_in_stages(scanned):
    seen = []
    redact_file(scanned, profile="health", outputs=("pdf",), ocr=ocr_backends()[0],
                on_progress=lambda stage, done, total: seen.append((stage, done, total)))
    stages = [s for s, _, _ in seen]
    assert stages[0] == "reading" and "redacting" in stages and stages[-1] == "checking"
    assert seen[-1] == ("checking", 1, 1)


# --------------------------------------------------------------------------
# review: a person adds boxes
# --------------------------------------------------------------------------

@requires_any_ocr
@pytest.mark.slow
def test_boxing_every_leak_turns_a_red_result_green(scanned, monkeypatch):
    from stripii import ocr, redact_boxes

    engine = ocr_backends()[0]
    monkeypatch.setattr(ocr, "redact_images", lambda read, spans, **kw: list(read.images))
    held = redact_file(scanned, profile="health", outputs=("text", "pdf"), ocr=engine)
    assert held.grade == RED and held.still_legible >= 4
    monkeypatch.undo()

    boxes = [(s.page, s.box) for s in held.spots if s.legible]
    revised = redact_boxes(held, boxes, ocr=engine)
    assert revised.reviewed and not held.reviewed
    assert revised.grade == GREEN, revised.reasons
    assert revised.still_legible == 0
    assert revised.text == held.text                 # the text was already redacted
    assert revised.outputs["pdf"] != held.outputs["pdf"]
    assert held.grade == RED                          # the original is untouched


@requires_any_ocr
@pytest.mark.slow
def test_a_box_over_an_undetected_word_removes_it_from_page_and_text(scanned):
    from stripii import ocr, redact_boxes

    engine = ocr_backends()[0]
    result = redact_file(scanned, profile="health", outputs=("text", "pdf"), ocr=engine)
    assert "Hemoglobin" in result.text
    word = next(w for w in result.read.words if w.text.startswith("Hemoglobin"))
    revised = redact_boxes(result, [(word.page + 1, word.box)], ocr=engine)
    assert "Hemoglobin" not in revised.text
    assert "[[MANUAL_1]]" in revised.text
    assert revised.counts.get("MANUAL") == 1
    after = ocr.read_images([revised.pages[0]], backend=engine).text
    assert "Hemoglobin" not in after
    assert "Glucose" in after                         # only the boxed word went


def test_a_text_result_cannot_be_reviewed(tmp_path):
    from stripii import redact_boxes

    source = tmp_path / "report.txt"
    source.write_text(HEALTH_REPORT, encoding="utf-8")
    with pytest.raises(ValueError, match="pages"):
        redact_boxes(redact_file(source), [(1, (0, 0, 10, 10))])


# --------------------------------------------------------------------------
# printing a result never prints the originals
# --------------------------------------------------------------------------

def _reprs(*objects) -> str:
    return "\n".join(f"{o!r}\n{o!s}" for o in objects)


@pytest.mark.parametrize("style", ["placeholder", "surrogate", "mask"])
def test_the_repr_of_a_result_holds_no_original_value(tmp_path, style):
    source = tmp_path / "report.txt"
    source.write_text(HEALTH_REPORT, encoding="utf-8")
    result = redact_file(source, profile="health", style=style)
    scrub, vault = scrub_text(HEALTH_REPORT, profile="health", style=style)
    printed = _reprs(
        result, result.vault, result.scrub, scrub, vault,
        *scrub.replacements, *(r.detection for r in scrub.replacements), *scrub.skipped,
    )
    for identifier in HEALTH_IDENTIFIERS:
        assert identifier not in printed, identifier
    assert "counts" in repr(result)            # still useful to print


@pytest.mark.slow
@requires_any_ocr
def test_the_repr_of_a_page_result_holds_no_original_value(tmp_path):
    from stripii import ocr

    from .conftest import write_photo

    source = tmp_path / "card.png"
    write_photo(source)
    result = redact_file(source, profile="health", outputs=("image",), verify=False)
    read = result.read
    printed = _reprs(result, read, *read.words, *result.spots, ocr.read_images(read.images))
    for value in ("Whitfield", "412-88-9031", "4471982"):
        assert value not in printed



@requires_any_ocr
@pytest.mark.slow
def test_a_review_with_no_boxes_is_not_a_review(scanned):
    """Applying nothing must not count as a person having checked the pages:
    the app releases a held result only after a real review."""
    from stripii import redact_boxes

    held = redact_file(scanned, profile="health", outputs=("text", "pdf"), ocr=ocr_backends()[0])
    assert not redact_boxes(held, [], ocr=ocr_backends()[0]).reviewed


@requires_any_ocr
@pytest.mark.slow
def test_one_oversized_page_lowers_the_resolution_instead_of_refusing(tmp_path, monkeypatch):
    """Real statements can carry one very large page. The whole document is drawn
    a little smaller, at one scale, and the names on it are still blacked out."""
    from reportlab.pdfgen import canvas

    from stripii import ocr

    path = tmp_path / "big-page.pdf"
    pdf = canvas.Canvas(str(path), pagesize=(612, 792))
    pdf.setFont("Helvetica", 14)
    pdf.drawString(72, 700, "Patient Name: Margaret Whitfield")
    pdf.drawString(72, 670, "MRN: 4471982")
    pdf.save()
    # Letter at 200 dpi is 3.7 Mpx; with a 2 Mpx limit it must come down to about 147 dpi.
    monkeypatch.setattr(ocr, "MAX_PAGE_PIXELS", 2_000_000)
    assert 140 <= ocr.fit_dpi(path, 200) < 200

    result = redact_file(path, profile="health", outputs=("text", "pdf"), ocr=ocr_backends()[0])
    assert result.dpi < 200
    assert result.still_legible == 0, result.reasons
    assert "Whitfield" not in result.text
    width, height = result.pages[0].size
    assert width * height <= 2_000_000


def test_a_page_too_large_even_at_the_lowest_resolution_is_still_refused(tmp_path, monkeypatch):
    from reportlab.pdfgen import canvas

    from stripii import ocr

    path = tmp_path / "poster.pdf"
    pdf = canvas.Canvas(str(path), pagesize=(612, 792))
    pdf.drawString(72, 700, "hello")
    pdf.save()
    monkeypatch.setattr(ocr, "MAX_PAGE_PIXELS", 1000)
    assert ocr.fit_dpi(path, 200) == 200
    with pytest.raises(ocr.DocumentTooLarge):
        ocr.render_pdf(path, 200)
