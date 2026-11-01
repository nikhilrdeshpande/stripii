"""Structured formats keep their structure."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from stripii import Scrubber, get_profile
from stripii.readers import UnsupportedDocument, kind_of, read_text, scrub_csv, scrub_json

from .conftest import (
    LAB_ROWS,
    _module_available,
    blank_pdf_bytes,
    requires_docx,
    requires_pdf,
    requires_xlsx,
    write_docx_with_table,
    write_xlsx_with_table,
)


def scrubber():
    """A scrubber that ignores the context hint, to isolate structure handling."""
    s = Scrubber(get_profile("default"))
    return lambda text, _hint=None: s.scrub(text)[0].text


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("a.txt", "text"), ("a.md", "text"), ("notes", "text"),
        ("a.json", "json"), ("a.jsonl", "json"),
        ("a.csv", "csv"), ("a.tsv", "csv"),
        ("a.pdf", "pdf"), ("a.docx", "docx"),
    ],
)
def test_kind_detection(filename, expected):
    assert kind_of(Path(filename)) == expected


def test_json_keeps_its_shape_and_keys():
    raw = json.dumps({
        "patient_name": "Margaret Whitfield",
        "labs": [{"test": "Hemoglobin", "value": 10.2}],
        "contact": {"email": "m.whitfield@example.com"},
        "active": True,
        "visits": 3,
    })
    out = json.loads(scrub_json(raw, scrubber()))
    # keys describe the schema and survive
    assert set(out) == {"patient_name", "labs", "contact", "active", "visits"}
    # non-string values are untouched
    assert out["active"] is True
    assert out["visits"] == 3
    assert out["labs"][0]["value"] == 10.2
    assert out["labs"][0]["test"] == "Hemoglobin"
    # string values are scrubbed
    assert "Margaret Whitfield" not in out["patient_name"]
    assert "m.whitfield@example.com" not in out["contact"]["email"]


def test_json_lines_are_handled_line_by_line():
    raw = '{"email": "a@example.com"}\n{"email": "b@example.com"}'
    out = scrub_json(raw, scrubber())
    lines = out.splitlines()
    assert len(lines) == 2
    assert all("@example.com" not in line for line in lines)


def test_csv_keeps_the_header_and_the_grid():
    raw = "name,email,balance\nMichael Rodriguez,mr@example.net,4820.55\nJane Smith,js@example.net,120.00\n"
    out = scrub_csv(raw, scrubber())
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == ["name", "email", "balance"]
    assert len(rows) == 3
    assert all(len(row) == 3 for row in rows)
    # amounts are not personal data
    assert rows[1][2] == "4820.55"
    assert "mr@example.net" not in out
    assert "Michael Rodriguez" not in out


def test_empty_csv_is_returned_unchanged():
    assert scrub_csv("", scrubber()) == ""


def test_malformed_json_still_raises():
    with pytest.raises(json.JSONDecodeError):
        scrub_json("{definitely not json", scrubber())


def test_plain_text_is_read_verbatim(tmp_path):
    path = tmp_path / "note.txt"
    path.write_text("Patient: Jane Smith\n")
    assert read_text(path) == "Patient: Jane Smith\n"


def test_undecodable_bytes_do_not_crash_the_reader(tmp_path):
    path = tmp_path / "note.txt"
    path.write_bytes(b"Patient: Jane Smith \xff\xfe done")
    assert "Jane Smith" in read_text(path)


def test_missing_pdf_support_explains_the_extra(tmp_path):
    path = tmp_path / "scan.pdf"
    path.write_bytes(blank_pdf_bytes())
    if _module_available("pypdf"):
        pytest.skip("the pdf extra is installed, so there is no missing-extra path")
    with pytest.raises(UnsupportedDocument, match=r"stripii\[pdf\]"):
        read_text(path)


@requires_pdf
def test_a_pdf_with_no_text_layer_is_rejected_not_passed_through(tmp_path):
    """The worst failure mode would be emitting an empty "scrubbed" file.

    A scan has no text layer, so there is nothing to redact and nothing to
    verify. Returning "" would look like a clean document.
    """
    path = tmp_path / "scan.pdf"
    path.write_bytes(blank_pdf_bytes())
    with pytest.raises(UnsupportedDocument, match=r"(?i)ocr"):
        read_text(path)


@requires_pdf
def test_the_cli_exits_nonzero_on_a_scanned_pdf(tmp_path, capsys):
    from stripii.cli import EXIT_ERROR, main

    path = tmp_path / "scan.pdf"
    path.write_bytes(blank_pdf_bytes())
    assert main(["scrub", str(path), "-p", "health"]) == EXIT_ERROR
    out, err = capsys.readouterr()
    assert out == ""            # nothing emitted that could be mistaken for output
    assert "--ocr" in err


def hinting_scrubber():
    """A scrubber that forwards the column header / JSON key as a context hint."""
    s = Scrubber(get_profile("paranoid"))
    return lambda text, hint=None: s.scrub(text, context_hint=hint)[0].text


def test_json_keys_supply_the_context_their_values_lack():
    raw = json.dumps({
        "routing_number": "021000021",
        "medical_record_number": "4471982",
        "glucose_mg_dl": "142",
    })
    out = json.loads(scrub_json(raw, hinting_scrubber()))
    assert "021000021" not in out["routing_number"]
    assert "4471982" not in out["medical_record_number"]
    # a lab value under a lab key is not an identifier
    assert out["glucose_mg_dl"] == "142"


def test_list_items_inherit_the_key_of_their_list():
    raw = json.dumps({"account_numbers": ["483920175", "483920176"]})
    out = json.loads(scrub_json(raw, hinting_scrubber()))
    assert all("4839201" not in value for value in out["account_numbers"])


def test_csv_headers_supply_the_context_their_cells_lack():
    raw = "name,routing_number,glucose\nJane Smith,021000021,142\n"
    out = scrub_csv(raw, hinting_scrubber())
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == ["name", "routing_number", "glucose"]
    assert "021000021" not in rows[1][1]
    assert rows[1][2] == "142"


def test_a_row_longer_than_its_header_does_not_crash():
    raw = "name,email\nJane Smith,j@example.com,extra,more\n"
    out = scrub_csv(raw, hinting_scrubber())
    assert "j@example.com" not in out



# --------------------------------------------------------------------------
# tables survive the binary formats
# --------------------------------------------------------------------------

def assert_grid_intact(markdown: str) -> None:
    """Every cell present, and laid out as a pipe table rather than a list."""
    assert "| --- |" in markdown, "not rendered as a Markdown table"
    for row in LAB_ROWS:
        for cell in row:
            assert cell in markdown, f"{cell!r} was lost"
    for row in LAB_ROWS[1:]:
        line = [ln for ln in markdown.splitlines() if ln.startswith(f"| {row[0]} ")]
        assert line, f"row {row[0]!r} is not on one line"
        # the whole row stayed together, which is the thing flat text destroys
        for cell in row[1:]:
            assert cell in line[0]


@requires_docx
def test_docx_tables_become_markdown_tables(tmp_path):
    path = tmp_path / "labs.docx"
    write_docx_with_table(path)
    assert_grid_intact(read_text(path))


@requires_docx
def test_docx_keeps_a_table_next_to_the_paragraph_that_introduces_it(tmp_path):
    """document.paragraphs and document.tables are separate sequences.

    Reading one then the other puts every table at the end of the document.
    """
    path = tmp_path / "labs.docx"
    write_docx_with_table(path)
    out = read_text(path)
    assert out.index("Margaret Whitfield") < out.index("| Test |")


@requires_xlsx
def test_xlsx_sheets_become_markdown_tables(tmp_path):
    path = tmp_path / "labs.xlsx"
    write_xlsx_with_table(path)
    out = read_text(path)
    assert "## Labs" in out
    assert_grid_intact(out)


@requires_docx
def test_a_scrubbed_docx_table_keeps_every_clinical_value(tmp_path):
    from stripii import Scrubber, get_profile

    path = tmp_path / "labs.docx"
    write_docx_with_table(path)
    result, _ = Scrubber(get_profile("health")).scrub(read_text(path))
    assert "Margaret Whitfield" not in result.text
    assert "4471982" not in result.text
    assert_grid_intact(result.text)


# --------------------------------------------------------------------------
# nothing in a structured file is passed through on trust
# --------------------------------------------------------------------------

def test_a_headerless_csv_does_not_leak_its_first_record():
    raw = (
        "Margaret Whitfield,219-09-9999,margaret.whitfield@example.com\n"
        "Harold Pennington,078-05-1120,h.pennington@example.com\n"
    )
    out = scrub_csv(raw, hinting_scrubber())
    for value in ("Margaret Whitfield", "219-09-9999", "margaret.whitfield@example.com",
                  "Harold Pennington", "h.pennington@example.com"):
        assert value not in out
    assert len(list(csv.reader(io.StringIO(out)))) == 2


def test_a_real_header_still_comes_back_verbatim_and_hints():
    raw = "name,routing_number\nJane Smith,021000021\n"
    rows = list(csv.reader(io.StringIO(scrub_csv(raw, hinting_scrubber()))))
    assert rows[0] == ["name", "routing_number"]
    assert "021000021" not in rows[1][1]


def test_json_keys_are_scrubbed_too():
    raw = json.dumps({
        "Margaret Whitfield": {"ssn": "219-09-9999"},
        "contacts": {"margaret.whitfield@example.com": "primary"},
    })
    out = scrub_json(raw, hinting_scrubber())
    assert "Margaret Whitfield" not in out
    assert "margaret.whitfield@example.com" not in out
    parsed = json.loads(out)
    # schema keys survive
    assert "contacts" in parsed
    assert any(isinstance(v, dict) and "ssn" in v for v in parsed.values())


def test_json_keys_that_scrub_to_one_placeholder_are_both_kept():
    raw = json.dumps({"Harold Pennington": 1, "HAROLD PENNINGTON": 2})
    parsed = json.loads(scrub_json(raw, hinting_scrubber()))
    assert sorted(parsed.values()) == [1, 2]
    assert "pennington" not in json.dumps(parsed).lower()


def test_a_tsv_is_split_on_tabs(tmp_path):
    from stripii.document import redact_file

    path = tmp_path / "people.tsv"
    path.write_text("name\tssn\nMargaret Whitfield\t219-09-9999\n")
    result = redact_file(path, profile="health")
    rows = [line.split("\t") for line in result.text.splitlines()]
    assert rows[0] == ["name", "ssn"]
    assert len(rows[1]) == 2
    assert "Margaret Whitfield" not in result.text
    assert "219-09-9999" not in result.text


def test_the_cli_reads_a_tsv_with_tabs(tmp_path, capsys):
    from stripii.cli import main

    path = tmp_path / "people.tsv"
    path.write_text("Margaret Whitfield\t219-09-9999\n")
    assert main(["scrub", str(path), "-p", "health", "-q"]) == 0
    out = capsys.readouterr().out
    assert "Margaret Whitfield" not in out and "219-09-9999" not in out
    assert out.count("\t") == 1


# --- Prose must not be read as a table ------------------------------------------

from .conftest import requires_pdf_tables, requires_reportlab, write_label_value_pdf  # noqa: E402


@requires_pdf_tables
@requires_reportlab
def test_label_value_lines_are_read_as_prose_with_every_word_whole(tmp_path):
    path = tmp_path / "summary.pdf"
    write_label_value_pdf(path)
    text = read_text(path)
    # Whole values, exactly as printed: nothing split at an invented column edge.
    for value in ("Springfield, IL 62704", "2025-08-02", "2025-08-09", "Hematocrit 31%."):
        assert value in text
    assert "| --- |" not in text


@requires_pdf_tables
@requires_reportlab
def test_cli_text_output_of_a_label_value_pdf_holds_no_identifier(tmp_path, capsys):
    from stripii.cli import EXIT_OK, main

    path = tmp_path / "summary.pdf"
    write_label_value_pdf(path)
    assert main(["scrub", str(path), "-p", "health", "-q"]) == EXIT_OK
    out = capsys.readouterr().out
    # Invented values from examples/discharge-summary.txt. Under Safe Harbor the
    # city goes, the ZIP keeps three digits, and dates keep only the year.
    for value in ("Whitfield", "4471982", "Oakmont", "Springfield", "62704",
                  "08-02", "08-09", "555-0142", "412-88-9031", "XHP449182736"):
        assert value not in out, value
    assert "Hemoglobin 10.2 g/dL" in out
