"""Markdown rendering, and the table fidelity the whole output format exists for."""

from __future__ import annotations

import pytest

from stripii import Scrubber, get_profile
from stripii.markdown import drop_blank_rows, is_empty_table, pipe_table


def test_pipe_table_basic_shape():
    out = pipe_table([["Test", "Result"], ["Hemoglobin", "10.2"]])
    assert out.splitlines() == [
        "| Test | Result |",
        "| --- | --- |",
        "| Hemoglobin | 10.2 |",
    ]


def test_ragged_rows_are_padded_not_dropped():
    """A merged cell must not cost us a row that might contain an identifier."""
    out = pipe_table([["A", "B", "C"], ["only-one"]])
    assert out.splitlines()[-1] == "| only-one |  |  |"


def test_pipes_inside_a_cell_are_escaped():
    assert r"x\|y" in pipe_table([["A"], ["x|y"]])


def test_newlines_inside_a_cell_are_flattened():
    out = pipe_table([["A"], ["two\nlines"]])
    assert "| two lines |" in out
    assert len(out.splitlines()) == 3


def test_non_string_cells_render():
    assert "| 142 |" in pipe_table([["v"], [142]])
    assert pipe_table([["v"], [None]]).endswith("|  |")


@pytest.mark.parametrize("rows", [[], [[]], [["", ""], [None, "  "]]])
def test_empty_tables_are_recognised(rows):
    assert is_empty_table(rows)
    assert pipe_table(rows) == "" or not drop_blank_rows(rows)


def test_drop_blank_rows_keeps_real_ones():
    rows = [["A", "B"], ["", ""], ["x", "y"], [None, None]]
    assert drop_blank_rows(rows) == [["A", "B"], ["x", "y"]]


# --------------------------------------------------------------------------
# the point of all this: a table survives redaction intact
# --------------------------------------------------------------------------

LAB_TABLE = """Patient: Margaret Whitfield    MRN: 4471982

| Test | Result | Ref Range | Flag |
| --- | --- | --- | --- |
| Hemoglobin | 10.2 | 12.0-15.5 | LOW |
| Glucose | 142 | 70-99 | HIGH |
| Creatinine | 1.8 | 0.6-1.1 | HIGH |"""


def test_a_lab_table_survives_scrubbing_intact():
    result, _ = Scrubber(get_profile("health")).scrub(LAB_TABLE)
    out = result.text
    # identifiers gone
    assert "Margaret Whitfield" not in out
    assert "4471982" not in out
    # every cell of the grid still present and aligned
    for value in ["Hemoglobin", "10.2", "12.0-15.5", "LOW",
                  "Glucose", "142", "70-99", "HIGH",
                  "Creatinine", "1.8", "0.6-1.1"]:
        assert value in out, f"{value!r} was destroyed"
    # the grid itself is unchanged
    assert out.count("|") == LAB_TABLE.count("|")
    assert len(out.splitlines()) == len(LAB_TABLE.splitlines())
