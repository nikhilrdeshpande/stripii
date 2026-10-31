"""Building Markdown, which is how a document should reach a language model.

Plain text throws away the grid. A lab panel flattened to one cell per line is
unreadable -- nothing says that 10.2 belongs to Hemoglobin rather than to
Glucose -- and a redactor that destroys the structure before it starts has
already lost the thing the model was supposed to read.

Markdown pipe tables are the de facto interchange format for feeding documents
to models, and they have a property that matters here: each cell stays a
separate token run, so cell-level redaction works without disturbing the grid.
"""

from __future__ import annotations

from collections.abc import Sequence

Row = Sequence[object]


def _cell(value: object) -> str:
    """Render one cell, keeping it on a single line and safe inside a table."""
    if value is None:
        return ""
    text = str(value).strip()
    # A literal pipe would split the cell; a newline would end the row.
    text = text.replace("|", "\\|")
    return " ".join(text.split())


def pipe_table(rows: Sequence[Row], *, header: bool = True) -> str:
    """Render rows as a Markdown pipe table.

    Ragged rows are padded rather than rejected: a merged cell or a trailing
    empty column is normal in a real document, and dropping the row would lose
    data that might be exactly what needed redacting.
    """
    materialised = [[_cell(c) for c in row] for row in rows if row is not None]
    if not materialised:
        return ""
    width = max(len(row) for row in materialised)
    if width == 0:
        return ""
    for row in materialised:
        row.extend([""] * (width - len(row)))

    if header:
        head, body = materialised[0], materialised[1:]
    else:
        head, body = [""] * width, materialised

    lines = [
        "| " + " | ".join(head) + " |",
        "|" + "|".join([" --- "] * width) + "|",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in body)
    return "\n".join(lines)


def is_empty_table(rows: Sequence[Row]) -> bool:
    return not any(any(_cell(c) for c in (row or ())) for row in rows)


def drop_blank_rows(rows: Sequence[Row]) -> list[list[object]]:
    """Remove wholly empty rows.

    Alignment-based table detection in a PDF emits one of these between every
    real row, because the gap between lines reads as a row boundary. They are
    an artefact of the detector, never content.
    """
    return [list(row) for row in rows if row and any(_cell(c) for c in row)]
