#!/usr/bin/env python3
"""Write a redacted PDF for every document in a folder, and optionally prove it.

    python tools/redact_folder.py private/records private/redacted
    python tools/redact_folder.py private/records private/redacted --verify

Each input becomes ``<out>/<subfolder>/<name>.pdf`` with the redaction drawn
onto the page image: black boxes, no text layer underneath, so nothing can be
selected or copied out from under them. PDFs with a real text layer are
redacted from that layer's exact word positions; scans, photos and PDFs with
image-only pages go through local OCR.

The profile follows the subfolder: ``medical`` -> health, ``financial`` ->
finance, anything else -> paranoid.

``--verify`` then reads each redacted page back and checks that no detected
value is still legible -- the same measurement ``redact_file`` grades every
output with. It prints counts, grades and masked shapes ("XXXX9999X") only,
never a value. It is the only check that looks at the ink rather than the text.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from stripii import redact_file
from stripii.document import GRADE_WORDS, shape
from stripii.readers import kind_of

logging.disable(logging.CRITICAL)

PROFILE_BY_FOLDER = {"medical": "health", "financial": "finance"}


def label(index: int, path: Path) -> str:
    """How a file is named on screen: its index and the shape of its name.

    A file name is often the most identifying thing about a document
    ("Whitfield_M_bloodwork.pdf"), and this output gets pasted into issues and
    chat. The index and the masked shape are enough to find the file again.
    """
    return f"#{index:03d} {shape(path.stem)[:24]}{path.suffix.lower()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--verify", action="store_true", help="OCR the results to prove the ink")
    parser.add_argument("--ocr-engine", default="auto", choices=["auto", "vision", "tesseract"])
    args = parser.parse_args()

    files = sorted(
        p for p in args.source.rglob("*")
        if p.is_file() and not p.name.startswith(".") and kind_of(p) in {"pdf", "image"}
    )
    written, problems = 0, 0
    total_checked = total_left = 0
    grades: dict[str, int] = {}
    for index, path in enumerate(files, 1):
        profile = PROFILE_BY_FOLDER.get(path.parent.name, "paranoid")
        out = args.destination / path.parent.relative_to(args.source) / (path.stem + ".pdf")
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = redact_file(
                path, profile=profile, outputs=("pdf",), ocr=args.ocr_engine, verify=args.verify
            )
        except Exception as exc:  # report and carry on with the rest
            print(f"  FAILED    {label(index, path)}: {type(exc).__name__}")
            problems += 1
            continue
        out.write_bytes(result.outputs["pdf"])
        written += 1
        grades[result.grade] = grades.get(result.grade, 0) + 1
        note = ""
        if result.unreadable_pages:
            note = f"  (OCR could barely read page(s) {result.unreadable_pages}: check by eye)"
            problems += 1
        grade = GRADE_WORDS[result.grade] if args.verify else ""
        print(f"  {result.source:<10} {result.total:>4} redacted  {grade:<5} {label(index, path)}{note}")

        if args.verify:
            total_checked += result.checked
            total_left += result.still_legible
            leaks = [s for s in result.spots if s.legible]
            if leaks:
                problems += 1
                shapes = list(dict.fromkeys(s.shape for s in leaks))[:3]
                print(f"             still legible: {result.still_legible} of {result.checked}"
                      f" -- e.g. {', '.join(shapes)}")

    print(f"\n{written} of {len(files)} written to {args.destination}")
    if args.verify:
        print(f"verified: {total_checked - total_left} of {total_checked} values read back are covered")
        print("grades: " + ", ".join(f"{GRADE_WORDS[g]}={n}" for g, n in sorted(grades.items())))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
