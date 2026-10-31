"""One file in, a redacted document out, with a grade measured on that output.

This is the API an application calls. It composes what the library already
does -- read, detect, replace, draw -- and adds the step that makes the result
trustworthy: **the redacted pages are read back**, and every value that was
detected is looked for in what came back. A grade earned that way describes
*this* file, not a statistic from other files.

    result = redact_file("report.pdf", profile="health", outputs=("text", "pdf"))
    result.grade       # "green", "amber" or "red"
    result.outputs     # {"text": b"...", "pdf": b"..."}: bytes, not paths
    result.spots       # where to look, when the grade says so

Outputs are bytes rather than paths on purpose: a sandboxed app may write only
where the user has pointed it, and it decides where that is.
"""

from __future__ import annotations

import importlib.util
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import Scrubber, default_recognizers
from .policy import Policy, get_profile
from .readers import (
    UnsupportedDocument,
    csv_delimiter,
    kind_of,
    read_text,
    scrub_csv,
    scrub_json,
)
from .types import Action, Replacement, ScrubResult
from .vault import Vault

GREEN, AMBER, RED = "green", "amber", "red"
#: The grades as a person reads them: ready to share, check these spots, held.
GRADE_WORDS = {GREEN: "ready", AMBER: "check", RED: "HELD"}

#: Replacement styles, by the action each one requests for redacted entities.
STYLES = {
    "placeholder": Action.REDACT,
    "surrogate": Action.SURROGATE,
    "encrypt": Action.ENCRYPT,
    "hash": Action.HASH,
    "mask": Action.MASK,
}

#: Outputs that need page images, so a PDF or an image as input.
PAGE_OUTPUTS = {"pdf", "image"}
ALL_OUTPUTS = ("text", "pdf", "image")

#: A detection below this score was found on a hint, not a cue: a lone given
#: name from the list, with no label, title or surname beside it. It is
#: redacted, but the neighbourhood deserves a look because what hinted at it
#: may hide more -- an unlisted surname, say. A capitalised run of two or more
#: words (0.58) is a name, not a hint, and does not earn this: on the real
#: documents it marked 28 of 51 for checking, which is noise, not guidance.
WEAK_SCORE = 0.5
#: Values shorter than this, once punctuation is removed, are not looked for
#: on the read-back page: a three-digit CVV re-appears in every amount.
VERIFY_MIN_CHARS = 5

Progress = Callable[[str, int, int], None]


@dataclass(frozen=True)
class Spot:
    """A place on a page to look at, and why."""

    page: int                            # 1-based
    box: tuple[int, int, int, int]       # left, top, right, bottom, in pixels of the page image
    shape: str                           # the value's shape, never the value: "XXXX9999X"
    why: str                             # "still legible", "low-confidence name", ...
    #: The value itself, for an application that lets the user say "always
    #: remove this". Kept out of repr so a printed spot never shows it.
    value: str = field(default="", repr=False, compare=False)

    @property
    def legible(self) -> bool:
        return self.why == "still legible"


@dataclass
class RedactionResult:
    """Everything an application needs after redacting one file.

    Nothing that holds an original value -- the vault, the scrub, the words
    read off the pages -- or the output itself appears in its repr.
    """

    name: str
    kind: str                            # pdf, image, docx, xlsx, csv, json, text
    source: str                          # "text layer", "vision", "tesseract", "text"
    text: str = field(repr=False)        # the redacted text, the thing that gets pasted
    counts: dict[str, int] = field(default_factory=dict)
    outputs: dict[str, bytes] = field(default_factory=dict, repr=False)
    pages: list[Any] = field(default_factory=list, repr=False)  # redacted page images (PIL)
    page_count: int = 0
    grade: str = GREEN
    reasons: list[str] = field(default_factory=list)
    spots: list[Spot] = field(default_factory=list)
    unreadable_pages: list[int] = field(default_factory=list)
    checked: int = 0                     # values looked for on the read-back pages
    still_legible: int = 0               # ...of those, how many could still be read
    verified: bool = False               # whether the output was read back at all
    timings_ms: dict[str, int] = field(default_factory=dict)
    vault: Vault = field(default_factory=Vault, repr=False)
    scrub: ScrubResult | None = field(default=None, repr=False)
    #: What ``redact_boxes`` needs to carry on from here: the read pages and
    #: words, which outputs were asked for, and how to write them.
    read: Any = field(default=None, repr=False)
    wanted: tuple[str, ...] = ("text",)
    image_suffix: str = ".png"
    dpi: int = 200
    placeholder: str = "[[{entity}_{n}]]"
    reviewed: bool = False               # a person applied at least one box after looking at the pages
    #: The scrubber that redacted this file, kept to read the output back with:
    #: verification runs every detector over the redacted pages, not only a
    #: search for the values found the first time.
    scrubber: Any = field(default=None, repr=False)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def shape(value: str) -> str:
    """The shape of a value with its content removed: ``AB12-3`` -> ``XX99-9``."""
    return re.sub(r"[a-z]", "x", re.sub(r"[A-Z]", "X", re.sub(r"\d", "9", value)))[:32]


def legible(value: str, text: str) -> re.Match[str] | None:
    """Where ``value`` can be read in ``text``, allowing for OCR's spacing."""
    chunks = re.findall(r"[a-z0-9]+", value.lower())
    if not chunks:
        return None
    pattern = r"(?<![a-z0-9])" + r"[^a-z0-9]{0,3}".join(map(re.escape, chunks)) + r"(?![a-z0-9])"
    return re.search(pattern, text.lower())


def build_policy(profile: str | Policy, style: str = "placeholder") -> Policy:
    """A profile with every REDACT rewritten to ``style``; other actions untouched.

    Generalisation and masking decisions are left alone, because they are
    about how much information to keep rather than what a replacement looks like.
    """
    policy = get_profile(profile) if isinstance(profile, str) else profile
    try:
        action = STYLES[style]
    except KeyError:
        raise ValueError(f"unknown style {style!r}; choose from {', '.join(STYLES)}") from None
    if action is Action.REDACT:
        return policy
    return Policy(
        name=policy.name,
        description=policy.description,
        default_action=action if policy.default_action is Action.REDACT else policy.default_action,
        actions={e: (action if a is Action.REDACT else a) for e, a in policy.actions.items()},
        min_score=policy.min_score,
        disabled=policy.disabled,
        placeholder=policy.placeholder,
        mask_keep=policy.mask_keep,
    )


def _scrub_structured(
    scrubber: Scrubber, text: str, kind: str, vault: Vault, delimiter: str | None = None
) -> ScrubResult:
    collected: list[ScrubResult] = []

    def fragment(value: str, hint: str | None = None) -> str:
        result, _ = scrubber.scrub(value, vault, context_hint=hint)
        collected.append(result)
        return result.text

    if kind == "json":
        out = scrub_json(text, fragment)
    else:
        out = scrub_csv(text, fragment, delimiter=delimiter)
    return ScrubResult(
        text=out,
        replacements=[r for res in collected for r in res.replacements],
        skipped=[d for res in collected for d in res.skipped],
    )


def scrub_text(
    text: str,
    *,
    profile: str | Policy = "default",
    style: str = "placeholder",
    identifiers: list[str] | None = None,
    kind: str = "text",
    vault: Vault | None = None,
    hash_key: bytes | None = None,
    delimiter: str | None = None,
) -> tuple[ScrubResult, Vault]:
    """Scrub a string. ``kind`` may be ``json`` or ``csv`` to keep that structure.

    For ``csv``, ``delimiter`` is guessed from the first line unless given.
    """
    scrubber = Scrubber(
        build_policy(profile, style), default_recognizers(identifiers=identifiers),
        hash_key=hash_key,
    )
    vault = vault if vault is not None else Vault()
    if kind in {"json", "csv"}:
        return _scrub_structured(scrubber, text, kind, vault, delimiter), vault
    return scrubber.scrub(text, vault)


def _weak(replacement: Replacement) -> bool:
    d = replacement.detection
    return d.entity == "PERSON" and d.score < WEAK_SCORE


def redact_file(
    path: str | Path,
    *,
    profile: str | Policy = "default",
    style: str = "placeholder",
    outputs: tuple[str, ...] = ("text",),
    identifiers: list[str] | None = None,
    ocr: str | Any = "auto",
    verify: bool = True,
    dpi: int = 200,
    on_progress: Progress | None = None,
    hash_key: bytes | None = None,
    force_ocr: bool = False,
) -> RedactionResult:
    """Redact one file and grade the result by reading the output back.

    ``outputs`` is any of ``"text"``, ``"pdf"`` and ``"image"``. Page outputs
    (``pdf``, ``image``) need a PDF or an image in; ``image`` writes the first
    page in the input's own format. A PDF with a text layer is redacted from
    the layer's exact word positions; scans, photos and PDFs with image-only
    pages are read with local OCR (``ocr`` names the engine: ``auto``,
    ``vision``, ``tesseract``, or a backend instance). ``force_ocr`` reads a
    PDF with OCR even when it has a text layer.

    A text-layer page that also carries an image or a drawn annotation is OCR'd
    as well, because the text layer does not describe what is drawn there: a
    photographed ID card pasted onto a page, or a scanner's "searchable" PDF
    whose invisible text layer misread the digits. What either reading finds is
    redacted, from both sets of boxes, and text found only in the images is
    added to the text output.

    The grade: **red** when a detected value can still be read on the output,
    or a page could not be read at all; **amber** when something was found on a
    weak signal, or nothing was found in a document that has text; **green**
    otherwise. Reading back means OCR'ing every output page and running every
    detector over it, so anything detectable that is still legible is red,
    whether or not it was found the first time. ``spots`` says where to look.
    With ``verify=False``, or when no OCR engine is installed to read the
    output back, ``verified`` is False and the grade is at best amber: an
    output nobody read is not a green.
    """
    from . import ocr as ocr_module

    path = Path(path)
    for output in outputs:
        if output not in ALL_OUTPUTS:
            raise ValueError(f"unknown output {output!r}; choose from {', '.join(ALL_OUTPUTS)}")
    kind = kind_of(path)
    wants_pages = bool(PAGE_OUTPUTS & set(outputs))
    if wants_pages and kind not in {"pdf", "image"}:
        raise UnsupportedDocument(
            f"{path.name}: a redacted PDF or image can only be made from a PDF or an image"
        )
    if kind == "pdf":
        ocr_module.check_dpi(dpi)
        if importlib.util.find_spec("pypdfium2") is not None:
            dpi = ocr_module.fit_dpi(path, dpi)      # one oversized page lowers it, not refuses
    timings: dict[str, int] = {}
    progress = on_progress or (lambda stage, done, total: None)

    def timed(stage: str, started: float) -> None:
        timings[stage] = round((time.perf_counter() - started) * 1000)

    policy = build_policy(profile, style)
    scrubber = Scrubber(policy, default_recognizers(identifiers=identifiers), hash_key=hash_key)
    vault = Vault()

    # -- read ------------------------------------------------------------
    started = time.perf_counter()
    progress("reading", 0, 1)
    read = None
    page_ocr = None            # OCR of the text-layer pages that carry images
    not_read: list[int] = []   # ...of those, pages no OCR engine was there to read
    if kind in {"pdf", "image"}:
        if kind == "pdf" and not force_ocr:
            try:
                read = ocr_module.read_text_layer(path, dpi=dpi)
            except ocr_module.DocumentTooLarge:
                raise
            except UnsupportedDocument:
                read = None                       # a scan, or image-only pages
        if read is None:
            read = ocr_module.read_document(path, dpi=dpi, backend=ocr)
        elif read.pages_needing_ocr:
            try:
                page_ocr = ocr_module.read_some_pages(
                    read.images, read.pages_needing_ocr, backend=ocr
                )
            except ocr_module.OcrUnavailable:
                not_read = [number + 1 for number in read.pages_needing_ocr]
            else:
                read = ocr_module.with_image_text(read, page_ocr)
        text, source = read.text, read.source
        if page_ocr is not None:
            source = f"{read.source} + {page_ocr.source}"
    else:
        text, source = read_text(path), "text"
    timed("read", started)
    progress("reading", 1, 1)

    # -- redact ----------------------------------------------------------
    started = time.perf_counter()
    progress("redacting", 0, 1)
    if kind in {"json", "csv"}:
        delimiter = csv_delimiter(path, text) if kind == "csv" else None
        scrub = _scrub_structured(scrubber, text, kind, vault, delimiter)
    else:
        scrub, _ = scrubber.scrub(text, vault)
    ocr_boxes: list[Box] = []
    if page_ocr is not None:
        scrub, ocr_boxes = _add_page_ocr(read, scrub, page_ocr, scrubber, vault)
    unreadable = sorted({*(read.unreadable_pages if read else []), *not_read})
    result = RedactionResult(
        name=path.name, kind=kind, source=source, text=scrub.text, counts=scrub.counts,
        vault=vault, scrub=scrub, unreadable_pages=unreadable,
        page_count=len(read.images) if read else 0, timings_ms=timings, read=read,
        wanted=tuple(outputs), image_suffix=path.suffix if kind == "image" else ".png",
        dpi=dpi, placeholder=policy.placeholder, scrubber=scrubber,
    )
    if read is not None:
        spans = [(r.detection.start, r.detection.end) for r in scrub.replacements]
        result.pages = ocr_module.redact_images(read, spans)
        _paint(result.pages, ocr_boxes)
    _write_outputs(result)
    timed("redact", started)
    progress("redacting", 1, 1)

    # -- verify and grade -----------------------------------------------
    started = time.perf_counter()
    _verify(result, ocr=ocr, verify=verify, progress=progress)
    timed("verify", started)
    _grade(result, text)
    return result


def _splice(text: str, replacements: list[Replacement]) -> str:
    """``text`` with each replacement's span swapped for its text (spans must not overlap)."""
    pieces, cursor = [], 0
    for r in sorted(replacements, key=lambda r: r.detection.start):
        pieces.append(text[cursor:r.detection.start])
        pieces.append(r.text)
        cursor = r.detection.end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _paint(pages: list[Any], boxes: list[Box], padding: int = 2) -> None:
    from PIL import ImageDraw

    for page, (left, top, right, bottom) in boxes:
        if 1 <= page <= len(pages):
            ImageDraw.Draw(pages[page - 1]).rectangle(
                (left - padding, top - padding, right + padding, bottom + padding),
                fill=(0, 0, 0),
            )


def _add_page_ocr(
    read: Any, scrub: ScrubResult, page_ocr: Any, scrubber: Scrubber, vault: Vault
) -> tuple[ScrubResult, list[Box]]:
    """Fold what OCR found on image-bearing pages into a text-layer redaction.

    Everything detected in the OCR text is painted from the OCR boxes. Words of
    the text layer lying under those boxes are redacted from the text output as
    well: in a scanner's searchable PDF the invisible layer may read the SSN as
    ``2l9-O9-99g9``, which no detector recognises, while OCR of the same pixels
    reads ``219-09-9999``.
    """
    from .types import Detection

    found, _ = scrubber.scrub(page_ocr.text, vault)
    taken = [(r.detection.start, r.detection.end) for r in scrub.replacements]
    by_page: dict[int, list[Any]] = {}
    for word in read.words:
        by_page.setdefault(word.page, []).append(word)
    boxes: list[Box] = []
    extras: list[Replacement] = []
    for replacement in found.replacements:
        d = replacement.detection
        seen = page_ocr.words_in(d.start, d.end)
        boxes.extend((w.page + 1, w.box) for w in seen)
        under = sorted(
            {
                word for w in seen for word in by_page.get(w.page, [])
                if _overlaps(word.box, w.box)
                and not any(word.start < e and s < word.end for s, e in taken)
            },
            key=lambda word: word.start,
        )
        runs: list[list[Any]] = []
        for word in under:
            if runs and not read.text[runs[-1][-1].end:word.start].strip():
                runs[-1].append(word)
            else:
                runs.append([word])
        for run in runs:
            start, end = run[0].start, run[-1].end
            detection = Detection(
                entity=d.entity, start=start, end=end, raw=read.text[start:end],
                detector=f"ocr:{d.detector}", score=d.score,
            )
            extras.append(Replacement(detection, replacement.action, replacement.text))
            taken.append((start, end))
    if not extras:
        return scrub, boxes
    replacements = sorted([*scrub.replacements, *extras], key=lambda r: r.detection.start)
    merged = ScrubResult(
        text=_splice(read.text, replacements), replacements=replacements,
        skipped=list(scrub.skipped),
    )
    return merged, boxes


def _write_outputs(result: RedactionResult) -> None:
    """Encode the outputs that were asked for, from the redacted text and pages."""
    from . import ocr as ocr_module

    result.outputs = {}
    if "text" in result.wanted:
        result.outputs["text"] = result.text.encode("utf-8")
    if not result.pages:
        return
    if "pdf" in result.wanted:
        import io

        buffer = io.BytesIO()
        first, *rest = [p.convert("RGB") for p in result.pages]
        first.save(buffer, format="PDF", save_all=bool(rest), append_images=rest,
                   resolution=float(result.dpi))
        result.outputs["pdf"] = buffer.getvalue()
    if "image" in result.wanted:
        result.outputs["image"] = ocr_module.image_bytes(
            result.pages[0], result.image_suffix, dpi=result.dpi
        )


def _verify(
    result: RedactionResult, *, ocr: str | Any, verify: bool, progress: Progress
) -> None:
    """Read the redacted pages back and record every detected value still on them.

    Fills ``spots`` (weak-signal names first, then anything still legible),
    ``checked``, ``still_legible`` and ``verified``.
    """
    from . import ocr as ocr_module

    read, scrub = result.read, result.scrub
    result.spots = []
    result.checked = result.still_legible = 0
    result.verified = False
    if read is None:
        # Text outputs are their own proof: what was replaced is gone from the string.
        result.verified = True
        result.checked = len(scrub.replacements)
        return
    for replacement in scrub.replacements:
        if _weak(replacement):
            d = replacement.detection
            for word in read.words_in(d.start, d.end):
                result.spots.append(Spot(word.page + 1, word.box, shape(d.raw),
                                         "low-confidence name", value=d.raw.strip()))
    if not verify:
        return
    try:
        engine = ocr_module.get_backend(ocr)
    except ocr_module.OcrUnavailable:
        return
    values = {
        r.detection.raw.strip() for r in scrub.replacements
        if len(re.sub(r"[^A-Za-z0-9]", "", r.detection.raw)) >= VERIFY_MIN_CHARS
    }
    # What we wrote in place of the originals. A surrogate name or an
    # encrypted number is detectable by design and is not a leak.
    produced = "\n".join(r.text for r in scrub.replacements)
    for number, page in enumerate(result.pages):
        progress("checking", number, len(result.pages))
        after = ocr_module.read_images([page], backend=engine)
        flagged: set[tuple[int, int, int, int]] = set()

        def flag(value: str, start: int, end: int, page=page, number=number,
                 after=after, flagged=flagged) -> None:
            boxes = [w.box for w in after.words_in(start, end)] or [
                (0, 0, page.width, page.height)
            ]
            for box in boxes:
                if box not in flagged:
                    flagged.add(box)
                    result.spots.append(Spot(number + 1, box, shape(value), "still legible",
                                             value=value))

        for value in values:
            match = legible(value, after.text)
            if match is not None:
                flag(value, match.start(), match.end())
        # Then every detector over what can be read: a value the first pass
        # never found -- in an image, an annotation, glyphs drawn as shapes --
        # is as legible as one it found and failed to cover.
        if result.scrubber is not None:
            found, _ = result.scrubber.scrub(after.text, Vault())
            for replacement in found.replacements:
                raw = replacement.detection.raw.strip()
                if raw and not legible(raw, produced):
                    flag(raw, replacement.detection.start, replacement.detection.end)
    result.checked = len(values)
    result.still_legible = len({s.value for s in result.spots if s.legible})
    result.verified = True
    progress("checking", len(result.pages), len(result.pages))


def _grade(result: RedactionResult, original_text: str) -> None:
    scrub = result.scrub
    weak = sum(1 for r in scrub.replacements if _weak(r))
    reasons = result.reasons = []
    if result.still_legible:
        reasons.append(f"{result.still_legible} detected value(s) can still be read on the output")
    if result.unreadable_pages:
        pages = ", ".join(str(p) for p in result.unreadable_pages)
        reasons.append(f"page(s) {pages} could not be read, so nothing on them was checked")
    if reasons:
        result.grade = RED
        return
    if not result.verified:
        reasons.append("the output was not read back")
    if weak:
        reasons.append(f"{weak} name(s) found on a weak signal; check around them")
    if not scrub.replacements and original_text.strip():
        reasons.append("nothing was detected; check this is the document you meant")
    result.grade = AMBER if reasons else GREEN


# --------------------------------------------------------------------------
# review: a person adds boxes
# --------------------------------------------------------------------------

Box = tuple[int, tuple[int, int, int, int]]   # (1-based page, (left, top, right, bottom))

MANUAL = "MANUAL"


def _overlaps(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def redact_boxes(
    result: RedactionResult,
    boxes: list[Box],
    *,
    ocr: str | Any = "auto",
    verify: bool = True,
    on_progress: Progress | None = None,
) -> RedactionResult:
    """Paint more boxes onto a graded result, then read it back and grade it again.

    This is the review step: the application shows the pages with the spots
    marked, the person draws or accepts boxes, and the boxes come here. Each
    box is painted onto the page as drawn, and every word under it is also
    removed from the text output, so what is hidden on the page is not left
    in the text. The pages are read back and graded exactly as before; a
    result that comes back green earned it on the new pages.

    Returns a new result; the one passed in is left as it was.
    """
    from .types import Detection, Replacement

    if result.read is None:
        raise ValueError("only a result with pages (a PDF or an image) can be reviewed")
    progress = on_progress or (lambda stage, done, total: None)
    read, scrub = result.read, result.scrub
    timings: dict[str, int] = {}
    started = time.perf_counter()
    progress("redacting", 0, 1)

    # Words under each box become manual replacements, unless already replaced.
    taken = [(r.detection.start, r.detection.end) for r in scrub.replacements]
    new_replacements: list[Replacement] = []
    for page, box in boxes:
        for word in read.words_on(page - 1):
            if not _overlaps(word.box, box):
                continue
            if any(word.start < e and s < word.end for s, e in taken):
                continue
            detection = Detection(entity=MANUAL, start=word.start, end=word.end,
                                  raw=word.text, detector="review", score=1.0)
            text = result.vault.placeholder_for(MANUAL, word.text, result.placeholder)
            new_replacements.append(Replacement(detection, Action.REDACT, text))
            taken.append((word.start, word.end))
    replacements = sorted([*scrub.replacements, *new_replacements],
                          key=lambda r: r.detection.start)
    new_scrub = ScrubResult(text=_splice(read.text, replacements), replacements=replacements,
                            skipped=list(scrub.skipped))

    # The pages: the earlier boxes, plus the words' boxes and the drawn boxes.
    from PIL import ImageDraw

    pages = [p.copy() for p in result.pages]
    for page, box in boxes:
        if 1 <= page <= len(pages):
            ImageDraw.Draw(pages[page - 1]).rectangle(box, fill=(0, 0, 0))
    spans = [(r.detection.start, r.detection.end) for r in new_replacements]
    for word in read.words_in(0, len(read.text)) if spans else []:
        if any(word.start < e and s < word.end for s, e in spans) and word.page < len(pages):
            left, top, right, bottom = word.box
            ImageDraw.Draw(pages[word.page]).rectangle(
                (left - 2, top - 2, right + 2, bottom + 2), fill=(0, 0, 0)
            )

    revised = RedactionResult(
        name=result.name, kind=result.kind, source=result.source, text=new_scrub.text,
        counts=new_scrub.counts, pages=pages, page_count=result.page_count,
        unreadable_pages=list(result.unreadable_pages), timings_ms=timings,
        vault=result.vault, scrub=new_scrub, read=read, wanted=result.wanted,
        image_suffix=result.image_suffix, dpi=result.dpi, placeholder=result.placeholder,
        reviewed=result.reviewed or bool(boxes), scrubber=result.scrubber,
    )
    _write_outputs(revised)
    timings["redact"] = round((time.perf_counter() - started) * 1000)
    progress("redacting", 1, 1)

    started = time.perf_counter()
    _verify(revised, ocr=ocr, verify=verify, progress=progress)
    timings["verify"] = round((time.perf_counter() - started) * 1000)
    _grade(revised, read.text)
    return revised
