"""Person-name detection.

Names are the one identifier with no format to validate against, so this uses
three layers of decreasing certainty and lets the confidence score decide what
survives:

1. **Labelled** -- ``Patient Name: Jane A. Smith``. The label proves the intent.
2. **Titled / credentialled** -- ``Dr. Robert Chen``, ``Chen, MD``.
3. **Anchored** -- a capitalised sequence containing a known given name, minus
   anything in the clinical/financial gazetteer.

An optional spaCy backend can be layered on top for documents where names appear
with none of those cues. It is off by default: the point of this tool is that it
runs locally with no model download and no network call.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar

from ..types import Detection
from .base import PatternRecognizer
from .gazetteer import (
    GIVEN_NAMES,
    NAME_LABELS,
    NON_NAME_TERMS,
    RELATIONSHIPS,
    SUFFIXES,
    TITLES,
)

#: One capitalised name-shaped token: "Jane", "O'Brien", "Smith-Jones", "A."
#: The second branch exists for names where the capital is followed straight
#: away by an apostrophe, which the first branch cannot match.
_TOKEN = (
    "[A-Z](?:"
    "[a-z]+(?:['\u2019\\-][A-Z]?[a-z]+)*"   # Jane, Smith-Jones, Anne-Marie
    "|['\u2019][A-Z]?[a-z]+"                  # O'Brien, D'Angelo
    "|\\."                                    # A.
    ")"
)
#: The same token printed in capitals: "ANAYA", "O'BRIEN", "SMITH-JONES".
#: Indian forms, bank statements, payslips and ID cards print names this way
#: almost without exception. A title-case-only pattern missed every one of
#: them -- 184 of 184 in the first run against real documents.
_CAPS_TOKEN = (
    "[A-Z](?:"
    "[A-Z]+(?:['\u2019\\-][A-Z]+)*"           # ANAYA, SMITH-JONES
    "|['\u2019][A-Z]+"                         # O'BRIEN
    "|\\."                                     # A.
    ")"
)
_LABEL_ALT = "|".join(re.escape(label) for label in NAME_LABELS)
_TITLE_ALT = "|".join(TITLES)

#: Up to four such tokens in a row, optionally introduced by an honorific.
#: The honorific is folded into the sequence so that a labelled value like
#: "Attending: Dr. Robert Chen" does not stop at the "Dr." abbreviation dot.
_SEQUENCE = rf"(?:(?:{_TITLE_ALT})\.?[ ])?{_TOKEN}(?:[ ]{_TOKEN}){{0,3}}"
_CAPS_SEQUENCE = rf"(?:(?i:{_TITLE_ALT})\.?[ ])?{_CAPS_TOKEN}(?:[ ]{_CAPS_TOKEN}){{0,3}}"
#: Either casing. The capitals branch must not end mid-word, or it would take
#: the "J" of "Jane" and stop.
_ANY_SEQUENCE = f"(?:{_CAPS_SEQUENCE}(?![a-z])|{_SEQUENCE})"
_SUFFIX_ALT = "|".join(re.escape(s) for s in SUFFIXES)

#: Between a label and its value: a colon or dash, or -- once a document has
#: been rendered as a Markdown table -- one or more cell boundaries, as in
#: "| Applicant Name | - | ANAYA RAGHUNATHAN |".
_LABEL_SEPARATOR = "[ ]*(?:[:\\-\u2013|][ ]*)+"

LABELLED_NAME = PatternRecognizer(
    "PERSON",
    [f"(?<![A-Za-z])(?i:{_LABEL_ALT}){_LABEL_SEPARATOR}(?P<name>{_ANY_SEQUENCE})"],
    name="person_labelled",
    score=0.9,
    group="name",
    flags=0,
)

TITLED_NAME = PatternRecognizer(
    "PERSON",
    [rf"\b(?:{_TITLE_ALT})\.?[ ]+(?P<name>{_SEQUENCE})"],
    name="person_titled",
    score=0.88,
    group="name",
    flags=0,
)

#: Anything whose whole match is a gazetteer term is not a person, however it
#: was introduced: "her daughter Diabetes" is a parse accident, not a name.
_NON_NAME_DENY = "(?i)(?:" + "|".join(sorted(NON_NAME_TERMS)) + r")\.?"

#: A relationship word introduces a name even when nothing else does. This is
#: the common shape in narrative clinical notes -- "her daughter Elena" -- where
#: there is no label, no title and no credential to go on.
RELATIVE_NAME = PatternRecognizer(
    "PERSON",
    [
        f"(?<![A-Za-z])(?i:{'|'.join(re.escape(r) for r in RELATIONSHIPS)})"
        f"(?:[ ,:|\\-\u2013]+)(?P<name>{_ANY_SEQUENCE})"
    ],
    name="person_relative",
    score=0.7,
    group="name",
    deny=[_NON_NAME_DENY],
    flags=0,
)

CREDENTIALLED_NAME = PatternRecognizer(
    "PERSON",
    [rf"(?P<name>{_SEQUENCE}),[ ]*(?:{_SUFFIX_ALT})\b\.?"],
    name="person_credentialled",
    score=0.85,
    group="name",
    flags=0,
)

_SEQUENCE_RE = re.compile(_SEQUENCE)
_TOKEN_RE = re.compile(_TOKEN)
_CAPS_SEQUENCE_RE = re.compile(
    rf"(?<![A-Za-z]){_CAPS_TOKEN}(?:[ ]{_CAPS_TOKEN}){{0,3}}(?![A-Za-z])"
)
_CAPS_TOKEN_RE = re.compile(_CAPS_TOKEN)


def _normalise(token: str) -> str:
    return token.strip(".").lower()


def _emit_run(
    text: str, run: list[tuple[str, int, int]], *, capitals: bool = False
) -> Detection | None:
    """Turn one run of non-gazetteer tokens into a detection, if it looks like a name."""
    if not run:
        return None
    words = [_normalise(tok) for tok, _, _ in run]
    if not any(word in GIVEN_NAMES for word in words):
        return None
    # A lone initial is not a name; a lone given name is only a hint.
    meaningful = [word for word in words if len(word) > 1]
    if not meaningful:
        return None
    if capitals:
        # Capitalised headings ("TRADE MARK", "BILL AMOUNT") are commoner than
        # capitalised prose, so an unlabelled capital run needs two real tokens
        # and scores a shade lower than its title-case equivalent.
        if len(meaningful) < 2:
            return None
        score = 0.58
    else:
        score = 0.62 if len(meaningful) >= 2 else 0.45
    start, end = run[0][1], run[-1][2]
    return Detection(
        entity="PERSON",
        start=start,
        end=end,
        raw=text[start:end],
        detector="person_anchored_caps" if capitals else "person_anchored",
        score=score,
        meta={"tokens": len(meaningful)},
    )


def _anchored_runs(
    text: str,
    sequence_re: re.Pattern[str],
    token_re: re.Pattern[str],
    *,
    capitals: bool,
) -> Iterator[Detection]:
    for match in sequence_re.finditer(text):
        raw = match.group(0).rstrip()
        if not raw:
            continue
        offset = match.start()
        tokens = [
            (m.group(0), offset + m.start(), offset + m.end())
            for m in token_re.finditer(raw)
        ]
        run: list[tuple[str, int, int]] = []
        for token in [*tokens, None]:
            if token is None or _normalise(token[0]) in NON_NAME_TERMS:
                detection = _emit_run(text, run, capitals=capitals)
                if detection is not None:
                    yield detection
                run = []
            else:
                run.append(token)


def find_anchored_names(text: str) -> Iterator[Detection]:
    """Capitalised sequences anchored by a known given name.

    A gazetteer term inside the sequence splits it rather than discarding it.
    "Patient Margaret Whitfield" is one capitalised run, and rejecting the whole
    thing because "Patient" is a suppressed term loses the actual name; the
    right answer is to keep "Margaret Whitfield" and drop the label. The same
    scan runs over ALL-CAPS text, where "PATIENT ANAYA RAGHUNATHAN" is the norm.
    """
    yield from _anchored_runs(text, _SEQUENCE_RE, _TOKEN_RE, capitals=False)
    yield from _anchored_runs(text, _CAPS_SEQUENCE_RE, _CAPS_TOKEN_RE, capitals=True)


class AnchoredNameRecognizer:
    """Wraps :func:`find_anchored_names` in the recognizer interface."""

    name = "person_anchored"
    entity = "PERSON"

    def detect(self, text: str) -> Iterator[Detection]:
        return find_anchored_names(text)


class SpacyNameRecognizer:
    """Optional NER backend.

    Enabled with ``--ner``. Requires ``pip install stripii[ner]`` and a model;
    if either is missing we raise at construction time rather than silently
    detecting nothing, because a redaction tool that quietly does less than you
    asked is worse than one that refuses to start.
    """

    name = "person_ner"
    entity = "PERSON"

    #: spaCy labels worth mapping onto our entity vocabulary.
    LABEL_MAP: ClassVar[dict[str, str]] = {
        "PERSON": "PERSON",
        "PER": "PERSON",
        "GPE": "LOCATION",
        "LOC": "LOCATION",
        "FAC": "LOCATION",
        "ORG": "ORGANIZATION",
    }

    def __init__(self, model: str = "en_core_web_sm", entities: tuple[str, ...] = ("PERSON",)):
        try:
            import spacy
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "NER backend requested but spaCy is not installed. "
                "Install it with: pip install 'stripii[ner]'"
            ) from exc
        try:
            self._nlp = spacy.load(model, disable=["lemmatizer", "textcat"])
        except OSError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                f"NER backend requested but spaCy model {model!r} is not downloaded. "
                f"Install it with: python -m spacy download {model}"
            ) from exc
        self._wanted = set(entities)

    def detect(self, text: str) -> Iterator[Detection]:
        for ent in self._nlp(text).ents:
            mapped = self.LABEL_MAP.get(ent.label_)
            if mapped is None or mapped not in self._wanted:
                continue
            if ent.text.strip().lower() in NON_NAME_TERMS:
                continue
            yield Detection(
                entity=mapped,
                start=ent.start_char,
                end=ent.end_char,
                raw=ent.text,
                detector="person_ner",
                score=0.7,
                meta={"spacy_label": ent.label_},
            )


NAME_RECOGNIZERS = [
    LABELLED_NAME,
    TITLED_NAME,
    CREDENTIALLED_NAME,
    RELATIVE_NAME,
    AnchoredNameRecognizer(),
]
