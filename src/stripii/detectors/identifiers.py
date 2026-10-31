"""Your own identifiers: values the user has said must always go.

The detectors find what *looks like* personal data. This one finds what the
user *knows* is theirs -- their name, a family member's, an account number, a
street -- regardless of how it is written or whether a label sits beside it.
It is the answer to the survivors on real documents: a surname that is also an
English word, an unlabelled uncommon name, a bare city.

A **name** ("Margaret Whitfield") is looked for in every form a document
writes it:

* the whole name, in any casing, with any light separator between the parts
  or none at all -- ``MARGARET WHITFIELD``, ``Margaret-Whitfield``,
  ``MargaretWhitfield`` (a bank narration);
* each part alone, as a whole word -- ``Whitfield``, ``margaret``;
* the surname with initials -- ``M. Whitfield``, ``M Whitfield``;
* a part of five letters or more glued inside a longer token --
  ``mwhitfield@example.com``, ``whitfield1934``.

Anything else (a number, an email, an address) is matched as a whole, in any
casing, tolerating the separators OCR and formatting introduce.

Name-like identifiers are emitted as PERSON, so the engine's own name
propagation applies to them as well, and the placeholder reads ``[[PERSON_n]]``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from ..types import Detection
from .gazetteer import TITLES

ENTITY = "IDENTIFIER"
_NAME_LIKE = re.compile(r"^[A-Za-z][A-Za-z .'\-]*$")
_SEPARATOR = r"[^A-Za-z0-9|\r\n]{0,3}"
_BOUNDARY_START = r"(?<![A-Za-z0-9])"
_BOUNDARY_END = r"(?![A-Za-z0-9])"
#: Up to two initials before a surname: "M. Whitfield", "M E Whitfield".
#: A lower-case letter needs its dot, so "a Whitfield" is not swallowed.
_INITIALS = r"(?:(?:[A-Z]\.?|[a-z]\.)[ ]?){1,2}"

#: A name part shorter than this is not looked for on its own: "Li" alone
#: is every "li" in the document.
PART_MIN_CHARS = 3
#: A part at least this long is distinctive enough to find inside other
#: tokens -- an email's local part, a UPI handle, a file name.
GLUED_MIN_CHARS = 5

_TITLES = frozenset(t.lower() for t in TITLES)


def _chunks(value: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9]+", value)


def _whole(chunks: Sequence[str]) -> re.Pattern[str]:
    body = _SEPARATOR.join(re.escape(c) for c in chunks)
    return re.compile(_BOUNDARY_START + body + _BOUNDARY_END, re.IGNORECASE)


def _name_parts(value: str) -> list[str]:
    """The words of a name, without titles and initials."""
    parts = []
    for token in re.findall(r"[A-Za-z]+", value):
        if token.lower() in _TITLES or len(token) < 2:
            continue
        parts.append(token)
    return parts


class IdentifierRecognizer:
    """Finds every occurrence, in every written form, of each identifier supplied."""

    name = "identifier"
    entity = ENTITY

    def __init__(self, identifiers: Sequence[str]) -> None:
        self.identifiers = [i.strip() for i in identifiers if i and i.strip()]
        #: (pattern, entity, score)
        self._patterns: list[tuple[re.Pattern[str], str, float]] = []
        for value in self.identifiers:
            if _NAME_LIKE.match(value):
                self._compile_name(value)
            else:
                chunks = _chunks(value)
                if chunks:
                    self._patterns.append((_whole(chunks), ENTITY, 0.99))

    def _compile_name(self, value: str) -> None:
        parts = _name_parts(value)
        if not parts:
            return
        self._patterns.append((_whole(parts), "PERSON", 0.99))
        if len(parts) >= 2:
            # Glued, inside a token, in either order: "mwhitfield", "whitfieldmargaret".
            for order in (parts, list(reversed(parts))):
                body = "".join(re.escape(p) for p in order)
                self._patterns.append((re.compile(body, re.IGNORECASE), "PERSON", 0.97))
        surname = parts[-1]
        if len(surname) >= PART_MIN_CHARS:
            self._patterns.append((
                re.compile(
                    _BOUNDARY_START + _INITIALS + re.escape(surname) + _BOUNDARY_END
                ),
                "PERSON", 0.97,
            ))
        for part in parts:
            if len(part) >= PART_MIN_CHARS:
                self._patterns.append((_whole([part]), "PERSON", 0.95))
            if len(part) >= GLUED_MIN_CHARS:
                self._patterns.append((re.compile(re.escape(part), re.IGNORECASE), "PERSON", 0.9))

    def detect(self, text: str) -> Iterable[Detection]:
        for pattern, entity, score in self._patterns:
            for match in pattern.finditer(text):
                yield Detection(
                    entity=entity,
                    start=match.start(),
                    end=match.end(),
                    raw=match.group(0),
                    detector=self.name,
                    score=score,
                    meta={"identifier": True},
                )
