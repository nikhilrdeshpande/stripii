"""Core data types shared by detectors, the engine and the redactors."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Action(str, enum.Enum):
    """What to do with a detected entity."""

    REDACT = "redact"          # replace entirely with a placeholder
    MASK = "mask"              # keep a short suffix, e.g. ****1234
    HASH = "hash"              # replace with a keyed digest
    GENERALIZE = "generalize"  # coarsen: 1984-03-02 -> 1984, 94107 -> 941**
    SURROGATE = "surrogate"    # a realistic stand-in from a reserved range
    ENCRYPT = "encrypt"        # format-preserving encryption (NIST SP 800-38G FF1)
    KEEP = "keep"              # leave untouched (documented, deliberate)


@dataclass(frozen=True)
class Detection:
    """A single candidate span of sensitive data found in the text.

    Offsets are half-open character indices into the document the detector ran
    against, so ``text[start:end] == raw``.
    """

    entity: str
    start: int
    end: int
    #: The detected text itself: personal data, so kept out of repr. A
    #: detection printed in a log or a failing assertion shows where and what
    #: kind, never the value.
    raw: str = field(repr=False)
    detector: str
    score: float = 0.5
    meta: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Detection) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class Replacement:
    """A resolved decision: this span becomes this text.

    ``text`` is kept out of repr as well: a mask keeps part of the value, and a
    surrogate or an encrypted value is reversible with the key.
    """

    detection: Detection
    action: Action
    text: str = field(repr=False)


@dataclass
class ScrubResult:
    """Everything a caller needs after scrubbing one document.

    Its repr shows counts only. ``text`` is the redacted text, but it is only
    as clean as the detectors' recall, which is no reason to print it.
    """

    text: str
    replacements: list[Replacement] = field(default_factory=list)
    skipped: list[Detection] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.replacements:
            out[r.detection.entity] = out.get(r.detection.entity, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def total(self) -> int:
        return len(self.replacements)

    def __repr__(self) -> str:
        return (
            f"ScrubResult(<{len(self.text)} chars>, counts={self.counts}, "
            f"skipped={len(self.skipped)})"
        )
