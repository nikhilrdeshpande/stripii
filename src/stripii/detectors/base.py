"""The detector framework.

A detector turns raw text into :class:`Detection` candidates. Nearly every
detector here is a regex plus two refinements that do the real work:

* a **validator** (usually a checksum) that rejects lookalikes, and
* a **context window** -- weak patterns such as "a 10-digit number" only count
  as an account number when a word like "account" sits nearby.

Keeping both knobs declarative means the entity catalogue in ``patterns.py``
reads like a policy document rather than like code.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Protocol

from ..types import Detection

Validator = Callable[[str], bool]

#: How far either side of a match we look for supporting keywords.
CONTEXT_WINDOW = 48


class Recognizer(Protocol):
    """Anything that can find sensitive spans in text."""

    name: str
    entity: str

    def detect(self, text: str) -> Iterable[Detection]: ...


def _compile(patterns: Sequence[str], flags: int) -> list[re.Pattern[str]]:
    return [re.compile(p, flags) for p in patterns]


class PatternRecognizer:
    """A regex-driven recognizer with optional validation and context scoring."""

    def __init__(
        self,
        entity: str,
        patterns: Sequence[str],
        *,
        name: str | None = None,
        score: float = 0.6,
        validator: Validator | None = None,
        context: Sequence[str] = (),
        context_boost: float = 0.3,
        requires_context: bool = False,
        deny: Sequence[str] = (),
        group: int | str | None = None,
        flags: int = re.IGNORECASE,
    ) -> None:
        self.entity = entity
        self.name = name or entity.lower()
        self.patterns = _compile(patterns, flags)
        self.score = score
        self.validator = validator
        self.context_boost = context_boost
        self.requires_context = requires_context
        self.group = group
        self._deny = _compile(deny, re.IGNORECASE) if deny else []
        self._context = (
            re.compile(
                r"(?<![a-z0-9])(?:" + "|".join(context) + r")(?![a-z0-9])",
                re.IGNORECASE,
            )
            if context
            else None
        )

    # -- context ---------------------------------------------------------
    @staticmethod
    def _trim_to_nearby_lines(fragment: str, *, from_end: bool) -> str:
        """Drop everything beyond the adjacent line.

        A window measured purely in characters bleeds between fields: an
        ``SSN:`` label two lines up would otherwise vouch for a member ID.
        Labels sit on the value's own line or the one next to it, so that is
        all we look at.
        """
        if from_end:
            parts = fragment.split("\n")
            return "\n".join(parts[:2])
        parts = fragment.split("\n")
        return "\n".join(parts[-2:])

    def _has_context(self, text: str, start: int, end: int) -> bool:
        if self._context is None:
            return False
        left = max(0, start - CONTEXT_WINDOW)
        right = min(len(text), end + CONTEXT_WINDOW)
        before = self._trim_to_nearby_lines(text[left:start], from_end=False)
        after = self._trim_to_nearby_lines(text[end:right], from_end=True)
        return self._context.search(before + " " + after) is not None

    # -- detection -------------------------------------------------------
    def detect(self, text: str) -> Iterator[Detection]:
        seen: set[tuple[int, int]] = set()
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                span = self._span(match)
                if span is None or span in seen:
                    continue
                start, end = span
                raw = text[start:end]
                if not raw.strip():
                    continue
                if any(d.fullmatch(raw) for d in self._deny):
                    continue
                if self.validator is not None and not self.validator(raw):
                    continue
                has_context = self._has_context(text, start, end)
                if self.requires_context and not has_context:
                    continue
                seen.add(span)
                score = min(1.0, self.score + (self.context_boost if has_context else 0.0))
                yield Detection(
                    entity=self.entity,
                    start=start,
                    end=end,
                    raw=raw,
                    detector=self.name,
                    score=score,
                    meta={"context": has_context},
                )

    def _span(self, match: re.Match[str]) -> tuple[int, int] | None:
        """Prefer an explicit capture group so patterns can match surrounding cues."""
        if self.group is not None:
            if match.group(self.group) is None:
                return None
            return match.span(self.group)
        return match.span()


class FunctionRecognizer:
    """Escape hatch for detectors that need real logic rather than a pattern."""

    def __init__(
        self,
        entity: str,
        func: Callable[[str], Iterable[Detection]],
        *,
        name: str | None = None,
    ) -> None:
        self.entity = entity
        self.name = name or entity.lower()
        self._func = func

    def detect(self, text: str) -> Iterable[Detection]:
        return self._func(text)
