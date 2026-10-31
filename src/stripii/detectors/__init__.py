"""Detectors: pattern, gazetteer and optional NER backends."""

from __future__ import annotations

from .base import FunctionRecognizer, PatternRecognizer, Recognizer
from .identifiers import IdentifierRecognizer
from .names import NAME_RECOGNIZERS, SpacyNameRecognizer
from .patterns import ALL_ENTITIES, ALL_RECOGNIZERS

__all__ = [
    "ALL_ENTITIES",
    "ALL_RECOGNIZERS",
    "NAME_RECOGNIZERS",
    "FunctionRecognizer",
    "IdentifierRecognizer",
    "PatternRecognizer",
    "Recognizer",
    "SpacyNameRecognizer",
]
