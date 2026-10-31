"""Measuring recall, rather than asserting it.

Golden tests prove that specific identifiers in specific documents are caught.
They say nothing about the ones nobody thought to write down. A de-identification
tool that cannot report a recall number is making a claim, not a measurement.

Three matching modes, because they answer different questions:

``strict``
    Exact span and exact entity type. The hardest, and the least interesting for
    privacy: getting the boundary one character wrong is a labelling error, not
    a leak.

``relaxed``
    Overlapping span, same entity type. The usual way de-identification results
    are reported.

``binary``
    Overlapping span, *any* entity type. This is the number that matters here: a
    person's name detected as an MRN is still redacted, and the reader still
    cannot see it. Recall under this mode is the probability an identifier
    survives into the output -- which is the only failure that hurts anyone.

Corpora are not bundled. The i2b2/n2c2 de-identification sets are the standard
benchmark and require a data use agreement, so they cannot be redistributed;
``load_i2b2`` reads them in place for anyone who has one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

from .engine import Scrubber
from .types import Detection

MATCH_MODES = ("strict", "relaxed", "binary")


@dataclass(frozen=True)
class Span:
    """A gold-annotated stretch of personal data."""

    start: int
    end: int
    entity: str

    def overlaps(self, other: Span | Detection) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass
class Document:
    """One corpus document and its gold annotations."""

    doc_id: str
    text: str
    spans: list[Span] = field(default_factory=list)


@dataclass
class Score:
    """Counts for one entity type, or for a whole corpus."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def support(self) -> int:
        return self.true_positives + self.false_negatives

    def __iadd__(self, other: Score) -> Score:
        self.true_positives += other.true_positives
        self.false_positives += other.false_positives
        self.false_negatives += other.false_negatives
        return self


@dataclass
class Report:
    """Per-entity and overall results for one run."""

    mode: str
    profile: str
    documents: int
    overall: Score
    per_entity: dict[str, Score]
    missed: list[tuple[str, Span, str]] = field(default_factory=list)

    @property
    def macro_f1(self) -> float:
        if not self.per_entity:
            return 0.0
        return sum(s.f1 for s in self.per_entity.values()) / len(self.per_entity)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "profile": self.profile,
            "documents": self.documents,
            "overall": {
                "precision": round(self.overall.precision, 4),
                "recall": round(self.overall.recall, 4),
                "f1": round(self.overall.f1, 4),
                "support": self.overall.support,
            },
            "macro_f1": round(self.macro_f1, 4),
            "per_entity": {
                entity: {
                    "precision": round(score.precision, 4),
                    "recall": round(score.recall, 4),
                    "f1": round(score.f1, 4),
                    "support": score.support,
                }
                for entity, score in sorted(self.per_entity.items())
            },
        }


# --------------------------------------------------------------------------
# corpus loading
# --------------------------------------------------------------------------

def load_jsonl(path: Path) -> list[Document]:
    """Read the simple format: one JSON object per line.

    ``{"id": ..., "text": ..., "spans": [{"start": .., "end": .., "entity": ..}]}``
    """
    documents = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        documents.append(
            Document(
                doc_id=str(record.get("id", f"{path.stem}:{number}")),
                text=record["text"],
                spans=[
                    Span(int(s["start"]), int(s["end"]), str(s["entity"]).upper())
                    for s in record.get("spans", [])
                ],
            )
        )
    return documents


#: i2b2/n2c2 PHI tag types mapped onto this tool's entity vocabulary. Several
#: i2b2 types have no counterpart here (PROFESSION, for instance), and are
#: dropped rather than silently scored against an entity that cannot match.
I2B2_TYPE_MAP = {
    "PATIENT": "PERSON", "DOCTOR": "PERSON", "USERNAME": "PERSON",
    "HOSPITAL": "ORGANIZATION", "ORGANIZATION": "ORGANIZATION",
    "CITY": "CITY", "STREET": "STREET_ADDRESS", "ZIP": "US_ZIP",
    "STATE": "LOCATION", "COUNTRY": "LOCATION", "LOCATION-OTHER": "LOCATION",
    "DATE": "DATE", "AGE": "AGE_OVER_89",
    "PHONE": "PHONE", "FAX": "PHONE", "EMAIL": "EMAIL", "URL": "URL",
    "IPADDR": "IP_ADDRESS", "IPADDRESS": "IP_ADDRESS",
    "MEDICALRECORD": "MRN", "IDNUM": "HEALTH_PLAN_ID",
    "HEALTHPLAN": "HEALTH_PLAN_ID", "ACCOUNT": "BANK_ACCOUNT",
    "SSN": "SSN", "LICENSE": "DRIVER_LICENSE", "VEHICLE": "VEHICLE_VIN",
    "DEVICE": "DEVICE_SERIAL", "BIOID": "BIOMETRIC_ID",
}


def load_i2b2(directory: Path) -> list[Document]:
    """Read an i2b2/n2c2 de-identification corpus from its XML files.

    The corpora themselves require a data use agreement and are not bundled;
    point this at your own copy.
    """
    documents = []
    for path in sorted(directory.glob("*.xml")):
        root = ElementTree.parse(path).getroot()
        text_node = root.find("TEXT")
        if text_node is None or text_node.text is None:
            continue
        spans = []
        tags = root.find("TAGS")
        for tag in tags if tags is not None else []:
            entity = I2B2_TYPE_MAP.get((tag.get("TYPE") or "").upper())
            if entity is None:
                continue
            try:
                spans.append(Span(int(tag.get("start")), int(tag.get("end")), entity))
            except (TypeError, ValueError):
                continue
        documents.append(Document(path.stem, text_node.text, spans))
    return documents


def load_corpus(path: Path, fmt: str = "auto") -> list[Document]:
    if fmt == "i2b2" or (fmt == "auto" and path.is_dir()):
        return load_i2b2(path)
    return load_jsonl(path)


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def _matches(gold: Span, prediction: Detection, mode: str) -> bool:
    if mode == "strict":
        return (gold.start, gold.end, gold.entity) == (
            prediction.start, prediction.end, prediction.entity
        )
    if mode == "relaxed":
        return gold.entity == prediction.entity and gold.overlaps(prediction)
    return gold.overlaps(prediction)  # binary: any entity type will do


def evaluate(
    scrubber: Scrubber,
    documents: Sequence[Document],
    *,
    mode: str = "binary",
    collect_misses: bool = True,
) -> Report:
    """Score a scrubber against a gold-annotated corpus."""
    if mode not in MATCH_MODES:
        raise ValueError(f"mode must be one of {', '.join(MATCH_MODES)}")

    overall = Score()
    per_entity: dict[str, Score] = {}
    missed: list[tuple[str, Span, str]] = []

    for document in documents:
        # Score exactly what the tool emits -- Scrubber.plan is the same call
        # scrub() makes. Re-deriving it here has gone wrong twice: first by
        # scoring unresolved alternatives (a routing number is also a plausible
        # account number), then by missing propagation of repeated values.
        predictions, _ = scrubber.plan(document.text)
        matched_predictions: set[int] = set()

        for gold in document.spans:
            bucket = per_entity.setdefault(gold.entity, Score())
            hit = next(
                (
                    index
                    for index, prediction in enumerate(predictions)
                    if index not in matched_predictions
                    and _matches(gold, prediction, mode)
                ),
                None,
            )
            if hit is None:
                bucket.false_negatives += 1
                overall.false_negatives += 1
                if collect_misses:
                    missed.append(
                        (document.doc_id, gold, document.text[gold.start:gold.end])
                    )
            else:
                matched_predictions.add(hit)
                bucket.true_positives += 1
                overall.true_positives += 1

        for index, prediction in enumerate(predictions):
            if index in matched_predictions:
                continue
            per_entity.setdefault(prediction.entity, Score()).false_positives += 1
            overall.false_positives += 1

    return Report(
        mode=mode,
        profile=scrubber.policy.name,
        documents=len(documents),
        overall=overall,
        per_entity=per_entity,
        missed=missed,
    )


def render(report: Report, *, show_missed: int = 0) -> str:
    """A plain-text results table."""
    lines = [
        f"corpus: {report.documents} document(s)   "
        f"profile: {report.profile}   match: {report.mode}",
        "",
        f"{'entity':<18}{'prec':>8}{'recall':>8}{'F1':>8}{'support':>9}",
        "-" * 51,
    ]
    for entity, score in sorted(report.per_entity.items()):
        lines.append(
            f"{entity:<18}{score.precision:>8.3f}{score.recall:>8.3f}"
            f"{score.f1:>8.3f}{score.support:>9}"
        )
    lines += [
        "-" * 51,
        f"{'MICRO':<18}{report.overall.precision:>8.3f}"
        f"{report.overall.recall:>8.3f}{report.overall.f1:>8.3f}"
        f"{report.overall.support:>9}",
        f"{'MACRO F1':<18}{report.macro_f1:>8.3f}",
    ]
    if show_missed and report.missed:
        lines += ["", f"missed ({len(report.missed)} total, showing {show_missed}):"]
        for doc_id, span, text in report.missed[:show_missed]:
            lines.append(f"  {doc_id:<16} {span.entity:<16} {text!r}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# synthetic corpus
# --------------------------------------------------------------------------

_SLOT = re.compile(r"\{\{(?P<entity>[A-Z_0-9]+):(?P<value>[^}]*)\}\}")


def build_document(doc_id: str, template: str) -> Document:
    """Turn a template into a document plus exact gold spans.

    Slots are written ``{{ENTITY:value}}``. Because the annotation is produced
    by the same substitution that produces the text, the offsets are exact by
    construction -- there is no annotator disagreement to account for.
    """
    out: list[str] = []
    spans: list[Span] = []
    cursor = 0
    position = 0
    for match in _SLOT.finditer(template):
        out.append(template[position:match.start()])
        cursor += match.start() - position
        value = match.group("value")
        spans.append(Span(cursor, cursor + len(value), match.group("entity")))
        out.append(value)
        cursor += len(value)
        position = match.end()
    out.append(template[position:])
    return Document(doc_id, "".join(out), spans)


def write_corpus(documents: Iterable[Document], path: Path) -> int:
    """Write documents to a JSONL corpus file. Returns the count."""
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for document in documents:
            handle.write(
                json.dumps(
                    {
                        "id": document.doc_id,
                        "text": document.text,
                        "spans": [
                            {"start": s.start, "end": s.end, "entity": s.entity}
                            for s in document.spans
                        ],
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            count += 1
    return count
