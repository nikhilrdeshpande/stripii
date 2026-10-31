"""Policies: which entities matter, and what should happen to each one.

The interesting decisions in a redaction tool are not "can you find an SSN" but
"what do you do with a date". Stripping every date out of a lab report makes the
trend meaningless; leaving dates in a record that HIPAA governs is a violation.
So the action per entity is data, not code, and it ships as named profiles.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .types import Action

DEFAULT_PLACEHOLDER = "[[{entity}_{n}]]"

#: Three-digit ZIP prefixes whose population is at or below 20,000. HIPAA Safe
#: Harbor requires these to be reported as 000 rather than truncated, because
#: the prefix alone is identifying (45 CFR 164.514(b)(2)(i)(B), per the HHS
#: de-identification guidance).
RESTRICTED_ZIP_PREFIXES: frozenset[str] = frozenset(
    {
        "036", "059", "063", "102", "203", "556", "692", "790",
        "821", "823", "830", "831", "878", "879", "884", "890", "893",
    }
)


@dataclass
class Policy:
    """A named set of redaction decisions."""

    name: str
    description: str = ""
    #: What to do with an entity that has no explicit rule.
    default_action: Action = Action.REDACT
    #: entity -> action
    actions: dict[str, Action] = field(default_factory=dict)
    #: Detections scoring below this are reported but not replaced.
    min_score: float = 0.5
    #: Entities to ignore entirely. Takes precedence over ``actions``.
    disabled: frozenset[str] = frozenset()
    #: Placeholder template; ``{entity}`` and ``{n}`` are substituted.
    placeholder: str = DEFAULT_PLACEHOLDER
    #: Characters of the original to keep when the action is MASK.
    mask_keep: int = 4

    def action_for(self, entity: str) -> Action:
        if entity in self.disabled:
            return Action.KEEP
        return self.actions.get(entity, self.default_action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "default_action": self.default_action.value,
            "min_score": self.min_score,
            "placeholder": self.placeholder,
            "mask_keep": self.mask_keep,
            "disabled": sorted(self.disabled),
            "actions": {k: v.value for k, v in sorted(self.actions.items())},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, base: Policy | None = None) -> Policy:
        """Build a policy, optionally layering ``data`` over an existing one."""
        start = base or cls(name=str(data.get("name", "custom")))
        actions = dict(start.actions)
        for entity, action in (data.get("actions") or {}).items():
            actions[entity.upper()] = Action(action)
        return cls(
            name=str(data.get("name", start.name)),
            description=str(data.get("description", start.description)),
            default_action=Action(data.get("default_action", start.default_action.value)),
            actions=actions,
            min_score=float(data.get("min_score", start.min_score)),
            disabled=frozenset(
                e.upper() for e in data.get("disabled", sorted(start.disabled))
            ),
            placeholder=str(data.get("placeholder", start.placeholder)),
            mask_keep=int(data.get("mask_keep", start.mask_keep)),
        )

    @classmethod
    def load(cls, path: str | Path, *, base: Policy | None = None) -> Policy:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if "extends" in data and base is None:
            base = get_profile(str(data["extends"]))
        return cls.from_dict(data, base=base)


# --------------------------------------------------------------------------
# built-in profiles
# --------------------------------------------------------------------------

_SECRET_ENTITIES = ("PRIVATE_KEY", "AWS_ACCESS_KEY", "API_TOKEN", "JWT")

DEFAULT = Policy(
    name="default",
    description="Balanced general-purpose redaction for pasting into an AI tool.",
    default_action=Action.REDACT,
    actions={
        # Dates and links usually carry the meaning of the document; the
        # health profile is the one that has to be strict about them.
        "DATE": Action.KEEP,
        "URL": Action.KEEP,
        "CARD_EXPIRY": Action.REDACT,
        "CREDIT_CARD": Action.MASK,
        "BANK_ACCOUNT": Action.MASK,
        "US_ZIP": Action.GENERALIZE,
        "UK_POSTCODE": Action.GENERALIZE,
        "IN_PINCODE": Action.GENERALIZE,
        "AGE_OVER_89": Action.GENERALIZE,
    },
    min_score=0.5,
)

HEALTH = Policy(
    name="health",
    description=(
        "HIPAA Safe Harbor (45 CFR 164.514(b)(2)): removes all 18 identifier "
        "classes, generalises dates to the year, ages over 89, and ZIP codes to "
        "the first three digits (000 for sparsely populated prefixes)."
    ),
    default_action=Action.REDACT,
    actions={
        "DATE": Action.GENERALIZE,
        "AGE_OVER_89": Action.GENERALIZE,
        "US_ZIP": Action.GENERALIZE,
        "UK_POSTCODE": Action.GENERALIZE,
        "IN_PINCODE": Action.GENERALIZE,
        "URL": Action.REDACT,
        "CREDIT_CARD": Action.REDACT,
        "BANK_ACCOUNT": Action.REDACT,
    },
    # Health records are the case where a missed identifier is most costly, so
    # weak-but-plausible matches are acted on rather than merely reported.
    min_score=0.4,
)

FINANCE = Policy(
    name="finance",
    description=(
        "Financial statements: identity and account numbers go, transaction "
        "dates and amounts stay so the document remains analysable."
    ),
    default_action=Action.REDACT,
    actions={
        "DATE": Action.KEEP,
        "URL": Action.KEEP,
        "CREDIT_CARD": Action.MASK,
        "BANK_ACCOUNT": Action.MASK,
        "US_ROUTING": Action.REDACT,
        "IBAN": Action.MASK,
        "US_ZIP": Action.GENERALIZE,
        "AGE_OVER_89": Action.GENERALIZE,
    },
    min_score=0.45,
)

PARANOID = Policy(
    name="paranoid",
    description="Redacts everything detectable, including low-confidence matches.",
    default_action=Action.REDACT,
    actions={"DATE": Action.GENERALIZE, "AGE_OVER_89": Action.GENERALIZE},
    min_score=0.3,
)

SECRETS = Policy(
    name="secrets",
    description="Credentials only: a fast pre-paste or pre-commit check.",
    default_action=Action.KEEP,
    actions=dict.fromkeys(_SECRET_ENTITIES, Action.REDACT),
    min_score=0.5,
)

TOKENIZED = Policy(
    name="tokenized",
    description=(
        "Everything keeps its shape: identifiers are format-preserving "
        "encrypted, names and places get realistic surrogates, dates are "
        "shifted by a constant offset. For pipelines that validate what they "
        "receive, where [[PERSON_1]] would simply be rejected."
    ),
    default_action=Action.REDACT,
    actions={
        # Format-preserving: a card stays a valid card, reversible under the key.
        "CREDIT_CARD": Action.ENCRYPT,
        "BANK_ACCOUNT": Action.ENCRYPT,
        "US_ROUTING": Action.ENCRYPT,
        "MRN": Action.ENCRYPT,
        "HEALTH_PLAN_ID": Action.ENCRYPT,
        "NHS_NUMBER": Action.ENCRYPT,
        "AADHAAR": Action.ENCRYPT,
        # Surrogates: readable as language, drawn from reserved ranges.
        "PERSON": Action.SURROGATE,
        "EMAIL": Action.SURROGATE,
        "PHONE": Action.SURROGATE,
        "SSN": Action.SURROGATE,
        "STREET_ADDRESS": Action.SURROGATE,
        "CITY": Action.SURROGATE,
        "DATE": Action.SURROGATE,
        "US_ZIP": Action.GENERALIZE,
        "AGE_OVER_89": Action.GENERALIZE,
    },
    min_score=0.45,
)

PROFILES: dict[str, Policy] = {
    p.name: p for p in (DEFAULT, HEALTH, FINANCE, PARANOID, SECRETS, TOKENIZED)
}


def get_profile(name: str) -> Policy:
    try:
        return PROFILES[name.lower()]
    except KeyError:
        raise KeyError(
            f"unknown profile {name!r}; available: {', '.join(sorted(PROFILES))}"
        ) from None
