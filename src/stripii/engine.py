"""The scrubbing engine: detect, resolve, replace, and reverse."""

from __future__ import annotations

import functools
import gzip
import hmac
import re
import secrets
from collections.abc import Callable, Iterable, Sequence
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import ClassVar

from . import checksums as ck
from . import fpe
from .detectors.base import Recognizer
from .detectors.gazetteer import GIVEN_NAMES, NON_NAME_TERMS, TITLES
from .detectors.identifiers import IdentifierRecognizer
from .detectors.names import NAME_RECOGNIZERS, SpacyNameRecognizer
from .detectors.patterns import ALL_RECOGNIZERS
from .policy import RESTRICTED_ZIP_PREFIXES, Policy
from .surrogates import Surrogator, infer_dayfirst
from .types import Action, Detection, Replacement, ScrubResult
from .vault import Vault

_YEAR = re.compile(r"(?:19|20)\d{2}")
_ALNUM = re.compile(r"[0-9A-Za-z]")
_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")
_TITLES = frozenset(title.lower() for title in TITLES)

#: Shortest value worth propagating to its other occurrences. Below this an
#: exact repeat is as likely to be coincidence -- "837" as a CVV and as part of
#: an amount -- as the same identifier turning up again.
PROPAGATE_MIN_CHARS = 5
#: Name parts are shorter than whole identifiers, and a surname seen once in a
#: full name is exactly what reappears alone later ("Mrs. Whitfield").
NAME_PART_MIN_CHARS = 4
#: MASK keeps a trailing few characters only when at least this share of the
#: value is digits -- cards, accounts and ID numbers, not names or addresses.
MASK_NUMERIC_SHARE = 0.6


def _occurrences(text: str, value: str, entity: str) -> Iterable[tuple[int, int]]:
    """Every whole-token occurrence of ``value`` in ``text``.

    Case-sensitive but tolerant of the three casings a document actually uses
    -- as written, CAPITALS and Title Case -- so a name labelled once as
    "Anaya Raghunathan" is also caught as "ANAYA RAGHUNATHAN" in a header. Plain
    case-insensitivity would also turn "rose" and "mark" into names.

    Values of two or more letter/digit groups -- a full name, an email, a
    formatted number -- are matched case-insensitively: "priya iyer" in lower
    case is still Priya Iyer, and no two-word phrase of ordinary English
    collides with it. On the real documents, 20 lower-case full names survived
    redaction under the case-sensitive rule.
    """
    chunks = re.findall(r"[A-Za-z0-9]+", value)
    if len(chunks) >= 2:
        # Match the value's letter and digit groups with any light separator
        # between them, including none: "9999 999 9999" is also written
        # "9999-999-9999" and "9999999999", a name wraps onto a new line, and
        # OCR puts a stray space into an address. Requiring the exact string
        # left 11 of 644 legible values unredacted on the real documents.
        body = rf"{SEPARATOR}".join(re.escape(c) for c in chunks)
        pattern = re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE)
    else:
        variants = list(dict.fromkeys([value, value.upper(), value.title()]))
        alternation = "|".join(re.escape(v) for v in variants)
        flags = re.IGNORECASE if entity == "EMAIL" else 0
        pattern = re.compile(rf"(?<![A-Za-z0-9])(?:{alternation})(?![A-Za-z0-9])", flags)
    for match in pattern.finditer(text):
        yield match.span()


#: What may sit between the letter/digit groups of a propagated value. Never a
#: table cell boundary -- " | " is three characters and a value must not swallow
#: the grid -- and never a line break, which would join two lines into one. A
#: name wrapped across lines is still covered: each of its parts propagates.
SEPARATOR = r"[^A-Za-z0-9|\r\n]{0,3}"


#: A name's parts glued together must add up to at least this many letters
#: before they count. Short combinations collide with ordinary words.
CONCATENATION_MIN_CHARS = 8


def _concatenations(
    text: str, raw: str, searched: set[tuple[str, str]]
) -> Iterable[tuple[int, int]]:
    """A detected name written without spaces: "ANAYARAGHUNATHAN", "RaghunathanAnaya".

    UPI and NEFT narrations in bank statements, and many invoice systems, drop
    the spaces from names. On the real statements that left the account
    holder's name readable in the narration column after it had been redacted
    everywhere else. Any run of two or more of the name's parts, in any order,
    counts; case is ignored, because the combined length makes an accidental
    match with an ordinary word vanishingly unlikely.
    """
    parts = sorted(
        {p for p in re.findall(r"[A-Za-z]{3,}", raw) if p.lower() not in _TITLES},
        key=len,
        reverse=True,
    )
    if len(parts) < 2:
        return
    key = ("PERSON+", "|".join(sorted(p.casefold() for p in parts)))
    if key in searched:
        return
    searched.add(key)
    alternation = "|".join(re.escape(p) for p in parts)
    pattern = re.compile(rf"(?<![A-Za-z])(?:{alternation}){{2,}}(?![A-Za-z])", re.IGNORECASE)
    for match in pattern.finditer(text):
        if len(match.group(0)) >= CONCATENATION_MIN_CHARS:
            yield match.span()


#: Name detectors whose cue -- a label, a title, a credential, a relationship
#: word -- is evidence enough that a one-word value is a name.
_TRUSTED_NAME_DETECTORS = frozenset(
    {"person_labelled", "person_titled", "person_credentialled", "person_relative", "identifier"}
)

#: The bundled list, and the system lists as a fallback should it be missing.
_BUNDLED_WORDS = Path(__file__).resolve().parent / "data" / "words.txt.gz"
_WORD_LISTS = ("/usr/share/dict/words", "/usr/dict/words")


@functools.lru_cache(maxsize=1)
def _english_words() -> frozenset[str]:
    """Lower-case English words, from the list bundled with the package.

    Proper nouns are capitalised in dictionary word lists, so keeping only
    lower-case entries keeps "rose" and "mark" while dropping "Rose" and
    "Mark". The list is bundled (see ``data/README.md``) so that a name part
    propagates or not the same way on every operating system; before that,
    Linux boxes without a word list over-redacted and macOS did not. Should
    the bundled file be missing, the system list is tried, and with nothing
    at all every name part propagates -- the tool then over-redacts rather
    than leaks.
    """
    try:
        with gzip.open(_BUNDLED_WORDS, "rt", encoding="utf-8") as handle:
            return frozenset(w.strip() for w in handle if w.strip().islower())
    except OSError:
        pass
    for path in _WORD_LISTS:
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                return frozenset(w.strip() for w in handle if w.strip().islower())
        except OSError:
            continue
    return frozenset()


def _common_word_here(text: str, word: str) -> bool:
    """Whether ``word`` is an English word that this document uses as one.

    Both conditions are needed. A false-positive "Name: Test Case" swept up
    ordinary words and propagation spread them across a whole document --
    174 times in one real file -- so words the document itself uses in lower
    case must not spread. But a chat export writes real names in lower case
    too, and that alone stopped three real surnames spreading. The difference
    is that "test" is an English word and a surname usually is not.
    """
    lowered = word.lower()
    if lowered == word or lowered not in _english_words():
        return False
    # Only prose counts, not emails, handles or URLs.
    prose = re.search(
        rf"(?<![A-Za-z0-9@._/\-]){re.escape(lowered)}(?![A-Za-z0-9@_/\-]|\.[A-Za-z])", text
    )
    return prose is not None


#: A surname must be at least this long to be looked for inside other tokens.
DISTINCTIVE_PART_MIN_CHARS = 5


def _tokens_containing_surname(
    text: str, raw: str, searched: set[tuple[str, str]]
) -> Iterable[tuple[int, int]]:
    """Whole tokens that contain a distinctive part of a detected full name.

    A user handle ("anayaraghunathan"), an email-like account id, or a payee
    token in a narration ("UPI/VIKRAMRAGHUNATHAN") carries the surname inside a
    longer word, where whole-token matching cannot see it. Only parts of a
    multi-word name qualify, only if they are at least five letters, and only
    if they are not common given names -- "Kumar" or "Mark" inside another
    word says nothing, while "Raghunathan" inside one says a great deal.
    """
    words = raw.split()
    if len(words) < 2:
        return
    for part in re.findall(r"[A-Za-z]+", raw):
        folded = part.casefold()
        if (
            len(part) < DISTINCTIVE_PART_MIN_CHARS
            or folded in GIVEN_NAMES
            or folded in NON_NAME_TERMS
            or ("PERSON~", folded) in searched
            or _common_word_here(text, part)
        ):
            continue
        searched.add(("PERSON~", folded))
        pattern = re.compile(
            rf"[A-Za-z0-9._-]*{re.escape(part)}[A-Za-z0-9._-]*", re.IGNORECASE
        )
        for match in pattern.finditer(text):
            start, end = match.span()
            # Trim the punctuation a token-ish run can pick up at its edges.
            while start < end and text[start] in "._-":
                start += 1
            while end > start and text[end - 1] in "._-":
                end -= 1
            token = text[start:end]
            if token.casefold() == folded:
                continue
            # A plain lower-case or Title-case word is prose ("patella" is not
            # Dr. Patel). Handles and payee tokens give themselves away with
            # digits, dots, capitals or CamelCase; a first name glued to the
            # surname in lower case is caught by _concatenations instead.
            if token.isalpha() and (token.islower() or token.istitle()):
                continue
            yield start, end


#: Candidate glued names: CAPITALS, CamelCase, or one Title-case word
#: ("RAJESHKUMAR", "RajeshKumar", "Rajeshkumar" -- all three turn up).
_GLUED_TOKEN = re.compile(
    r"(?<![A-Za-z])(?:[A-Z]{8,}|[A-Z][a-z]{7,}|[A-Z][a-z]+(?:[A-Z][a-z]+)+)(?![A-Za-z])"
)


def _glued_names(text: str, known_parts: set[str]) -> Iterable[tuple[int, int]]:
    """Capitalised tokens that split entirely into name parts.

    Only runs once a document has at least one detected person, and a part must
    be either a given name or a part of a name already found in this document.
    "RAJESHKUMAR" splits into two names; "MARKETING" splits into "mark" and
    "eting", and is left alone. Lower-case tokens are skipped: payment systems
    write names in capitals or capitalised, and ordinary prose is lower case.
    """
    vocabulary = {p for p in known_parts | GIVEN_NAMES if len(p) >= 3}
    by_length = sorted(vocabulary, key=len, reverse=True)

    def splits(token: str) -> bool:
        # DP over prefixes: parts[i] is how many name parts token[:i] splits
        # into (capped at 2, which is all the answer needs), 0 if it cannot.
        parts = [0] * (len(token) + 1)
        reachable = [False] * (len(token) + 1)
        reachable[0] = True
        for i in range(len(token)):
            if not reachable[i]:
                continue
            for part in by_length:
                if token.startswith(part, i):
                    j = i + len(part)
                    reachable[j] = True
                    parts[j] = max(parts[j], min(parts[i] + 1, 2))
        if reachable[len(token)] and parts[len(token)] >= 2:
            return True
        # A surname nobody has written separately: two known parts, then an
        # unknown tail ("RAJESH" + "KUMAR" + "SHARMA"). One known part is not
        # enough -- "MARY" + "LAND" and "JACK" + "SONVILLE" are places.
        return any(
            reachable[i] and parts[i] >= 2 and len(token) - i >= 3
            for i in range(len(token))
        )

    for match in _GLUED_TOKEN.finditer(text):
        token = match.group(0).casefold()
        if len(token) >= CONCATENATION_MIN_CHARS and token not in NON_NAME_TERMS and splits(token):
            yield match.span()


def _is_numeric_identifier(detection: Detection) -> bool:
    """Whether format-preserving encryption keeps this value meaningful."""
    body = _NON_ALNUM.sub("", detection.raw)
    return bool(body) and body.isdigit()


def default_recognizers(
    *,
    ner: bool = False,
    ner_model: str = "en_core_web_sm",
    identifiers: Sequence[str] | None = None,
) -> list[Recognizer]:
    """The standard detector set, optionally with the spaCy NER backend.

    ``identifiers`` are the user's own values (their name, family, account
    numbers): always found, whatever the context, see ``detectors.identifiers``.
    """
    recognizers: list[Recognizer] = [*ALL_RECOGNIZERS, *NAME_RECOGNIZERS]
    if identifiers:
        recognizers.append(IdentifierRecognizer(identifiers))
    if ner:
        recognizers.append(SpacyNameRecognizer(ner_model))
    return recognizers


def resolve_overlaps(detections: Iterable[Detection]) -> list[Detection]:
    """Pick a non-overlapping set, preferring confident then longer matches.

    Two detectors firing on the same span is the normal case, not an error:
    ``Dr. Robert Chen`` is found by the title pattern and by the anchored-name
    scan, and an email inside a URL is found by both. Resolving by confidence
    first means the specific detector wins over the generic one.
    """
    ordered = sorted(
        detections,
        key=lambda d: (-d.score, -(d.end - d.start), d.start, d.entity),
    )
    kept: list[Detection] = []
    for candidate in ordered:
        if any(candidate.overlaps(k) for k in kept):
            continue
        kept.append(candidate)
    kept.sort(key=lambda d: d.start)
    return kept


class Scrubber:
    """Applies a :class:`Policy` to text."""

    def __init__(
        self,
        policy: Policy,
        recognizers: Sequence[Recognizer] | None = None,
        *,
        hash_key: bytes | None = None,
    ) -> None:
        self.policy = policy
        self.recognizers = list(recognizers) if recognizers is not None else default_recognizers()
        # Keyed so that a digest of a known-format identifier (an SSN has only
        # 10^9 possibilities) cannot simply be looked up in a rainbow table.
        self.hash_key = hash_key or secrets.token_bytes(32)
        # Derived rather than reused, so a leaked digest says nothing about the
        # FPE key and vice versa.
        self._surrogator = Surrogator(self._derive(b"surrogate"))
        self._fpe_key = self._derive(b"fpe")

    def _derive(self, label: bytes) -> bytes:
        return hmac.new(self.hash_key, label, sha256).digest()

    # -- detection -------------------------------------------------------
    def scan(self, text: str) -> list[Detection]:
        """Every candidate, before policy is applied. Useful for dry runs."""
        found: list[Detection] = []
        for recognizer in self.recognizers:
            found.extend(recognizer.detect(text))
        return sorted(found, key=lambda d: (d.start, -d.score))

    # -- scrubbing -------------------------------------------------------
    def scrub(
        self,
        text: str,
        vault: Vault | None = None,
        *,
        context_hint: str | None = None,
    ) -> tuple[ScrubResult, Vault]:
        """Return the redacted text plus the vault needed to reverse it.

        ``context_hint`` supplies the label a fragment was found under, for
        callers that scrub values in isolation. A CSV cell reading ``483920175``
        is just a number; the same cell under an ``account_number`` header is an
        account number. The hint is prepended for detection only and never
        appears in the output.
        """
        vault = vault if vault is not None else Vault()
        chosen, skipped = self.plan(text, context_hint=context_hint)
        dayfirst = infer_dayfirst(text)

        pieces: list[str] = []
        replacements: list[Replacement] = []
        cursor = 0
        for detection in chosen:
            requested = self.policy.action_for(detection.entity)
            replacement_text, applied = self._apply(detection, requested, vault, text, dayfirst)
            pieces.append(text[cursor:detection.start])
            pieces.append(replacement_text)
            cursor = detection.end
            # The action actually applied, not the one requested: ENCRYPT on a
            # name becomes a surrogate, and a value too short to encipher falls
            # back to a placeholder. Reports and audits must say what happened.
            replacements.append(Replacement(detection, applied, replacement_text))
        pieces.append(text[cursor:])

        result = ScrubResult(
            text="".join(pieces),
            replacements=replacements,
            skipped=skipped,
        )
        return result, vault

    def plan(
        self, text: str, *, context_hint: str | None = None
    ) -> tuple[list[Detection], list[Detection]]:
        """Exactly the spans ``scrub`` will replace, and those it will not.

        The single source of truth for "what does the tool emit". The benchmark
        scores this rather than re-deriving it, because re-deriving it already
        drifted once: the scorer used ``scan`` plus overlap resolution, missed
        the propagation step, and under-reported recall on repeated values.
        """
        eligible, skipped = [], []
        for detection in self._scan_with_hint(text, context_hint):
            action = self.policy.action_for(detection.entity)
            if action is Action.KEEP or detection.score < self.policy.min_score:
                skipped.append(detection)
            else:
                eligible.append(detection)
        return self._propagate(text, resolve_overlaps(eligible)), skipped

    def _scan_with_hint(self, text: str, hint: str | None) -> list[Detection]:
        """Scan ``text`` as though ``hint`` labelled it, then map offsets back."""
        if not hint:
            return self.scan(text)
        # Underscores and dashes are how field names are written; the context
        # keywords are written as words.
        label = hint.replace("_", " ").replace("-", " ").strip()
        if not label:
            return self.scan(text)
        prefix = f"{label}: "
        offset = len(prefix)
        shifted = []
        for detection in self.scan(prefix + text):
            if detection.start < offset:
                # Started inside the synthetic prefix: not part of the value.
                continue
            shifted.append(
                replace(detection, start=detection.start - offset, end=detection.end - offset)
            )
        return shifted

    # -- propagation ---------------------------------------------------------
    def _propagate(self, text: str, chosen: list[Detection]) -> list[Detection]:
        """Replace every occurrence of a detected value, not just the one found.

        Context-gated detectors only fire where the cue is: an account number
        is found beside "Account No:" in a statement's header and missed where
        it recurs, unlabelled, in the body. On the first run against real
        documents that left 78 values redacted in one place and readable in
        another -- which leaks exactly as much as not redacting at all.

        For names, each part is propagated too: a document that says "Margaret
        Whitfield" once and "Mrs. Whitfield" thereafter only labels the first.
        So is the name written without spaces, as payment narrations write it.
        """
        current = list(chosen)
        searched: set[tuple[str, str]] = set()

        def claim(start: int, end: int, detection: Detection) -> None:
            """Add a propagated span if it fits.

            It may swallow smaller detections of the same entity lying wholly
            inside it -- in "RaghunathanAnaya" the name scan finds "Anaya" on its
            own, and refusing the longer span because of that would leave
            "Raghunathan" readable. Any other overlap means the span is already
            accounted for, and it is dropped.
            """
            overlapping = [d for d in current if start < d.end and d.start < end]
            if any(
                d.entity != detection.entity or d.start < start or d.end > end
                for d in overlapping
            ):
                return
            if len(overlapping) == 1 and (overlapping[0].start, overlapping[0].end) == (start, end):
                return
            for d in overlapping:
                current.remove(d)
            current.append(
                replace(
                    detection,
                    start=start,
                    end=end,
                    raw=text[start:end],
                    detector="propagated",
                    meta={"from": detection.detector},
                )
            )

        for detection in chosen:
            raw = detection.raw.strip()
            person = detection.entity == "PERSON"
            values = []
            # A one-word name from a label or a title ("Name: Hunter",
            # "Mr. Hunter") spreads even if it is also an English word: the cue
            # says it is a name, and a visible name is a leak while a redacted
            # word is only untidy. Low-confidence one-word names -- found only
            # because they are on the given-name list -- do not.
            trusted = detection.detector in _TRUSTED_NAME_DETECTORS
            if len(_NON_ALNUM.sub("", raw)) >= PROPAGATE_MIN_CHARS and not (
                person and " " not in raw and not trusted and _common_word_here(text, raw)
            ):
                values.append(raw)
            if person and " " in raw:
                for part in raw.split():
                    core = part.strip(".,")
                    if (
                        len(core) >= NAME_PART_MIN_CHARS
                        and core.lower() not in NON_NAME_TERMS
                        and core.lower() not in _TITLES
                        and not _common_word_here(text, core)
                    ):
                        values.append(core)
            spans = []
            for value in values:
                key = (detection.entity, value.casefold())
                if key in searched:
                    continue
                searched.add(key)
                spans.extend(_occurrences(text, value, detection.entity))
            if detection.entity == "PERSON":
                spans.extend(_concatenations(text, raw, searched))
                spans.extend(_tokens_containing_surname(text, raw, searched))
            for start, end in spans:
                claim(start, end, detection)

        # Names glued together from parts of *different* people -- a payee
        # "RAJESHKUMAR" in a UPI narration, never written any other way.
        known = {
            p.casefold()
            for d in current
            if d.entity == "PERSON"
            for p in re.findall(r"[A-Za-z]{3,}", d.raw)
            if not _common_word_here(text, p)
        }
        template = next((d for d in current if d.entity == "PERSON"), None)
        if template is not None:
            for start, end in _glued_names(text, known):
                claim(start, end, replace(template, score=0.6, detector="glued_name"))
        return sorted(current, key=lambda d: d.start)

    def _apply(
        self,
        detection: Detection,
        action: Action,
        vault: Vault,
        text: str = "",
        dayfirst: bool | None = None,
    ) -> tuple[str, Action]:
        """Replace one detection. Returns the text and the action actually used."""
        if action is Action.ENCRYPT and not _is_numeric_identifier(detection):
            # FF1 over a name or an address produces "XX9XXX": unreadable, and
            # letters turn into digits, so it no longer even looks like a name.
            # Format-preserving encryption is for numeric identifiers; anything
            # else gets a surrogate, which keeps its shape and stays reversible
            # through the vault.
            action = Action.SURROGATE
        if action is Action.REDACT:
            return vault.placeholder_for(
                detection.entity, detection.raw, self.policy.placeholder
            ), Action.REDACT
        if action is Action.MASK:
            # Deliberately not recorded in the vault: "****1111" is not unique,
            # so restoring it would rewrite every card ending in 1111 to this
            # one. MASK and GENERALIZE are one-way by design.
            return self._mask(detection.raw), Action.MASK
        if action is Action.SURROGATE:
            def unavailable(candidate: str) -> bool:
                # A surrogate must not already mean something else. If it is
                # text that exists in the document, restoring a reply would
                # rewrite that real text; if it already stands for a different
                # value, restore can only give one of them back.
                owner = vault.mapping.get(candidate)
                if owner is not None:
                    return owner.strip().casefold() != detection.raw.strip().casefold()
                return candidate in text

            surrogate = self._surrogator.surrogate(
                detection.entity, detection.raw, avoid=unavailable, dayfirst=dayfirst
            )
            if surrogate is None:
                return vault.placeholder_for(
                    detection.entity, detection.raw, self.policy.placeholder
                ), Action.REDACT
            # Recorded, so a surrogate run is still reversible through the vault.
            vault.record(surrogate, detection.raw)
            return surrogate, Action.SURROGATE
        if action is Action.HASH:
            digest = hmac.new(
                self.hash_key, detection.raw.strip().casefold().encode(), sha256
            ).hexdigest()[:10]
            token = f"[[{detection.entity}:{digest}]]"
            vault.record(token, detection.raw)
            return token, Action.HASH
        if action is Action.ENCRYPT:
            encrypted = self._encrypt(detection.raw, detection.entity)
            if encrypted is None:
                return vault.placeholder_for(
                    detection.entity, detection.raw, self.policy.placeholder
                ), Action.REDACT
            # Recorded so `restore` works the same way for every style. FF1 is
            # invertible under the key alone, but the vault keeps one reversal
            # path rather than two.
            vault.record(encrypted, detection.raw)
            return encrypted, Action.ENCRYPT
        if action is Action.GENERALIZE:
            generalized = self._generalize(detection)
            if generalized is None:
                # Nothing sensible to coarsen to (a date with no year, say):
                # fall back to full redaction rather than leaving it in place.
                return vault.placeholder_for(
                    detection.entity, detection.raw, self.policy.placeholder
                ), Action.REDACT
            return generalized, Action.GENERALIZE  # one-way, see MASK above
        return detection.raw, Action.KEEP

    #: Entities whose last digit is a check digit that FPE would invalidate.
    #: Mapping is entity -> function from the enciphered body to its check digit.
    CHECKSUM_PRESERVING: ClassVar[dict[str, Callable[[str], str]]] = {
        "CREDIT_CARD": ck.luhn_check_digit,
        "US_ROUTING": ck.aba_check_digit,
        "AADHAAR": ck.verhoeff_check_digit,
    }

    def _encrypt(self, raw: str, entity: str = "") -> str | None:
        """Format-preserving encryption over the alphanumerics, separators kept.

        Returns ``None`` when the value cannot be enciphered in place -- too few
        characters for SP 800-38G's minimum domain, or no working cipher backend
        -- so the caller can fall back to a placeholder rather than leaving the
        original in the document.
        """
        body = [c for c in raw if c.isalnum()]
        if not body:
            return None
        if all(c.isdigit() for c in body):
            alphabet, text = fpe.DIGITS, "".join(body)
        else:
            alphabet, text = fpe.ALNUM_UPPER, "".join(body).upper()

        check_digit = self.CHECKSUM_PRESERVING.get(entity) if alphabet is fpe.DIGITS else None
        try:
            if check_digit is not None:
                # Encipher everything but the check digit, then recompute it, so
                # the result still validates. Still reversible: the body is
                # bijective under FF1 and the check digit follows from the body.
                ciphered = fpe.encrypt(self._fpe_key, text[:-1], alphabet=alphabet)
                ciphered += check_digit(ciphered)
            else:
                ciphered = fpe.encrypt(self._fpe_key, text, alphabet=alphabet)
        except (fpe.FPEError, ValueError):
            return None
        out, index = [], 0
        for char in raw:
            if char.isalnum():
                out.append(ciphered[index])
                index += 1
            else:
                out.append(char)
        return "".join(out)

    def _mask(self, raw: str) -> str:
        """Star out every alphanumeric except the trailing ``mask_keep``.

        The trailing characters are kept only for identifiers that are mostly
        digits. "**** **** **** 1111" is the convention for a card, and the last
        four digits of an Aadhaar number are exactly what UIDAI's own masked
        Aadhaar shows. The last four letters of a surname or a city are not a
        convention; they are a partial leak ("******** ****field").
        """
        positions = [m.start() for m in _ALNUM.finditer(raw)]
        digits = sum(1 for index in positions if raw[index].isdigit())
        numeric = bool(positions) and digits / len(positions) >= MASK_NUMERIC_SHARE
        keep = self.policy.mask_keep if numeric else 0
        if len(positions) <= keep:
            return "*" * len(raw)
        cutoff = positions[-keep] if keep else len(raw)
        chars = list(raw)
        for index in positions:
            if index < cutoff:
                chars[index] = "*"
        return "".join(chars)

    def _generalize(self, detection: Detection) -> str | None:
        """Coarsen a quasi-identifier, or ``None`` to fall back to a placeholder."""
        entity, raw = detection.entity, detection.raw
        if entity == "DATE":
            year = _YEAR.search(raw)
            return year.group(0) if year else None
        if entity == "AGE_OVER_89":
            return "90+"
        if entity == "US_ZIP":
            prefix = raw[:3]
            if not prefix.isdigit():
                return None
            # HIPAA: sparsely populated prefixes are identifying on their own.
            return "000**" if prefix in RESTRICTED_ZIP_PREFIXES else f"{prefix}**"
        if entity == "IN_PINCODE":
            return f"{raw[:3]}***" if raw[:3].isdigit() else None
        if entity == "UK_POSTCODE":
            outward = raw.strip().split()
            if len(outward) == 2:
                return f"{outward[0]} ***"
            return f"{raw[:-3].strip()} ***" if len(raw) > 4 else None
        return None

    # -- reversal --------------------------------------------------------
    @staticmethod
    def restore(text: str, vault: Vault) -> str:
        """Put the original values back, e.g. into a model's reply.

        A single pass over the text, trying the longest key first at each
        position. Sequential ``str.replace`` calls would let one restored value
        be rewritten by the next replacement when it happens to contain another
        key -- a surrogate name inside a restored address, say -- and would let
        ``[[PERSON_1]]`` match inside ``[[PERSON_11]]``.
        """
        if not vault.mapping:
            return text
        keys = sorted(vault.mapping, key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(key) for key in keys))
        return pattern.sub(lambda match: vault.mapping[match.group(0)], text)
