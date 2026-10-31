"""Realistic replacement values, drawn only from reserved ranges.

Clinical de-identification research calls this "hiding in plain sight": replace
a name with another name rather than with a marker. It reads as natural language,
which keeps a model's grammar and coreference intact, and it does not announce to
a reader which parts of the record were touched.

The obvious danger is that a plausible surrogate could *be* somebody. So every
generator here draws from a range that is reserved against real use:

* emails use ``example.org``, reserved by RFC 2606,
* phone numbers use the NANP ``555-01xx`` block, reserved for fiction,
* SSNs use area ``900-999``, which the SSA has never issued,
* cards use the ``4111`` test BIN, with a correct Luhn digit so format checks pass,
* dates are shifted by a constant offset, so intervals between them survive.

Surrogates are deterministic: the same value always yields the same surrogate
under the same key, so "Margaret" stays one person throughout the document.
"""

from __future__ import annotations

import hmac
import random
import re
from collections.abc import Callable
from datetime import date, datetime, timedelta
from hashlib import sha256

from .checksums import luhn
from .detectors.gazetteer import GIVEN_NAMES, SURNAMES

_GIVEN = tuple(sorted(name.capitalize() for name in GIVEN_NAMES))

CITIES = (
    "Fairhaven", "Brookmere", "Ashcroft", "Kingsport", "Riverton", "Westbury",
    "Northfield", "Elmwood", "Glenmoor", "Havenbrook", "Stonebridge", "Lakeport",
)
STREETS = (
    "Alder", "Birchwood", "Cedar Hollow", "Draycott", "Eastgate", "Foxglove",
    "Granary", "Hillcrest", "Ironwood", "Juniper", "Kestrel", "Linden",
)
STREET_TYPES = ("Street", "Avenue", "Road", "Lane", "Drive", "Way", "Court")

#: RFC 2606 reserves these; they can never belong to anyone.
EMAIL_DOMAINS = ("example.com", "example.org", "example.net")

_ISO_AND_TEXTUAL = ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%d %b %Y")
_MONTH_FIRST = ("%m/%d/%Y", "%m-%d-%Y", "%m.%d.%Y", "%m/%d/%y", "%m-%d-%y")
_DAY_FIRST = ("%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%d/%m/%y", "%d-%m-%y")

#: Attempts at a collision-free surrogate before giving up on the value and
#: falling back to a placeholder.
MAX_ATTEMPTS = 16

_NUMERIC_DATE = re.compile(r"(?<!\d)(\d{1,2})[/.\-](\d{1,2})[/.\-](?:\d{4}|\d{2})(?!\d)")


def _date_formats(dayfirst: bool | None) -> tuple[str, ...]:
    """Formats to parse with, in ONE numeric order.

    Trying both orders is what broke date shifting on Indian documents:
    "15-06-2026" parses only day-first while "05-06-2026" parsed month-first,
    so the same document mixed two readings. Intervals came out wrong, and two
    different dates could shift onto the same string, which restore cannot
    tell apart. One order per document keeps the shift a bijection.
    """
    return _ISO_AND_TEXTUAL + (_DAY_FIRST if dayfirst else _MONTH_FIRST)


def infer_dayfirst(text: str) -> bool | None:
    """Decide a document's numeric date order from its unambiguous dates.

    A first field over 12 can only be a day ("15/06/2026"); a second field over
    12 can only be a day in month-first order ("06/15/2026"). The majority
    wins. ``None`` when nothing in the document settles it.
    """
    day_first = month_first = 0
    for match in _NUMERIC_DATE.finditer(text):
        first, second = int(match.group(1)), int(match.group(2))
        if first > 12 >= second:
            day_first += 1
        elif second > 12 >= first:
            month_first += 1
    if day_first == month_first:
        return None
    return day_first > month_first


class Surrogator:
    """Deterministic surrogate generation under a key."""

    def __init__(self, key: bytes) -> None:
        self.key = key
        # One offset for the whole run. Date shifting only preserves the
        # interval between two dates if every date moves by the same amount.
        self._date_shift = timedelta(days=self._int(b"date-shift", 3653) - 1826)

    # -- keyed randomness ------------------------------------------------
    def _digest(self, *parts: bytes) -> bytes:
        return hmac.new(self.key, b"|".join(parts), sha256).digest()

    def _int(self, seed: bytes, modulus: int) -> int:
        return int.from_bytes(self._digest(seed), "big") % modulus

    def _rng(self, entity: str, value: str, attempt: int = 0) -> random.Random:
        normalised = " ".join(value.split()).casefold()
        return random.Random(
            self._digest(entity.encode(), normalised.encode(), str(attempt).encode())
        )

    # -- generators ------------------------------------------------------
    def surrogate(
        self,
        entity: str,
        value: str,
        *,
        avoid: Callable[[str], bool] | None = None,
        dayfirst: bool | None = None,
    ) -> str | None:
        """A replacement for ``value``, or ``None`` if one cannot be produced.

        ``avoid`` rejects candidates that already mean something -- text that
        exists in the document, or a surrogate already standing for a different
        value. A rejected candidate is redrawn deterministically. Dates are not
        redrawn: every date must move by the same offset or intervals break, so
        a colliding date gives up and the caller uses a placeholder.
        """
        if entity == "DATE":
            candidate = self._gen_date(value, dayfirst)
            if candidate is None or (avoid is not None and avoid(candidate)):
                return None
            return candidate

        handler = getattr(self, f"_gen_{entity.lower()}", self._gen_default)
        for attempt in range(MAX_ATTEMPTS):
            candidate = handler(value, self._rng(entity, value, attempt))
            if candidate is not None and not (avoid is not None and avoid(candidate)):
                return candidate
        return None

    def _gen_person(self, value: str, rng: random.Random) -> str:
        # Keep the shape: a single token in, a single token out, and a name
        # printed in capitals stays in capitals.
        tokens = [t for t in value.replace(".", " ").split() if t]
        if len(tokens) <= 1:
            name = rng.choice(_GIVEN)
        else:
            parts = [rng.choice(_GIVEN), rng.choice(SURNAMES)]
            if len(tokens) >= 3:
                parts.insert(1, f"{rng.choice(_GIVEN)[0]}.")
            name = " ".join(parts)
        letters = [c for c in value if c.isalpha()]
        return name.upper() if letters and all(c.isupper() for c in letters) else name

    def _gen_email(self, value: str, rng: random.Random) -> str:
        local = f"{rng.choice(_GIVEN)}.{rng.choice(SURNAMES)}".lower()
        return f"{local}@{rng.choice(EMAIL_DOMAINS)}"

    def _gen_phone(self, value: str, rng: random.Random) -> str:
        # NANP reserves 555-0100 through 555-0199 for fictitious use.
        return f"({rng.randint(200, 989)}) 555-{rng.randint(100, 199):04d}"

    def _gen_ssn(self, value: str, rng: random.Random) -> str:
        # Area numbers 900-999 have never been issued by the SSA.
        return f"{rng.randint(900, 999)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"

    def _gen_credit_card(self, value: str, rng: random.Random) -> str:
        digits = [c for c in value if c.isdigit()]
        body = "4111" + "".join(str(rng.randint(0, 9)) for _ in range(max(len(digits) - 5, 1)))
        number = body + "0"
        for check in range(10):
            if luhn(body + str(check)):
                number = body + str(check)
                break
        return self._reshape(value, number)

    def _gen_date(self, value: str, dayfirst: bool | None = None) -> str | None:
        # Parse and re-emit with the same format, chosen from one numeric
        # order, so the output is written the way the document writes dates.
        text = value.strip()
        for fmt in _date_formats(dayfirst):
            try:
                parsed = datetime.strptime(text, fmt).date()
            except ValueError:
                continue
            return (parsed + self._date_shift).strftime(fmt)
        return None

    def _gen_city(self, value: str, rng: random.Random) -> str:
        return rng.choice(CITIES)

    def _gen_street_address(self, value: str, rng: random.Random) -> str:
        return f"{rng.randint(1, 9999)} {rng.choice(STREETS)} {rng.choice(STREET_TYPES)}"

    def _gen_default(self, value: str, rng: random.Random) -> str:
        """Same shape, different content: digits stay digits, letters stay letters."""
        out = []
        for char in value:
            if char.isdigit():
                out.append(str(rng.randint(0, 9)))
            elif char.isupper():
                out.append(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ"))
            elif char.islower():
                out.append(rng.choice("abcdefghijkmnpqrstuvwxyz"))
            else:
                out.append(char)
        return "".join(out)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _parse_date(value: str, dayfirst: bool | None = None) -> date | None:
        text = value.strip()
        for fmt in _date_formats(dayfirst):
            try:
                return datetime.strptime(text, fmt).date()
            except ValueError:
                continue
        return None

    @staticmethod
    def _reshape(template: str, digits: str) -> str:
        """Lay ``digits`` back into the separators of ``template``."""
        out, index = [], 0
        for char in template:
            if char.isdigit() and index < len(digits):
                out.append(digits[index])
                index += 1
            elif char.isdigit():
                out.append("0")
            else:
                out.append(char)
        return "".join(out)
