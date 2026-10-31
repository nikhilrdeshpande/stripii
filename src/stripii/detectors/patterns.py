"""The entity catalogue.

Coverage is organised around the rules that actually govern this data:

* **HIPAA Safe Harbor** (45 CFR 164.514(b)(2)) enumerates 18 identifier classes
  that must come out of a health record before it stops being PHI. Each one has
  an entity here, including the two people usually forget: ages over 89, and ZIP
  codes narrower than the first three digits.
* **PCI DSS** treats the PAN, and anything that could authenticate a card, as
  data you do not paste anywhere. Hence CARD, CVV and expiry.
* Everything under "secrets" exists because the most common accident when
  pasting a config file or a log into a chat window is not a name -- it is a key.

Clinical codes (ICD-10, CPT, LOINC), lab values, units and drug names are
deliberately *not* entities. Stripping them would destroy the reason someone
wanted a model to read the report, and none of them identify a person.
"""

from __future__ import annotations

import re

from .. import checksums as ck
from .base import PatternRecognizer

# --------------------------------------------------------------------------
# contact and identity
# --------------------------------------------------------------------------

EMAIL = PatternRecognizer(
    "EMAIL",
    [r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b"],
    score=0.95,
)

PHONE = PatternRecognizer(
    "PHONE",
    [
        # North American, separators required so bare 10-digit blobs do not match
        r"(?<![\d-])(?:\+?1[ .\-]?)?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-])\d{3}[ .\-]\d{4}(?![\d-])",
        # India, 10 digits starting 6-9, with an explicit country code.
        # The 5+5 grouping ("+91 98765 43210") is how they are actually written.
        r"(?<![\d-])\+91[ .\-]?[6-9]\d{4}[ .\-]?\d{5}(?![\d-])",
        # generic E.164
        r"(?<![\d-])\+(?:[2-9]\d{0,2})[ .\-]?\d{6,12}(?![\d-])",
    ],
    score=0.7,
    context=["phone", "tel", "telephone", "mobile", "cell", "fax", "contact", "call"],
)

#: An Indian mobile written without "+91" -- "Mobile: 9820123456" -- is the
#: usual form on Indian forms and statements, and matched none of the
#: patterns above. Ten digits starting 6-9, in the groupings actually printed,
#: counted only beside a phone cue.
PHONE_IN_BARE = PatternRecognizer(
    "PHONE",
    [
        r"(?<![\w-])[6-9]\d{9}(?![\w-])",
        r"(?<![\w-])[6-9]\d{4}[ -]\d{5}(?![\w-])",
        r"(?<![\w-])[6-9]\d{2}[ -]\d{3}[ -]\d{4}(?![\w-])",
    ],
    name="phone_in_bare",
    score=0.6,
    context=["mobile", "mob", "phone", "ph", "tel", "contact", "whatsapp", "call", "cell"],
    requires_context=True,
)

URL = PatternRecognizer(
    "URL",
    [r"\bhttps?://[^\s<>\"')\]]+"],
    score=0.6,
)

IP_ADDRESS = PatternRecognizer(
    "IP_ADDRESS",
    [
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])",
        r"(?<![:\w])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![:\w])",
    ],
    score=0.75,
    deny=[r"0\.0\.0\.0", r"127\.0\.0\.1", r"255\.255\.255\.\d+", r"(?:\d+\.){3}0"],
)

MAC_ADDRESS = PatternRecognizer(
    "MAC_ADDRESS",
    [r"(?<![\w:])(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}(?![\w:])"],
    score=0.8,
)

# --------------------------------------------------------------------------
# government identifiers
# --------------------------------------------------------------------------

SSN = PatternRecognizer(
    "SSN",
    [
        r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])",
        r"(?<![\w-])\d{3} \d{2} \d{4}(?![\w-])",
    ],
    score=0.85,
    validator=ck.ssn_structurally_valid,
    context=["ssn", "social security", "soc sec", "ss#", "tin", "taxpayer"],
)

SSN_BARE = PatternRecognizer(
    "SSN",
    [r"(?<![\w-])\d{9}(?![\w-])"],
    name="ssn_bare",
    score=0.45,
    validator=ck.ssn_structurally_valid,
    context=["ssn", "social security", "soc sec", "ss#"],
    requires_context=True,
)

EIN = PatternRecognizer(
    "EIN",
    [r"(?<![\w-])\d{2}-\d{7}(?![\w-])"],
    score=0.5,
    context=["ein", "employer identification", "federal tax", "fein", "tax id"],
    requires_context=True,
)

PASSPORT = PatternRecognizer(
    "PASSPORT",
    [r"\b[A-Z]{1,2}\d{6,8}\b", r"\b\d{9}\b"],
    score=0.35,
    context=["passport", "travel document", "mrz"],
    requires_context=True,
)

#: Generic "alphanumeric token with a digit in it" patterns will happily match
#: an ISO date or a version string. Those have their own entity (or none), so
#: they are denied here rather than being fought over during overlap resolution.
_DATE_SHAPED = (
    r"\d{4}-\d{2}-\d{2}",
    r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}",
    r"\d{4}[-/]\d{1,2}",
    r"[Vv]?\d+\.\d+(?:\.\d+)*",
)

DRIVER_LICENSE = PatternRecognizer(
    "DRIVER_LICENSE",
    [r"\b(?=[A-Z0-9]*\d)[A-Z0-9]{5,16}\b"],
    score=0.3,
    flags=0,
    context=["driver", "driving licen", "licence no", "license no", "dl#", "dl no", "permit"],
    requires_context=True,
    deny=[r"(?i)licen[cs]e", r"(?i)number", r"(?i)driver", *_DATE_SHAPED],
)

VEHICLE_VIN = PatternRecognizer(
    "VEHICLE_VIN",
    [r"\b[A-HJ-NPR-Z0-9]{17}\b"],
    score=0.8,
    validator=ck.vin,
)

LICENSE_PLATE_IN = PatternRecognizer(
    "LICENSE_PLATE",
    [r"\b[A-Z]{2}[ -]?\d{2}[ -]?[A-Z]{1,2}[ -]?\d{4}\b"],
    score=0.5,
    context=["plate", "vehicle", "registration", "reg no", "car"],
    requires_context=True,
)

#: Indian registration marks written compactly ("KA05MN7319") need no context:
#: a valid state code followed by the district and series shape is specific
#: enough on its own. A vehicle receipt that named the plate only in its title
#: was missed entirely when this required a nearby "vehicle".
_IN_STATE_CODES = (
    "AN|AP|AR|AS|BR|CH|CG|DD|DL|DN|GA|GJ|HR|HP|JK|JH|KA|KL|LA|LD|MP|MH|MN|ML|MZ|"
    "NL|OD|OR|PY|PB|RJ|SK|TN|TS|TR|UP|UK|UA|WB"
)
LICENSE_PLATE_IN_COMPACT = PatternRecognizer(
    "LICENSE_PLATE",
    [rf"\b(?:{_IN_STATE_CODES})\d{{2}}[A-Z]{{1,3}}\d{{4}}\b"],
    name="license_plate_in_compact",
    score=0.7,
    flags=0,
)

# --------------------------------------------------------------------------
# financial
# --------------------------------------------------------------------------

#: Leading digits a payment card can actually start with: 2 and 5 (Mastercard),
#: 3 (Amex, Diners, JCB), 4 (Visa), 6 (Discover, RuPay, Maestro) and 8 (RuPay).
#: A number starting 0, 1, 7 or 9 is a reference, not a card -- and about one
#: random number in ten passes Luhn, so the prefix does real work.
_CARD_PREFIX = re.compile(r"[2-6]|8")


def _card(value: str) -> bool:
    digits = ck.digits_only(value)
    return 13 <= len(digits) <= 19 and bool(_CARD_PREFIX.match(digits)) and ck.luhn(digits)


#: Printed the way cards are printed -- 16 digits in fours, Amex's 4-6-5, or
#: an unbroken 15-16 -- a Luhn-valid number is a card without further evidence.
CREDIT_CARD = PatternRecognizer(
    "CREDIT_CARD",
    [
        r"(?<![\w-])\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?![\w-])",
        r"(?<![\w-])\d{4}([ -])\d{6}\1\d{5}(?![\w-])",
        r"(?<![\w-])\d{15,16}(?![\w-])",
    ],
    score=0.8,
    validator=_card,
    context=["card", "visa", "mastercard", "amex", "rupay", "discover", "payment", "credit"],
)

#: Any other length or grouping -- "999 99-99999999", fourteen bare digits --
#: is a card only if the text around it says so. Reference and invoice numbers
#: in these shapes were being redacted as cards.
CREDIT_CARD_UNUSUAL = PatternRecognizer(
    "CREDIT_CARD",
    [r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])"],
    name="credit_card_unusual",
    score=0.55,
    validator=_card,
    context=["card", "visa", "mastercard", "amex", "rupay", "discover", "credit card", "debit card"],
    requires_context=True,
)

#: Not part of a larger number: "837" inside "1,837.00" is an amount, and a
#: "CVV" label on the line above used to vouch for it.
CVV = PatternRecognizer(
    "CVV",
    [r"(?<![\w,.-])\d{3,4}(?![\w-]|[.,]\d)"],
    score=0.4,
    context=["cvv", "cvc", "cid", "security code", "card verification"],
    requires_context=True,
)

CARD_EXPIRY = PatternRecognizer(
    "CARD_EXPIRY",
    [r"(?<![\d/])(?:0[1-9]|1[0-2])/(?:\d{2}|20\d{2})(?![\d/])"],
    score=0.4,
    context=["exp", "expiry", "expires", "valid thru", "valid until", "card"],
    requires_context=True,
)

IBAN = PatternRecognizer(
    "IBAN",
    [r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b"],
    score=0.9,
    validator=ck.iban,
    flags=0,
)

SWIFT_BIC = PatternRecognizer(
    "SWIFT_BIC",
    [r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"],
    score=0.4,
    context=["swift", "bic", "wire", "beneficiary bank", "intermediary"],
    requires_context=True,
    flags=0,
)

US_ROUTING = PatternRecognizer(
    "US_ROUTING",
    [r"(?<![\w-])\d{9}(?![\w-])"],
    score=0.5,
    validator=ck.aba_routing,
    context=["routing", "aba", "rtn", "wire", "ach", "transit", "bank"],
    requires_context=True,
)

BANK_ACCOUNT = PatternRecognizer(
    "BANK_ACCOUNT",
    [r"(?<![\w-])\d{7,17}(?![\w-])", r"\b[Xx*]{2,}\d{3,6}\b"],
    score=0.4,
    context=[
        "account", "account number", "acct", "acct no", "a/c", "iban",
        "savings", "checking", "current a", "beneficiary account",
    ],
    requires_context=True,
)

IFSC = PatternRecognizer(
    "IFSC",
    [r"\b[A-Z]{4}0[A-Z0-9]{6}\b"],
    score=0.75,
    flags=0,
)

UPI_ID = PatternRecognizer(
    "UPI_ID",
    [r"\b[a-z0-9.\-_]{2,30}@(?:okhdfcbank|oksbi|okicici|okaxis|paytm|ybl|ibl|axl|upi|apl)\b"],
    score=0.9,
)

# --------------------------------------------------------------------------
# national identity numbers
# --------------------------------------------------------------------------

def _aadhaar(value: str) -> bool:
    return len(ck.digits_only(value)) == 12 and ck.verhoeff(value)


#: Aadhaar is printed in groups of four ("2345 6789 0123"). Written that way it
#: needs no further evidence.
AADHAAR = PatternRecognizer(
    "AADHAAR",
    [r"(?<![\w-])[2-9]\d{3}([ -])\d{4}\1\d{4}(?![\w-])"],
    score=0.6,
    validator=_aadhaar,
    context=["aadhaar", "aadhar", "uid", "uidai"],
)

#: Twelve unbroken digits are also the shape of every UPI transaction
#: reference, and Verhoeff passes one random number in ten -- so a bank
#: statement produced 32 "Aadhaar numbers". Unbroken, it needs a nearby cue.
AADHAAR_BARE = PatternRecognizer(
    "AADHAAR",
    [r"(?<![\w-])[2-9]\d{11}(?![\w-])"],
    name="aadhaar_bare",
    score=0.6,
    validator=_aadhaar,
    context=["aadhaar", "aadhar", "uid", "uidai", "enrolment", "enrollment"],
    requires_context=True,
)

PAN_IN = PatternRecognizer(
    "PAN_IN",
    [r"\b[A-Z]{5}\d{4}[A-Z]\b"],
    score=0.75,
    validator=ck.pan_india,
    flags=0,
)

#: Tax Deduction Account Number: four letters, five digits, a letter. It names
#: the employer deducting tax on a Form 16 rather than the employee, but it
#: identifies the employer, and without its own entity it was being picked up
#: as a health plan ID by the "policy" cue elsewhere on the form.
TAN_IN = PatternRecognizer(
    "TAN_IN",
    [r"\b[A-Z]{4}\d{5}[A-Z]\b"],
    # Above the generic health-plan pattern's 0.7, so the specific shape wins
    # the overlap rather than losing a tie on alphabetical order.
    score=0.75,
    context=["tan", "deductor", "tax deduction"],
    flags=0,
)

GSTIN = PatternRecognizer(
    "GSTIN",
    [r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b"],
    score=0.9,
    validator=ck.gstin,
    flags=0,
)

UK_NINO = PatternRecognizer(
    "UK_NINO",
    [r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D]\b"],
    score=0.75,
    flags=0,
)

# --------------------------------------------------------------------------
# health
# --------------------------------------------------------------------------

MRN = PatternRecognizer(
    "MRN",
    # The letter prefix must be attached: "MR-4471982" is one identifier, but in
    # "MRN 4471982" the letters are the label. Allowing a space there let the
    # pattern swallow its own context cue and then fail the context check, so
    # an MRN written without a colon was missed entirely.
    [r"\b(?:[A-Z]{1,3}-)?\d{5,12}\b"],
    score=0.45,
    context=[
        "mrn", "m\\.r\\.n", "medical record", "medical record number",
        "patient id", "patient no", "patient number", "patient #",
        "chart no", "chart number", "chart #", "accession", "accession number",
        "record number", "hospital no", "hospital number", "encounter id",
    ],
    requires_context=True,
)

NHS_NUMBER = PatternRecognizer(
    "NHS_NUMBER",
    [r"(?<![\w-])\d{3}[ -]?\d{3}[ -]?\d{4}(?![\w-])"],
    score=0.55,
    validator=ck.nhs_number,
    context=["nhs"],
)

NPI = PatternRecognizer(
    "NPI",
    [r"(?<![\w-])\d{10}(?![\w-])"],
    score=0.6,
    validator=ck.npi,
    context=["npi", "provider", "physician", "clinician", "prescriber"],
)

DEA = PatternRecognizer(
    "DEA",
    [r"\b[A-Z]{2}\d{7}\b"],
    score=0.7,
    validator=ck.dea,
    flags=0,
)

HEALTH_PLAN_ID = PatternRecognizer(
    "HEALTH_PLAN_ID",
    [r"\b(?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{5,16}\b"],
    score=0.4,
    flags=0,
    context=[
        "member id", "member no", "member number", "member #",
        "policy", "subscriber", "subscriber number",
        "group number", "group no", "group #",
        "health plan", "insurance", "payer", "beneficiary",
        "medicare", "medicaid", "mbi", "certificate number",
    ],
    requires_context=True,
    deny=[r"(?i)member|policy|number|subscriber|insurance|medicare|medicaid", *_DATE_SHAPED],
)

DEVICE_SERIAL = PatternRecognizer(
    "DEVICE_SERIAL",
    [r"\b(?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{5,24}\b"],
    score=0.35,
    flags=0,
    context=["serial", "s/n", "sn:", "device id", "implant", "udi", "lot no"],
    requires_context=True,
    deny=[r"(?i)serial|device|number", *_DATE_SHAPED],
)

BIOMETRIC_REF = PatternRecognizer(
    "BIOMETRIC_ID",
    [r"\b[A-F0-9]{32,64}\b"],
    score=0.4,
    context=["biometric", "fingerprint", "retina", "iris", "voiceprint", "faceprint"],
    requires_context=True,
    flags=0,
)

# --------------------------------------------------------------------------
# quasi-identifiers: dates, ages, places
# --------------------------------------------------------------------------

_MONTHS = (
    "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|"
    "aug(?:ust)?|sep(?:t)?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
)

DATE = PatternRecognizer(
    "DATE",
    [
        # The backreference requires the SAME separator on both sides. A real
        # date is 12/31/1999 or 12-31-1999; a clinical reference range such as
        # "12.0-15.5" mixes them, and without this the leading "12.0-15" is
        # date-shaped and a lab range gets destroyed.
        r"(?<![\d/.\-])\d{1,2}([/.\-])\d{1,2}\1(?:\d{4}|\d{2})(?![\d/])(?![.\-]\d)",
        r"(?<![\w-])(?:19|20)\d{2}-\d{2}-\d{2}(?![\w-])",
        rf"\b(?:{_MONTHS})\.?[ ]\d{{1,2}}(?:st|nd|rd|th)?,?[ ](?:19|20)\d{{2}}\b",
        rf"\b\d{{1,2}}(?:st|nd|rd|th)?[ ](?:{_MONTHS})\.?,?[ ](?:19|20)\d{{2}}\b",
    ],
    score=0.6,
)

AGE_OVER_89 = PatternRecognizer(
    "AGE_OVER_89",
    [
        r"\b(?:9\d|1[0-2]\d)[ -]?(?:years?[ -]?old|yrs?[ -]?old|y/o|yo)\b",
        r"(?<=age[ :])[ ]?(?:9\d|1[0-2]\d)\b",
        r"(?<=age of )(?:9\d|1[0-2]\d)\b",
    ],
    score=0.8,
)

#: USPS state abbreviations, used to anchor both ZIP codes and city names.
_US_STATE = (
    r"A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|"
    r"N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY]"
)

US_ZIP = PatternRecognizer(
    "US_ZIP",
    [
        # anchored to a state abbreviation, e.g. "San Jose, CA 95134"
        rf"\b(?:{_US_STATE})[ ,]+(?P<zip>\d{{5}}(?:-\d{{4}})?)\b",
    ],
    name="us_zip_stateful",
    score=0.8,
    group="zip",
    flags=0,
)

#: HIPAA Safe Harbor removes every geographic subdivision smaller than a state,
#: so the city has to go even though the state itself may stay.
CITY = PatternRecognizer(
    "CITY",
    [
        rf"(?P<city>\b[A-Z][a-z]+(?:[ ][A-Z][a-z]+){{0,2}}),[ ]*(?:{_US_STATE})\b"
        rf"(?![a-z])",
    ],
    name="city_stateful",
    score=0.7,
    group="city",
    flags=0,
)

US_ZIP_LABELLED = PatternRecognizer(
    "US_ZIP",
    [r"(?<![\w-])\d{5}(?:-\d{4})?(?![\w-])"],
    name="us_zip_labelled",
    score=0.45,
    context=["zip", "postal", "post code", "postcode"],
    requires_context=True,
)

UK_POSTCODE = PatternRecognizer(
    "UK_POSTCODE",
    [r"\b[A-Z]{1,2}\d[A-Z\d]?[ ]?\d[A-Z]{2}\b"],
    score=0.6,
    context=["postcode", "post code", "address", "united kingdom", "uk"],
    requires_context=True,
    flags=0,
)

IN_PINCODE = PatternRecognizer(
    "IN_PINCODE",
    [r"(?<![\w-])[1-9]\d{5}(?![\w-])"],
    score=0.4,
    context=["pin code", "pincode", "pin:", "india"],
    requires_context=True,
)

#: The house number may not follow a decimal point or thousands separator, and
#: at least one street-name word must sit between it and the suffix. Without
#: those two rules every "2,500.00 Dr" in a bank statement -- Dr for debit --
#: was a street address, 98 of them in one statement, each one eating the
#: fractional part of an amount.
STREET_ADDRESS = PatternRecognizer(
    "STREET_ADDRESS",
    [
        r"(?<![\d.,])\b\d{1,6}[A-Z]?[ ](?:[A-Z][A-Za-z.'\-]*[ ]){1,4}"
        r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|"
        r"circle|cir|way|place|pl|terrace|ter|parkway|pkwy|highway|hwy|square|sq|"
        r"marg|nagar|colony|sector|cross|main)\b\.?"
        r"(?:[ ,]+(?:apt|apartment|suite|ste|unit|floor|flat|#)[ ]?[A-Z0-9\-]+)?",
    ],
    score=0.7,
)

GEO_COORDS = PatternRecognizer(
    "GEO_COORDS",
    [r"(?<![\d.])-?\d{1,3}\.\d{4,},[ ]?-?\d{1,3}\.\d{4,}(?![\d.])"],
    score=0.7,
)

# --------------------------------------------------------------------------
# credentials and secrets
# --------------------------------------------------------------------------

PRIVATE_KEY = PatternRecognizer(
    "PRIVATE_KEY",
    [r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]{0,8192}?-----END[A-Z ]*PRIVATE KEY-----"],
    score=1.0,
    flags=0,
)

AWS_KEY = PatternRecognizer(
    "AWS_ACCESS_KEY",
    [r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"],
    score=1.0,
    flags=0,
)

JWT = PatternRecognizer(
    "JWT",
    [r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"],
    score=0.95,
    flags=0,
)

VCS_TOKEN = PatternRecognizer(
    "API_TOKEN",
    [
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
        r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b",
        r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
    ],
    name="vcs_token",
    score=1.0,
    flags=0,
)

GENERIC_SECRET = PatternRecognizer(
    "API_TOKEN",
    [
        r"(?i)\b(?:api[_\-]?key|secret|token|password|passwd|pwd|auth)\b"
        r"[\"']?\s*[:=]\s*[\"']?(?P<val>[A-Za-z0-9/+_\-.=]{12,256})",
    ],
    name="generic_secret",
    score=0.7,
    group="val",
    # Config files are full of values shaped like secrets that are not secrets.
    # Substring matching, not exact: "REDACTED-REDACTED" is still a placeholder.
    deny=[
        r"(?i)(?:null|none|true|false|undefined|\*+|\$\{.*)",
        r"(?i).*(?:redacted|changeme|change[_-]?me|placeholder|example|dummy|"
        r"sample|your[_-]?\w*here|xxxx|<[^>]*>).*",
    ],
    flags=0,
)

#: Everything above, in the order the engine should consider it.
ALL_RECOGNIZERS = [
    PRIVATE_KEY, AWS_KEY, JWT, VCS_TOKEN, GENERIC_SECRET,
    EMAIL, URL, IP_ADDRESS, MAC_ADDRESS, PHONE, PHONE_IN_BARE,
    SSN, SSN_BARE, EIN, PASSPORT, DRIVER_LICENSE, VEHICLE_VIN, LICENSE_PLATE_IN,
    LICENSE_PLATE_IN_COMPACT,
    CREDIT_CARD, CREDIT_CARD_UNUSUAL, IBAN, SWIFT_BIC, US_ROUTING, BANK_ACCOUNT,
    CVV, CARD_EXPIRY, IFSC, UPI_ID,
    AADHAAR, AADHAAR_BARE, PAN_IN, TAN_IN, GSTIN, UK_NINO,
    MRN, NHS_NUMBER, NPI, DEA, HEALTH_PLAN_ID, DEVICE_SERIAL, BIOMETRIC_REF,
    DATE, AGE_OVER_89, US_ZIP, US_ZIP_LABELLED, UK_POSTCODE, IN_PINCODE,
    STREET_ADDRESS, CITY, GEO_COORDS,
]

_names = [r.name for r in ALL_RECOGNIZERS]
if len(set(_names)) != len(_names):
    duplicates = sorted({n for n in _names if _names.count(n) > 1})
    raise RuntimeError(f"duplicate detector names in catalogue: {duplicates}")

#: Every entity type this build can produce.
ALL_ENTITIES = sorted({r.entity for r in ALL_RECOGNIZERS})
