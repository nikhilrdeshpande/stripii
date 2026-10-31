#!/usr/bin/env python3
"""Generate the synthetic benchmark corpus.

Deliberately not a showcase. A corpus written to match the detectors would
report a number that means nothing, so roughly a third of these documents use
constructions the detectors are known or expected to struggle with: surnames
absent from the bundled given-name list, cities with no state abbreviation
after them, narrative prose with no field labels, and identifiers written in
unusual formats.

Every value is invented. Where a format carries a check digit, the digit is
computed so the value is well formed, because a detector that validates
checksums would otherwise never see a positive case.

Annotation covers every identifier present, including ones a given profile
chooses to keep. A transaction date is a date whether or not the finance
profile redacts it; leaving it unannotated would score a correct detection as
a false positive.

    python tools/generate_corpus.py benchmarks/synthetic.jsonl
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from stripii.benchmark import build_document, write_corpus
from stripii.checksums import (
    aba_check_digit,
    luhn_check_digit,
    verhoeff_check_digit,
)

RNG = random.Random(20260916)

# Names chosen to straddle the bundled gazetteer: some are in it, several
# deliberately are not.
EASY_NAMES = ["Margaret Whitfield", "Robert Chen", "Priya Sharma", "Michael Rodriguez"]
HARD_NAMES = ["Kowalczyk Brzezinski", "Oyelaran Adebayo", "Thibodeaux Fontenot",
              "Siobhan Nic Dhomhnaill", "Xiulan Zhuang", "Agnieszka Wisniewska"]
CITIES_WITH_STATE = ["Springfield, IL", "Seattle, WA", "Brookfield, CT"]
CITIES_ALONE = ["Brookfield", "Wexford", "Nagercoil", "Ballingarry"]


def ssn() -> str:
    return f"{RNG.randint(100, 665)}-{RNG.randint(10, 99)}-{RNG.randint(1000, 9999)}"


def card() -> str:
    body = "4" + "".join(str(RNG.randint(0, 9)) for _ in range(14))
    number = body + luhn_check_digit(body)
    return " ".join(number[i:i + 4] for i in range(0, 16, 4))


def routing() -> str:
    body = "0" + "".join(str(RNG.randint(0, 9)) for _ in range(7))
    return body + aba_check_digit(body)


def aadhaar() -> str:
    body = str(RNG.randint(2, 9)) + "".join(str(RNG.randint(0, 9)) for _ in range(10))
    number = body + verhoeff_check_digit(body)
    return f"{number[:4]} {number[4:8]} {number[8:]}"


def npi() -> str:
    body = "".join(str(RNG.randint(0, 9)) for _ in range(9))
    return body + luhn_check_digit("80840" + body)


def phone() -> str:
    return f"({RNG.randint(200, 989)}) {RNG.randint(200, 999)}-{RNG.randint(1000, 9999)}"


def mrn() -> str:
    return str(RNG.randint(1000000, 99999999))


def email(name: str) -> str:
    first, _, last = name.lower().partition(" ")
    return f"{first[0]}.{last.replace(' ', '')}@{RNG.choice(['example.com', 'example.org'])}"


def date() -> str:
    return f"{RNG.randint(1, 12):02d}/{RNG.randint(1, 28):02d}/{RNG.randint(1930, 2026)}"


def slot(entity: str, value: str) -> str:
    return "{{" + entity + ":" + value + "}}"


def structured_health(index: int) -> str:
    """The easy case: a labelled clinical record."""
    name = RNG.choice(EASY_NAMES + HARD_NAMES)
    city = RNG.choice(CITIES_WITH_STATE)
    return f"""DISCHARGE SUMMARY

Patient Name: {slot('PERSON', name)}
MRN: {slot('MRN', mrn())}
Date of Birth: {slot('DATE', date())}
Address: {slot('STREET_ADDRESS', f'{RNG.randint(1, 9999)} Oakmont Drive')}, \
{slot('CITY', city.split(',')[0])}, {city.split(', ')[1]} {slot('US_ZIP', str(RNG.randint(10000, 99999)))}
Phone: {slot('PHONE', phone())}
Email: {slot('EMAIL', email(name))}
SSN: {slot('SSN', ssn())}
Attending: Dr. {slot('PERSON', RNG.choice(EASY_NAMES))} (NPI {slot('NPI', npi())})

ASSESSMENT
Hemoglobin {RNG.randint(80, 160) / 10} g/dL, Glucose {RNG.randint(70, 250)} mg/dL.
Diagnosis: Type 2 Diabetes Mellitus (E11.9). Continue metformin 1000 mg BID.
Follow up on {slot('DATE', date())}.
"""


def structured_finance(index: int) -> str:
    name = RNG.choice(EASY_NAMES + HARD_NAMES)
    return f"""ACCOUNT STATEMENT

Account Holder: {slot('PERSON', name)}
Account Number: {slot('BANK_ACCOUNT', str(RNG.randint(10000000, 999999999)))}
Routing Number: {slot('US_ROUTING', routing())}
Card: {slot('CREDIT_CARD', card())}
Contact: {slot('EMAIL', email(name))} / {slot('PHONE', phone())}
Tax ID (SSN): {slot('SSN', ssn())}

TRANSACTIONS
{slot('DATE', date())}  Payroll Deposit      +{RNG.randint(1000, 9000)}.{RNG.randint(10, 99)}
{slot('DATE', date())}  Mortgage Payment     -{RNG.randint(500, 3000)}.00
Closing Balance               {RNG.randint(1000, 90000)}.{RNG.randint(10, 99)}
"""


def narrative(index: int) -> str:
    """The hard case: prose, no labels, names that may be off-gazetteer."""
    name = RNG.choice(HARD_NAMES)
    relative = RNG.choice(["daughter", "son", "husband", "wife"])
    other = RNG.choice(HARD_NAMES).split()[0]
    city = RNG.choice(CITIES_ALONE)
    return f"""Clinic note.

{slot('PERSON', name)} returned today, accompanied by their {relative} \
{slot('PERSON', other)}, who drives in from {slot('CITY', city)} each month.
We reviewed the results with {slot('PERSON', RNG.choice(HARD_NAMES).split()[0])} from the lab.
Fasting glucose was {RNG.randint(80, 200)}. The patient can be reached on \
{slot('PHONE', phone())} or at {slot('EMAIL', email(name))}.
Record number {slot('MRN', mrn())}. Next review {slot('DATE', date())}.
"""


def international(index: int) -> str:
    name = RNG.choice(HARD_NAMES)
    return f"""KYC RECORD

Name: {slot('PERSON', name)}
Aadhaar: {slot('AADHAAR', aadhaar())}
PAN: {slot('PAN_IN', 'ABCPD' + str(RNG.randint(1000, 9999)) + 'E')}
IFSC: {slot('IFSC', 'HDFC0' + str(RNG.randint(100000, 999999)))}
Mobile: {slot('PHONE', '+91 ' + str(RNG.randint(60000, 99999)) + ' ' + str(RNG.randint(10000, 99999)))}
Email: {slot('EMAIL', email(name))}
Registered on {slot('DATE', date())}.
"""


INDIAN_NAMES = ["VIKRAM DESAI", "PRIYA IYER", "RAJESH KUMAR SHARMA", "ANITA KULKARNI",
                "SURESH PATIL", "KAVITA MENON", "ARJUN REDDY", "MEERA JOSHI"]


def upi_ref() -> str:
    """Twelve digits, like every UPI transaction reference -- never an identifier."""
    return str(RNG.randint(200000000000, 999999999999))


def indian_statement(index: int) -> str:
    """The shape that broke the tool on real documents: capital-letter names in
    label/value table cells, S/O lines, Dr/Cr markers and twelve-digit UPI
    references. Added after 184 of 184 such names were missed in real files --
    this corpus had none, which is why its recall figure did not show it."""
    name = RNG.choice(INDIAN_NAMES)
    father = RNG.choice(INDIAN_NAMES).split()[0] + " " + name.split()[-1]
    account = str(RNG.randint(10**13, 10**14 - 1))
    rows = "\n".join(
        f"| {slot('DATE', f'{RNG.randint(13, 28):02d}-{RNG.randint(1, 12):02d}-2026')} "
        f"| UPI/{upi_ref()}/{RNG.choice(['GROCERY', 'FUEL', 'RENT'])} "
        f"| {RNG.randint(100, 9000)}.{RNG.randint(10, 99)} {RNG.choice(['Dr', 'Cr'])} |"
        for _ in range(4)
    )
    return f"""STATEMENT OF ACCOUNT

| Account Holder | - | {slot('PERSON', name)} |
| --- | --- | --- |
| S/O | - | {slot('PERSON', father)} |
| Account Number | - | {slot('BANK_ACCOUNT', account)} |
| IFSC | - | {slot('IFSC', 'HDFC0' + str(RNG.randint(100000, 999999)))} |
| Mobile | - | {slot('PHONE', '+91 ' + str(RNG.randint(60000, 99999)) + ' ' + str(RNG.randint(10000, 99999)))} |

| Date | Narration | Amount |
| --- | --- | --- |
{rows}

Balance 1,{RNG.randint(100, 999)},{RNG.randint(100, 999)}.00 Cr
Transfer received into {slot('BANK_ACCOUNT', account)} from {slot('PERSON', name)}.
"""


def distractors(index: int) -> str:
    """No gold spans at all: everything here must be left alone.

    Without these, precision is measured against a corpus that contains nothing
    tempting, and a score of 1.000 says only that the corpus was easy. These are
    the shapes that have actually caused false positives in this codebase: lab
    reference ranges that contain a date-shaped substring, clinical codes,
    amounts, versions and measurements.
    """
    return f"""LABORATORY REPORT (no identifiers in this document)

| Test | Result | Ref Range | Units |
| --- | --- | --- | --- |
| Hemoglobin | {RNG.randint(80, 160) / 10} | 12.0-15.5 | g/dL |
| Potassium | {RNG.randint(30, 55) / 10} | 3.5-5.1 | mmol/L |
| Creatinine | {RNG.randint(5, 25) / 10} | 0.6-1.1 | mg/dL |
| Calcium | {RNG.randint(80, 110) / 10} | 8.5-10.2 | mg/dL |
| Sodium | {RNG.randint(130, 150)} | 135-145 | mmol/L |
| Specific gravity | 1.0{RNG.randint(10, 30)} | 1.02-1.08 | |

Diagnosis codes: E11.9, I10, N18.3, Z79.4. CPT 80053, 85025.
Blood pressure 120/80 mmHg. BMI {RNG.randint(180, 350) / 10}.
Assay version 2.14.3, analyser firmware 5.1.2, protocol revision 1.02-1.08.
Batch quantity {RNG.randint(100000, 999999)} units at {RNG.randint(10, 99)}.{RNG.randint(10, 99)} each.
Total {RNG.randint(100000, 999999)}.{RNG.randint(10, 99)} for the period.
Reference interval 70-99 for fasting glucose.
"""


GENERATORS = [
    (structured_health, 18),
    (structured_finance, 14),
    (narrative, 18),      # deliberately the largest share of hard cases
    (international, 10),
    (indian_statement, 12),
    (distractors, 12),    # no gold spans: pure precision pressure
]


def main() -> int:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "benchmarks/synthetic.jsonl")
    destination.parent.mkdir(parents=True, exist_ok=True)

    documents = []
    for generator, count in GENERATORS:
        for index in range(count):
            documents.append(
                build_document(f"{generator.__name__}-{index:03d}", generator(index))
            )

    written = write_corpus(documents, destination)
    spans = sum(len(d.spans) for d in documents)
    print(f"wrote {written} documents, {spans} gold spans -> {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
