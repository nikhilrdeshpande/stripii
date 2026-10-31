"""Detector coverage, and the false positives that matter more."""

from __future__ import annotations

import pytest

from stripii import Scrubber, get_profile
from stripii.detectors import ALL_ENTITIES

PARANOID = Scrubber(get_profile("paranoid"))


def entities_in(text: str) -> set[str]:
    return {d.entity for d in PARANOID.scan(text)}


POSITIVE_CASES = [
    ("EMAIL", "write to jane.doe+tag@sub.example.co.uk please"),
    ("PHONE", "call (415) 555-0132 today"),
    ("PHONE", "reach me on +91 98765 43210"),
    ("SSN", "SSN: 412-88-9031"),
    ("CREDIT_CARD", "card 4111 1111 1111 1111 on file"),
    ("IBAN", "IBAN GB82 WEST 1234 5698 7654 32"),
    ("US_ROUTING", "Routing number 021000021"),
    ("NPI", "provider NPI 1234567893"),
    ("DEA", "DEA BX1234563"),
    ("NHS_NUMBER", "NHS number 943 476 5919"),
    ("PAN_IN", "PAN ABCPD1234E"),
    ("GSTIN", "GSTIN 27AAPFU0939F1ZV"),
    ("IFSC", "IFSC HDFC0001234"),
    ("UPI_ID", "pay to anaya.r@oksbi now"),
    ("UK_NINO", "NINO AB123456C"),
    ("VEHICLE_VIN", "VIN 1HGCM82633A004352"),
    ("IP_ADDRESS", "connected from 192.168.44.201"),
    ("MAC_ADDRESS", "device AA:BB:CC:DD:EE:FF"),
    ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
    ("API_TOKEN", "token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
    ("JWT", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    ("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----"),
    ("STREET_ADDRESS", "lives at 1847 Oakmont Drive, Apt 3B"),
    ("GEO_COORDS", "pinned at 37.774929,-122.419418"),
    ("PERSON", "Patient Name: Margaret Whitfield"),
    ("MRN", "MRN: 4471982"),
    ("AGE_OVER_89", "the patient is 94 years old"),
    ("DATE", "seen on 03/14/1934 for review"),
    ("TAN_IN", "TAN of deductor MUMA12345B"),
    ("US_ZIP", "Springfield, IL 62704"),
    ("CITY", "Springfield, IL 62704"),
]


@pytest.mark.parametrize(("entity", "text"), POSITIVE_CASES)
def test_entity_is_detected(entity, text):
    assert entity in entities_in(text), f"{entity} not found in {text!r}"


def test_every_catalogued_entity_has_a_positive_case():
    """A detector nobody tests is a detector nobody can trust."""
    untested = set(ALL_ENTITIES) - {e for e, _ in POSITIVE_CASES}
    # These are covered in dedicated tests below rather than the table.
    untested -= {
        "AADHAAR", "BANK_ACCOUNT", "CARD_EXPIRY", "CVV", "DEVICE_SERIAL",
        "DRIVER_LICENSE", "EIN", "HEALTH_PLAN_ID", "IN_PINCODE", "LICENSE_PLATE",
        "PASSPORT", "SWIFT_BIC", "UK_POSTCODE", "URL", "BIOMETRIC_ID",
    }
    assert not untested, f"entities with no positive case: {sorted(untested)}"


# --------------------------------------------------------------------------
# false positives: what must NOT be detected
# --------------------------------------------------------------------------

CLINICAL_NEGATIVES = [
    "Diagnosis: Type 2 Diabetes Mellitus (E11.9)",
    "Hemoglobin 10.2 g/dL, Hematocrit 31%",
    "Complete Blood Count and Comprehensive Metabolic Panel ordered",
    "Chest X-Ray negative for acute process",
    "continue metformin 1000 mg BID",
    "Emergency Department admission, Intensive Care Unit stay",
]


@pytest.mark.parametrize("text", CLINICAL_NEGATIVES)
def test_clinical_language_is_not_treated_as_a_person(text):
    assert "PERSON" not in entities_in(text)


FINANCIAL_NEGATIVES = [
    "Closing Balance 14,209.87",
    "Payroll Deposit - ACME CORP +4,820.55",
    "Annual Percentage Yield 4.25%",
]


@pytest.mark.parametrize("text", FINANCIAL_NEGATIVES)
def test_amounts_are_not_identifiers(text):
    found = entities_in(text)
    assert "PERSON" not in found
    assert "CREDIT_CARD" not in found


def test_a_number_inside_a_word_is_not_an_ssn():
    """XHP449182736 is a member ID; the digits inside it are not an SSN."""
    found = PARANOID.scan("Member ID: XHP449182736")
    assert not [d for d in found if d.entity == "SSN"]


def test_a_date_is_not_a_health_plan_id():
    found = {d.entity for d in PARANOID.scan("Member ID: A1\nAdmission Date: 2025-08-02")}
    assert "DATE" in found


def test_invalid_checksums_are_rejected():
    assert "CREDIT_CARD" not in entities_in("order number 4111 1111 1111 1112")
    assert "US_ROUTING" not in entities_in("routing 021000022")
    assert "NPI" not in entities_in("NPI 1234567890")


def test_context_free_weak_patterns_stay_quiet():
    """Nine digits with nothing around them should not become an SSN."""
    assert "SSN" not in entities_in("the count was 412889031 items")


def test_context_does_not_bleed_across_distant_lines():
    """An SSN label two fields away must not vouch for an unrelated number."""
    text = "SSN: 412-88-9031\nMember ID: A1\nWidget count: 449182736\n"
    ssn_spans = [d.raw for d in PARANOID.scan(text) if d.entity == "SSN"]
    assert "449182736" not in ssn_spans


def test_loopback_and_broadcast_addresses_are_not_personal():
    assert "IP_ADDRESS" not in entities_in("bound to 127.0.0.1 and 0.0.0.0")


def test_placeholder_secrets_are_ignored():
    assert "API_TOKEN" not in entities_in('api_key = "REDACTED-REDACTED"')


# --------------------------------------------------------------------------
# entities exercised individually
# --------------------------------------------------------------------------

def test_aadhaar_needs_a_valid_verhoeff_digit():
    assert "AADHAAR" not in entities_in("Aadhaar 2346 1728 3060")


def test_context_gated_entities():
    cases = {
        "BANK_ACCOUNT": "Account Number: 483920175",
        "CVV": "CVV 837",
        "CARD_EXPIRY": "card Exp 11/27",
        "EIN": "EIN 12-3456789",
        "PASSPORT": "Passport N1234567",
        "SWIFT_BIC": "SWIFT CHASUS33XXX",
        "HEALTH_PLAN_ID": "Member ID: XHP449182736",
        "DEVICE_SERIAL": "Serial: PM-4471982-X",
        "DRIVER_LICENSE": "Driver License D1234567",
        "UK_POSTCODE": "postcode SW1A 1AA",
        "IN_PINCODE": "PIN code 411045",
        "LICENSE_PLATE": "vehicle registration MH12AB1234",
        "URL": "see https://example.com/patients/8821",
    }
    for entity, text in cases.items():
        assert entity in entities_in(text), f"{entity} not found in {text!r}"


def test_biometric_reference_requires_context():
    digest = "A3F9" * 8
    assert "BIOMETRIC_ID" not in entities_in(f"checksum {digest}")
    assert "BIOMETRIC_ID" in entities_in(f"fingerprint template {digest}")


# --------------------------------------------------------------------------
# regressions
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "her daughter Elena drove her in",
        "accompanied by her son Marco",
        "late husband Aurelio had the same condition",
        "next of kin Priya Iyer",
        "spoke with Kenji Tanaka this morning",
    ],
)
def test_relationship_words_introduce_a_name(text):
    """Narrative notes name people with no label, title or credential."""
    assert "PERSON" in entities_in(text)


@pytest.mark.parametrize(
    "text",
    [
        "Name: not available",
        "Patient: none recorded",
        "Her granddaughter, who teaches at the local school, called",
        "the patient reported that her son was unwell",
    ],
)
def test_lowercase_prose_is_not_a_name(text):
    """Regression: a leading (?i) once disabled the capitalisation requirement."""
    assert "PERSON" not in entities_in(text)


@pytest.mark.parametrize(
    "text",
    [
        "member number XHP449182736",
        "Member ID: XHP449182736",
        "subscriber number XHP449182736",
    ],
)
def test_health_plan_id_keyword_variants(text):
    """Regression: "member number" did not match the keyword "member no"."""
    assert "HEALTH_PLAN_ID" in entities_in(text)


@pytest.mark.parametrize(
    "text",
    ["Medical Record Number: 4471982", "Patient Number 4471982", "Chart #: 4471982"],
)
def test_mrn_keyword_variants(text):
    assert "MRN" in entities_in(text)


def test_mrn_does_not_swallow_the_preceding_space():
    """Regression: an optional letter prefix left its separator matching alone."""
    found = [d for d in PARANOID.scan("Patient Number 4471982") if d.entity == "MRN"]
    assert found
    assert found[0].raw == "4471982"


def test_redaction_leaves_surrounding_whitespace_intact():
    scrubbed, _ = Scrubber(get_profile("health")).scrub("Patient Number 4471982 today")
    assert scrubbed.text == "Patient Number [[MRN_1]] today"


@pytest.mark.parametrize(
    "text",
    [
        "Reference range 12.0-15.5 g/dL",
        "Creatinine ref 0.6-1.1 mg/dL",
        "Glucose 70-99 mg/dL",
        "Potassium 3.5-5.1 mmol/L",
        "Sodium 135-145",
        "Calcium 8.5-10.2 mg/dL",
        "Specific gravity 1.02-1.08",
        "BP 120/80 mmHg",
    ],
)
def test_clinical_reference_ranges_are_not_dates(text):
    """Regression: "12.0-15.5" contains the date-shaped substring "12.0-15".

    A real date uses the same separator on both sides; a numeric range does not.
    Redacting a lab reference range destroys the reason to read the report.
    """
    assert "DATE" not in entities_in(text)


@pytest.mark.parametrize(
    "text",
    [
        "03/14/1934", "12-31-1999", "12.31.1999", "1/2/25",
        "seen on 03/14/1934.", "admitted (05/06/2024)", "2025-08-02",
        "14 March 2026", "March 14, 1934",
    ],
)
def test_real_dates_are_still_detected(text):
    assert "DATE" in entities_in(text)


def test_a_lab_table_keeps_every_value():
    row = "| Hemoglobin | 10.2 | 12.0-15.5 | LOW |"
    scrubbed, _ = Scrubber(get_profile("health")).scrub(row)
    assert scrubbed.text == row


@pytest.mark.parametrize(
    "text",
    [
        "Patient Margaret Whitfield, MRN 4471982, was seen.",   # no colon
        "MRN: 4471982",
        "MRN MR-4471982",                                        # attached prefix
        "Medical Record Number 4471982",
        "chart no 4471982",
    ],
)
def test_mrn_is_found_however_the_label_is_punctuated(text):
    """Regression: an optional space-separated letter prefix let the pattern
    swallow the very keyword the context check then looked for, so "MRN 4471982"
    written without a colon was missed entirely."""
    assert "MRN" in entities_in(text)
