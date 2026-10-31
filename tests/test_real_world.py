"""Regressions from the first run against real documents.

Every case here is a failure that 51 real medical and financial records
exposed and that the synthetic suite did not. The documents themselves never
enter the repository; these are synthetic reproductions of their *shapes* --
all-caps names in label/value tables, statements with "Dr"/"Cr" markers and
twelve-digit UPI references, PDFs whose pages are photographs.
"""

from __future__ import annotations

import datetime as dt
import io
import re

import pytest

from stripii import Action, Policy, Scrubber, Vault, get_profile
from stripii.checksums import luhn
from stripii.surrogates import Surrogator, infer_dayfirst

from .conftest import _module_available

KEY = b"k" * 32


def entities(text: str, profile: str = "paranoid") -> set[tuple[str, str]]:
    scrubber = Scrubber(get_profile(profile))
    return {
        (d.entity, d.raw)
        for d in scrubber.scan(text)
        if d.score >= scrubber.policy.min_score
    }


def scrub(text: str, profile: str = "health", **policy) -> str:
    base = get_profile(profile)
    if policy:
        base = Policy(name="t", **policy)
    return Scrubber(base, hash_key=KEY).scrub(text)[0].text


# --------------------------------------------------------------------------
# names printed in capitals (0 of 184 caught before)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("| Applicant Name | - | VIKRAM DESAI |", "VIKRAM DESAI"),
        ("NAME: RAJESH KUMAR SHARMA", "RAJESH KUMAR SHARMA"),
        ("Customer Name : PRIYA IYER", "PRIYA IYER"),
        ("Father's Name: SURESH DESAI", "SURESH DESAI"),
        ("S/O RAMESH KUMAR, near the station", "RAMESH KUMAR"),
        ("Account Holder | ANITA KULKARNI", "ANITA KULKARNI"),
    ],
)
def test_capitalised_names_are_detected(text, name):
    assert ("PERSON", name) in entities(text)


@pytest.mark.parametrize(
    "text",
    ["PAYMENT RECEIPT", "TRADE MARK REGISTRATION", "HDFC BANK LTD",
     "INCOME TAX DEPARTMENT", "GOVT OF INDIA", "ACCOUNT STATEMENT"],
)
def test_capitalised_headings_are_not_names(text):
    assert not {e for e, _ in entities(text)} & {"PERSON"}


def test_label_and_value_in_separate_table_cells():
    """Rendering a PDF as Markdown puts the label and the value in different cells."""
    out = scrub("| Applicant Name | - | VIKRAM DESAI |\n| Mode | - | UPI |")
    assert "VIKRAM" not in out
    assert "| Mode | - | UPI |" in out


# --------------------------------------------------------------------------
# a value redacted in one place must not survive in another (78 cases)
# --------------------------------------------------------------------------

def test_a_value_found_once_is_redacted_everywhere():
    text = "Account Number: 50100123456789\n...\nTransfer from 50100123456789 received"
    out = scrub(text, "finance")
    assert "50100123456789" not in out


def test_the_parts_of_a_detected_name_are_redacted_where_they_recur():
    text = "Patient Name: Margaret Whitfield\n\nMrs. Whitfield reported feeling better."
    out = scrub(text)
    assert "Whitfield" not in out


def test_propagation_matches_capitals_and_title_case():
    text = "Account Holder: Vikram Desai\n\nVIKRAM DESAI  UPI/CR/1234"
    assert "VIKRAM" not in scrub(text, "finance")


def test_propagation_respects_word_boundaries():
    """A surname must not be cut out of a longer word."""
    text = "Patient Name: Rosa Mark\nPlease remark on the trademark filing."
    out = scrub(text)
    assert "remark" in out
    assert "trademark" in out


def test_a_cvv_does_not_match_inside_an_amount():
    """"837" as a CVV and "837" inside "1,837.00" are a coincidence, not a leak."""
    out = scrub("CVV 837\nTotal 1,837.00", "finance")
    assert "1,837.00" in out


# --------------------------------------------------------------------------
# masking must not leave part of a name visible (314 cases)
# --------------------------------------------------------------------------

def _mask_all(text: str) -> str:
    return scrub(text, default_action=Action.MASK, min_score=0.4)


def test_mask_hides_every_letter_of_a_name():
    out = _mask_all("Patient Name: Margaret Whitfield")
    assert "field" not in out
    assert "ret" not in out


def test_mask_hides_every_letter_of_an_email():
    out = _mask_all("Email: m.whitfield@example.com")
    assert "com" not in out
    assert "@" in out  # the shape survives, the content does not


def test_mask_keeps_the_last_four_of_a_card():
    """The payment-card convention, which is what MASK exists for."""
    assert _mask_all("card 4111 1111 1111 1111").endswith("**** **** **** 1111")


def test_mask_keeps_the_last_four_of_an_aadhaar():
    """UIDAI's own masked Aadhaar shows exactly the last four digits."""
    assert _mask_all("Aadhaar 2366 1728 3069").endswith("**** **** 3069")


# --------------------------------------------------------------------------
# surrogates: day/month order, and collisions
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("paid 15/06/2026 and 05/06/2026", True),      # 15 can only be a day
        ("paid 06/15/2026 and 06/05/2026", False),     # 15 can only be a day
        ("paid 05/06/2026", None),                     # nothing settles it
        ("no dates here", None),
    ],
)
def test_date_order_is_inferred_from_unambiguous_dates(text, expected):
    assert infer_dayfirst(text) is expected


def test_day_first_dates_shift_consistently():
    """Mixing orders in one document broke intervals and caused collisions."""
    surrogator = Surrogator(KEY)
    first = surrogator.surrogate("DATE", "05-06-2026", dayfirst=True)
    second = surrogator.surrogate("DATE", "15-06-2026", dayfirst=True)
    a = dt.datetime.strptime(first, "%d-%m-%Y").date()
    b = dt.datetime.strptime(second, "%d-%m-%Y").date()
    assert (b - a).days == 10  # 5 June to 15 June


def test_a_day_first_statement_restores_every_date_exactly():
    rows = "\n".join(f"{d:02d}-{m:02d}-2026  UPI transfer" for m in (1, 2, 3) for d in (3, 9, 12, 21, 28))
    text = "Transactions\n" + rows
    policy = Policy(name="t", default_action=Action.SURROGATE, min_score=0.4)
    result, vault = Scrubber(policy, hash_key=KEY).scrub(text)
    assert Scrubber.restore(result.text, vault) == text


def test_a_surrogate_never_reuses_text_already_in_the_document():
    """Otherwise restoring a reply rewrites real, unredacted text."""
    surrogator = Surrogator(KEY)
    blocked = surrogator.surrogate("PERSON", "Bob")
    text = f"Patient Name: Bob\nThe chart was reviewed by {blocked} in the lab."
    # 0.5 so the lone first name in the second sentence stays unredacted --
    # that unredacted mention is exactly what the surrogate must not collide with.
    policy = Policy(name="t", default_action=Action.SURROGATE, min_score=0.5)
    result, vault = Scrubber(policy, hash_key=KEY).scrub(text)
    assert blocked in result.text  # the real, unredacted mention is untouched
    assert Scrubber.restore(result.text, vault) == text


def test_a_capitalised_name_gets_a_capitalised_surrogate():
    out = scrub("NAME: VIKRAM DESAI", default_action=Action.SURROGATE, min_score=0.4)
    surrogate = out.removeprefix("NAME: ")
    assert surrogate.isupper()
    assert "VIKRAM" not in surrogate


# --------------------------------------------------------------------------
# encryption is for numbers
# --------------------------------------------------------------------------

@pytest.mark.skipif(not _module_available("cryptography"), reason="needs stripii[crypto]")
def test_encrypt_turns_a_name_into_a_readable_surrogate():
    out = scrub("Patient Name: Margaret Whitfield", default_action=Action.ENCRYPT, min_score=0.4)
    name = out.removeprefix("Patient Name: ")
    assert name.replace(" ", "").replace(".", "").isalpha()  # letters, not "XX9XXX"
    assert "Whitfield" not in name


@pytest.mark.skipif(not _module_available("cryptography"), reason="needs stripii[crypto]")
def test_encrypt_still_enciphers_numeric_identifiers():
    out = scrub("card 4111 1111 1111 1111", default_action=Action.ENCRYPT, min_score=0.4)
    card = out.removeprefix("card ")
    assert card != "4111 1111 1111 1111"
    assert luhn(card)


# --------------------------------------------------------------------------
# restore is a single pass
# --------------------------------------------------------------------------

def test_restore_does_not_rewrite_a_value_it_just_restored():
    vault = Vault()
    vault.mapping = {"Alpha": "Beta Gamma", "Gamma": "Delta"}
    # Sequential replacement would turn "Alpha" into "Beta Gamma" and then the
    # "Gamma" inside that into "Delta".
    assert Scrubber.restore("Alpha", vault) == "Beta Gamma"


# --------------------------------------------------------------------------
# false positives that damaged financial documents
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    ["Closing 2,500.00 Dr", "Opening 14,209.87 Cr", "Fee 50 Dr", "EMI 12,000.00 Dr on 05-06-2026"],
)
def test_debit_and_credit_markers_are_not_street_addresses(text):
    """98 of these in one statement, each eating part of an amount."""
    assert "STREET_ADDRESS" not in {e for e, _ in entities(text)}


def test_a_real_street_address_is_still_found():
    assert ("STREET_ADDRESS", "1847 Oakmont Drive") in entities("lives at 1847 Oakmont Drive")


def test_a_twelve_digit_upi_reference_is_not_an_aadhaar():
    # 236617283069 passes Verhoeff, exactly as a real Aadhaar would.
    assert "AADHAAR" not in {e for e, _ in entities("UPI/236617283069/payment to merchant")}


@pytest.mark.parametrize(
    "text", ["Aadhaar 2366 1728 3069", "Aadhaar No: 236617283069"],
)
def test_an_aadhaar_is_still_found_when_written_as_one(text):
    assert "AADHAAR" in {e for e, _ in entities(text)}


def test_an_iban_must_have_its_countrys_length():
    """mod-97 alone passes one string in 97; India has no IBANs at all."""
    from stripii.checksums import iban

    assert iban("GB82 WEST 1234 5698 7654 32")
    assert not iban("GB82 WEST 1234 5698 7654")      # right checksum family, wrong length
    assert not iban("IN22 1234 5678 9012 34")        # no such country in the registry


@pytest.mark.parametrize(
    "text",
    ["Invoice ref 40000000000006",        # 14 digits, Luhn-valid, no card cue
     "reference 400 00-00000006",         # a grouping no card uses
     "order 9111111111111111"],           # no card begins with 9
)
def test_card_shaped_references_are_not_cards(text):
    assert "CREDIT_CARD" not in {e for e, _ in entities(text)}


def test_a_compact_indian_plate_needs_no_context():
    assert ("LICENSE_PLATE", "KA05MN7319") in entities("PAYMENT RECEIPT KA05MN7319")


def test_a_tan_is_its_own_entity():
    """A generic health-plan pattern also fits; the specific shape must win."""
    assert ("TAN_IN", "MUMA12345B") in entities("TAN of deductor MUMA12345B under the policy")
    assert "[[TAN_IN_1]]" in scrub("TAN of deductor MUMA12345B under the policy")


# --------------------------------------------------------------------------
# pages that are photographs
# --------------------------------------------------------------------------

requires_pdf_tooling = pytest.mark.skipif(
    not all(_module_available(m) for m in ("pdfplumber", "reportlab", "PIL")),
    reason="needs pdfplumber, reportlab and Pillow",
)


def _pdf_with_an_image_page(path):
    """Page 1 is text; page 2 is a picture with a tiny watermark caption."""
    from PIL import Image
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    picture = io.BytesIO()
    Image.new("RGB", (400, 250), "white").save(picture, format="PNG")
    picture.seek(0)

    pdf = canvas.Canvas(str(path), pagesize=letter)
    pdf.drawString(72, 700, "Patient Name: Margaret Whitfield, reviewed today.")
    pdf.drawString(72, 680, "Hemoglobin 10.2 g/dL. Glucose 142 mg/dL. Follow up in two weeks.")
    pdf.showPage()
    pdf.drawImage(ImageReader(picture), 72, 300, width=400, height=250)
    pdf.drawString(72, 280, "Scanned copy")
    pdf.showPage()
    pdf.save()


@requires_pdf_tooling
def test_a_pdf_with_an_image_only_page_is_refused_not_truncated(tmp_path):
    """Half a medical report vanished from the output without a word."""
    from stripii.readers import UnsupportedDocument, read_text

    path = tmp_path / "mixed.pdf"
    _pdf_with_an_image_page(path)
    with pytest.raises(UnsupportedDocument, match=r"page\(s\) 2 .*--ocr"):
        read_text(path)


@pytest.mark.parametrize(
    "narration",
    ["UPI/VIKRAMDESAI/HDFC/1234", "NEFT-DesaiVikram-REF", "IMPS vikramdesai 55"],
)
def test_a_name_written_without_spaces_is_redacted(narration):
    """Payment narrations drop the spaces; the holder's name survived in them."""
    out = scrub(f"Account Holder: Vikram Desai\n{narration}", "finance")
    assert "vikram" not in out.lower()
    assert "desai" not in out.lower()


def test_name_concatenation_needs_the_parts_of_that_name():
    """Only this name's own parts, and only when they add up to a real length."""
    out = scrub("Account Holder: Ravi Das\nPaid RAVIDAS\nThe DASHBOARD shows it", "finance")
    assert "DASHBOARD" in out


@pytest.mark.parametrize(
    ("narration", "name"),
    [("UPI/RAJESHKUMAR/HDFC/1234", "RAJESHKUMAR"), ("NEFT PriyaSharma REF", "PriyaSharma")],
)
def test_a_glued_payee_name_is_redacted_even_if_never_named_otherwise(narration, name):
    """Payees in narrations are often never written any other way."""
    out = scrub(f"Account Holder: Vikram Desai\n{narration}", "finance")
    assert name not in out


@pytest.mark.parametrize("word", ["MARKETING", "JACKSONVILLE", "MARYLAND", "PAYMENTGATEWAY"])
def test_capitalised_words_that_merely_start_with_a_name_are_left_alone(word):
    out = scrub(f"Account Holder: Vikram Desai\nUPI/{word}/HDFC/1234", "finance")
    assert word in out


def test_a_three_part_glued_name_is_redacted():
    out = scrub("Account Holder: Vikram Desai\nUPI/RAJESHKUMARSHARMA/1234", "finance")
    assert "RAJESHKUMARSHARMA" not in out


@pytest.mark.parametrize("word", ["Rosewood", "Maryland", "Carolina", "Markdown", "Jacksonville"])
def test_title_case_words_that_are_not_glued_names_are_left_alone(word):
    out = scrub(f"Account Holder: Vikram Desai\nPaid at {word} store", "finance")
    assert word in out


def test_a_glued_name_written_as_one_title_case_word_is_redacted():
    out = scrub("Account Holder: Vikram Desai\nUPI/grocery Rajeshkumar 1234", "finance")
    assert "Rajeshkumar" not in out


requires_word_list = pytest.mark.skipif(
    not __import__("stripii.engine", fromlist=["_english_words"])._english_words(),
    reason="needs the bundled word list (src/stripii/data/words.txt.gz)",
)


@requires_word_list
def test_a_false_positive_name_does_not_spread_across_the_document():
    """"Name: Test Case" is not a person, and "Test" must not be redacted everywhere."""
    text = "Name: Test Case\nRun the test again, case by case.\nTest results attached. Case closed."
    out = scrub(text, "paranoid")
    # the document itself uses both words in lower case, so neither is a name here
    assert "Test results" in out
    assert "Case closed" in out


def test_a_real_surname_still_spreads():
    text = "Patient Name: Margaret Whitfield\nWhitfield was seen again on review."
    assert "Whitfield" not in scrub(text)


def test_a_lower_case_full_name_is_redacted():
    text = "Account Holder: Priya Iyer\nforwarded by priya iyer via chat"
    assert "priya iyer" not in scrub(text, "finance")


def test_a_surname_inside_a_handle_is_redacted():
    text = "Patient Name: Kavita Deshmukh\ngithub.com/kavitadeshmukh and user kdeshmukh99"
    out = scrub(text)
    assert "deshmukh" not in out.lower()


def test_a_surname_inside_an_ordinary_word_is_left_alone():
    text = "Patient Name: Ravi Patel\nExamination of the patella was normal."
    assert "patella" in scrub(text)


@pytest.mark.parametrize(
    ("first", "again"),
    [
        ("Phone: (415) 555-0132", "call 415.555.0132 after six"),
        ("Phone: (415) 555-0132", "or 4155550132 on the ward line"),
        ("Mobile: 98201 23456", "whatsapp 9820123456 for reports"),
        ("Patient Name: Priya Iyer", "seen by Priya\nIyer on the ward"),
        ("Email: a.rao@clinic.org", "cc a.rao@ clinic.org"),
    ],
)
def test_a_repeated_value_is_caught_despite_different_spacing(first, again):
    out = scrub(f"{first}\n{again}", "paranoid")
    digits_or_words = re.findall(r"[A-Za-z0-9]{3,}", first.split(":", 1)[1])
    assert not any(token in out for token in digits_or_words)


@pytest.mark.parametrize("text", ["Mobile: 9820123456", "Mob. 98201 23456", "Contact 982 012 3456"])
def test_an_indian_mobile_without_country_code_is_detected(text):
    assert "PHONE" in {e for e, _ in entities(text)}


def test_ten_digits_without_a_phone_cue_are_not_a_phone():
    assert "PHONE" not in {e for e, _ in entities("Invoice number 9820123456 dated today")}


def test_a_real_surname_written_in_lower_case_still_spreads():
    """Chat exports lower-case real names; that must not stop them spreading."""
    text = "Patient Name: Kavita Deshmukh\ndeshmukh said ok. deshmukh again.\nDeshmukh: see you"
    assert "Deshmukh" not in scrub(text)
