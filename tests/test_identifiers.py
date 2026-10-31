"""The user's own identifiers: found in every written form, and kept encrypted.

Two claims. First, a name or number the user listed is redacted however the
document writes it -- capitals, glued, initials, inside an email. Second, the
list itself never touches the disk in the clear, and the file alone is
useless without the key from the credential store.
"""

from __future__ import annotations

import base64
import io
import json
import os
import stat

import pytest

from stripii import Scrubber, scrub_text
from stripii.detectors.identifiers import IdentifierRecognizer
from stripii.identifiers import (
    IdentifierStore,
    IdentifierStoreError,
    decrypt,
    default_path,
    encrypt,
    keychain_key,
)

from .conftest import requires_crypto

# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------

def _redact(text: str, identifiers: list[str]) -> str:
    result, _ = scrub_text(text, profile="paranoid", identifiers=identifiers)
    return result.text


@pytest.mark.parametrize("written", [
    "Margaret Whitfield",
    "MARGARET WHITFIELD",
    "margaret whitfield",
    "Margaret-Whitfield",
    "MargaretWhitfield",
    "WhitfieldMargaret",
    "Whitfield, Margaret",
    "M. Whitfield",
    "M Whitfield",
    "Mrs Whitfield",
    "whitfield",
    "Margaret",
])
def test_a_listed_name_is_found_however_it_is_written(written):
    text = f"Note for {written} about the results.\n"
    out = _redact(text, ["Margaret Whitfield"])
    assert "whitfield" not in out.lower()
    assert "margaret" not in out.lower()
    assert "about the results" in out


def test_a_listed_name_is_found_inside_handles_and_addresses():
    text = "Sent to mwhitfield@example.com and paid via whitfield1934@upi.\n"
    out = _redact(text, ["Margaret Whitfield"])
    assert "whitfield" not in out.lower()


def test_short_parts_are_not_hunted_on_their_own():
    """"Li" alone would be every "li"; the whole name still is."""
    text = "Wei Li signed. The list is long, and so is the limit.\n"
    out = _redact(text, ["Wei Li"])
    assert "Wei Li" not in out
    assert "list is long" in out and "limit" in out


def test_titles_and_initials_in_the_listed_value_are_ignored():
    out = _redact("Dr Whitfield and M. E. Whitfield both signed.\n", ["Dr. M. E. Whitfield"])
    assert "Whitfield" not in out
    assert "both signed" in out


def test_a_listed_number_is_found_with_or_without_separators():
    text = "Card 5544 3322 1100 9900, also 5544-3322-1100-9900 and 5544332211009900.\n"
    out = _redact(text, ["5544 3322 1100 9900"])
    assert "5544" not in out and "9900" not in out
    assert out.count("[[IDENTIFIER_") == 3


def test_a_listed_email_is_found_in_any_casing():
    out = _redact("Reply to M.Whitfield@Example.COM please.\n", ["m.whitfield@example.com"])
    assert "example" not in out.lower()


def test_an_english_word_surname_is_redacted_when_listed():
    """The survivor on the real documents: unlabelled, lower-case, an English word."""
    text = "thanks hunter, see you at 4. the hunter gathers.\n"
    plain, _ = scrub_text(text, profile="paranoid")
    assert "hunter" in plain.text
    out = _redact(text, ["Hunter"])
    assert "hunter" not in out


def test_listed_names_count_as_names_and_get_the_person_placeholder():
    result, vault = scrub_text("From Margaret Whitfield.\n", profile="health",
                               identifiers=["Margaret Whitfield"])
    assert result.counts == {"PERSON": 1}
    assert "[[PERSON_1]]" in result.text
    assert Scrubber.restore(result.text, vault) == "From Margaret Whitfield.\n"


def test_blank_and_duplicate_entries_are_harmless():
    recognizer = IdentifierRecognizer(["", "   ", "Whitfield", "Whitfield"])
    assert recognizer.identifiers == ["Whitfield", "Whitfield"]
    assert list(recognizer.detect("nothing here")) == []


def test_the_health_profile_still_keeps_clinical_content(health_text):
    result, _ = scrub_text(health_text, profile="health",
                           identifiers=["Margaret Ellen Whitfield", "4471982"])
    assert "Whitfield" not in result.text and "4471982" not in result.text
    assert "Hemoglobin 10.2 g/dL" in result.text


# --------------------------------------------------------------------------
# the encrypted store
# --------------------------------------------------------------------------

KEY = bytes(range(32))


@requires_crypto
def test_the_list_round_trips_and_is_never_on_disk_in_the_clear(tmp_path):
    path = tmp_path / "ids.enc"
    store = IdentifierStore(path, key=KEY)
    assert store.values() == []
    assert store.add("Margaret Whitfield")
    assert store.add("4471982")
    assert not store.add("margaret  whitfield")          # same value, different form
    raw = path.read_bytes()
    assert b"Whitfield" not in raw and b"4471982" not in raw
    assert json.loads(raw)["magic"] == "stripii-identifiers"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob("*.tmp"))

    again = IdentifierStore(path, key=KEY)
    assert again.values() == ["Margaret Whitfield", "4471982"]
    assert again.remove("MARGARET WHITFIELD")
    assert not again.remove("nobody")
    assert IdentifierStore(path, key=KEY).values() == ["4471982"]
    again.clear()
    assert len(IdentifierStore(path, key=KEY)) == 0


@requires_crypto
def test_the_wrong_key_and_a_tampered_file_are_refused(tmp_path):
    path = tmp_path / "ids.enc"
    IdentifierStore(path, key=KEY).add("Margaret Whitfield")
    with pytest.raises(IdentifierStoreError, match="wrong key"):
        IdentifierStore(path, key=bytes(32)).values()
    envelope = json.loads(path.read_bytes())
    tampered = bytearray(base64.b64decode(envelope["ciphertext"]))
    tampered[0] ^= 0xFF
    envelope["ciphertext"] = base64.b64encode(bytes(tampered)).decode()
    path.write_text(json.dumps(envelope))
    with pytest.raises(IdentifierStoreError, match="tampered"):
        IdentifierStore(path, key=KEY).values()
    path.write_text("{}")
    with pytest.raises(IdentifierStoreError, match="corrupt"):
        IdentifierStore(path, key=KEY).values()


@requires_crypto
def test_keys_must_be_the_right_length():
    with pytest.raises(IdentifierStoreError, match="32 bytes"):
        encrypt(["x"], b"short")
    assert decrypt(encrypt(["a", "b"], KEY), KEY) == ["a", "b"]


@requires_crypto
def test_replace_deduplicates_and_drops_blanks(tmp_path):
    store = IdentifierStore(tmp_path / "ids.enc", key=KEY)
    store.replace(["A B", "", "a b", " C "])
    assert store.values() == ["A B", "C"]


def test_the_default_path_is_per_user_and_inside_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    path = default_path()
    assert path.name == "identifiers.enc"
    assert str(tmp_path) in str(path)


class _FakeKeyring:
    """An in-memory credential store standing in for the Keychain."""

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], str] = {}

    def get_password(self, service, account):
        return self.entries.get((service, account))

    def set_password(self, service, account, value):
        self.entries[(service, account)] = value

    def delete_password(self, service, account):
        del self.entries[(service, account)]


@requires_crypto
def test_the_key_comes_from_the_credential_store_and_is_made_once(monkeypatch, tmp_path):
    keyring = pytest.importorskip("keyring")
    fake = _FakeKeyring()
    monkeypatch.setattr(keyring, "get_password", fake.get_password)
    monkeypatch.setattr(keyring, "set_password", fake.set_password)
    monkeypatch.setattr(keyring, "delete_password", fake.delete_password)

    first = keychain_key()
    assert len(first) == 32
    assert keychain_key() == first                     # stable
    assert len(fake.entries) == 1                       # one entry, base64
    assert base64.b64decode(next(iter(fake.entries.values()))) == first

    store = IdentifierStore(tmp_path / "ids.enc")       # no key given: the store fetches it
    store.add("Margaret Whitfield")
    assert IdentifierStore(tmp_path / "ids.enc").values() == ["Margaret Whitfield"]

    from stripii.identifiers import forget_keychain_key

    forget_keychain_key()
    assert fake.entries == {}
    with pytest.raises(IdentifierStoreError, match="no identifier-list key"):
        keychain_key(create=False)


@requires_crypto
def test_the_cli_manages_the_list_and_scrubs_with_it(tmp_path, capsys, monkeypatch):
    from stripii.cli import main

    monkeypatch.setattr("stripii.identifiers.keychain_key", lambda create=True: KEY)
    path = tmp_path / "ids.enc"
    assert main(["identifiers", "add", "Margaret Whitfield", "--file", str(path)]) == 0
    assert main(["identifiers", "list", "--file", str(path)]) == 0
    out = capsys.readouterr()
    assert "Whitfield" not in out.out and "Xxxxxxxx Xxxxxxxxx" in out.out
    assert main(["identifiers", "list", "--file", str(path), "--show-values"]) == 0
    assert "Margaret Whitfield" in capsys.readouterr().out

    monkeypatch.setattr("stripii.identifiers.default_path", lambda: path)
    source = tmp_path / "note.txt"
    source.write_text("thanks whitfield, see you.\n", encoding="utf-8")
    assert main(["scrub", str(source), "--stdout", "-q", "-p", "paranoid"]) == 0
    assert "whitfield" in capsys.readouterr().out
    assert main(["scrub", str(source), "--stdout", "-q", "-p", "paranoid",
                 "--saved-identifiers"]) == 0
    assert "whitfield" not in capsys.readouterr().out

    assert main(["identifiers", "remove", "margaret whitfield", "--file", str(path)]) == 0
    assert main(["identifiers", "clear", "--file", str(path)]) == 0
    assert IdentifierStore(path, key=KEY).values() == []
    assert os.path.exists(path)


@requires_crypto
def test_a_write_does_not_follow_a_symlink(tmp_path):
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("untouched")
    path = tmp_path / "ids.enc"
    path.symlink_to(elsewhere)
    IdentifierStore(path, key=KEY).replace(["Harold Pennington"])
    assert elsewhere.read_text() == "untouched"
    assert IdentifierStore(path, key=KEY).values() == ["Harold Pennington"]


def test_the_store_repr_shows_no_value(tmp_path):
    store = IdentifierStore(tmp_path / "ids.enc", key=KEY)
    store._values = ["Harold Pennington"]
    assert "Pennington" not in repr(store)


class _Stdin(io.StringIO):
    def __init__(self, text, tty=False):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


@requires_crypto
def test_identifiers_can_be_added_from_stdin_without_argv(tmp_path, capsys, monkeypatch):
    from stripii.cli import main

    path = tmp_path / "ids.enc"
    monkeypatch.setattr("stripii.identifiers.keychain_key", lambda create=True: KEY)
    monkeypatch.setattr("sys.stdin", _Stdin("Harold Pennington\n\n4471982\n"))
    assert main(["identifiers", "add", "-", "--file", str(path)]) == 0
    assert IdentifierStore(path, key=KEY).values() == ["Harold Pennington", "4471982"]
    assert "shell history" not in capsys.readouterr().err

    # with no value and a pipe, the values come from stdin too
    monkeypatch.setattr("sys.stdin", _Stdin("Theodore Ashcombe\n"))
    assert main(["identifiers", "add", "--file", str(path)]) == 0
    assert "Theodore Ashcombe" in IdentifierStore(path, key=KEY).values()


@requires_crypto
def test_identifiers_are_prompted_for_at_a_terminal(tmp_path, capsys, monkeypatch):
    from stripii.cli import main

    path = tmp_path / "ids.enc"
    monkeypatch.setattr("stripii.identifiers.keychain_key", lambda create=True: KEY)
    monkeypatch.setattr("sys.stdin", _Stdin("", tty=True))
    answers = iter(["Harold Pennington", "078-05-1120", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert main(["identifiers", "add", "--file", str(path)]) == 0
    assert IdentifierStore(path, key=KEY).values() == ["Harold Pennington", "078-05-1120"]


@requires_crypto
def test_identifiers_on_argv_still_work_but_warn(tmp_path, capsys, monkeypatch):
    from stripii.cli import main

    path = tmp_path / "ids.enc"
    monkeypatch.setattr("stripii.identifiers.keychain_key", lambda create=True: KEY)
    assert main(["identifiers", "add", "Harold Pennington", "--file", str(path)]) == 0
    assert "shell history" in capsys.readouterr().err
    assert IdentifierStore(path, key=KEY).values() == ["Harold Pennington"]


def test_the_identifier_flag_warns_and_a_file_does_not(tmp_path, capsys):
    from stripii.cli import main

    source = tmp_path / "note.txt"
    source.write_text("thanks pennington, see you.\n")
    assert main(["scrub", str(source), "--stdout", "-q", "--identifier", "Harold Pennington"]) == 0
    captured = capsys.readouterr()
    assert "pennington" not in captured.out and "shell history" in captured.err

    listed = tmp_path / "mine.txt"
    listed.write_text("Harold Pennington\n")
    assert main(["scrub", str(source), "--stdout", "-q", "--identifier-file", str(listed)]) == 0
    captured = capsys.readouterr()
    assert "pennington" not in captured.out and "shell history" not in captured.err
