"""Vault storage: permissions, round trips, encryption and refusals."""

from __future__ import annotations

import json
import os
import stat

import pytest

from stripii import Vault, VaultError

from .conftest import requires_crypto

TEMPLATE = "[[{entity}_{n}]]"


def _populated() -> Vault:
    vault = Vault()
    vault.placeholder_for("PERSON", "Jane Smith", TEMPLATE)
    vault.placeholder_for("SSN", "412-88-9031", TEMPLATE)
    return vault


def test_placeholders_are_allocated_once_per_value():
    vault = _populated()
    assert vault.placeholder_for("PERSON", "Jane Smith", TEMPLATE) == "[[PERSON_1]]"
    assert len(vault) == 2


def test_placeholder_lookup_ignores_case_and_extra_whitespace():
    vault = Vault()
    first = vault.placeholder_for("PERSON", "Jane Smith", TEMPLATE)
    assert vault.placeholder_for("PERSON", "jane   smith", TEMPLATE) == first


def test_counters_are_per_entity():
    vault = _populated()
    assert vault.mapping["[[PERSON_1]]"] == "Jane Smith"
    assert vault.mapping["[[SSN_1]]"] == "412-88-9031"


def test_plaintext_round_trip(tmp_path):
    path = _populated().save(tmp_path / "v.json")
    assert Vault.load(path).mapping == _populated().mapping


def test_vault_files_are_owner_only(tmp_path):
    path = _populated().save(tmp_path / "v.json")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_saving_creates_missing_directories(tmp_path):
    path = _populated().save(tmp_path / "nested" / "deeper" / "v.json")
    assert path.exists()


def test_loading_a_foreign_json_file_is_refused(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(VaultError, match="not a stripii vault"):
        Vault.load(path)


def test_loading_an_unsupported_version_is_refused(tmp_path):
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"magic": "stripii-vault", "version": 99, "mapping": {}}))
    with pytest.raises(VaultError, match="unsupported vault version"):
        Vault.load(path)


def test_corrupt_json_is_refused(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(VaultError):
        Vault.load(path)


PASS = "correct horse battery staple"


# --------------------------------------------------------------------------
# encryption
# --------------------------------------------------------------------------

@requires_crypto
def test_encrypted_round_trip(tmp_path):
    path = _populated().save(tmp_path / "v.enc", "correct horse battery staple")
    loaded = Vault.load(path, "correct horse battery staple")
    assert loaded.mapping["[[PERSON_1]]"] == "Jane Smith"


@requires_crypto
def test_ciphertext_does_not_contain_the_plaintext(tmp_path):
    path = _populated().save(tmp_path / "v.enc", PASS)
    blob = path.read_bytes()
    assert b"Jane Smith" not in blob
    assert b"412-88-9031" not in blob


@requires_crypto
def test_wrong_passphrase_is_rejected(tmp_path):
    path = _populated().save(tmp_path / "v.enc", "the right passphrase")
    with pytest.raises(VaultError, match="wrong passphrase"):
        Vault.load(path, "the wrong passphrase")


@requires_crypto
def test_tampered_ciphertext_is_rejected(tmp_path):
    """AES-GCM authenticates, so an edited vault fails rather than decoding."""
    path = _populated().save(tmp_path / "v.enc", PASS)
    envelope = json.loads(path.read_bytes().split(b"\n", 1)[1])
    first = envelope["ciphertext"][0]
    envelope["ciphertext"] = ("B" if first == "A" else "A") + envelope["ciphertext"][1:]
    path.write_bytes(b"STRIPII1\n" + json.dumps(envelope).encode())
    with pytest.raises(VaultError):
        Vault.load(path, PASS)


@requires_crypto
def test_encrypted_vault_without_a_passphrase_says_so(tmp_path):
    path = _populated().save(tmp_path / "v.enc", PASS)
    with pytest.raises(VaultError, match="encrypted"):
        Vault.load(path)


@requires_crypto
def test_passphrase_on_a_plaintext_vault_says_so(tmp_path):
    path = _populated().save(tmp_path / "v.json")
    with pytest.raises(VaultError, match="not encrypted"):
        Vault.load(path, PASS)


# --------------------------------------------------------------------------
# hardening
# --------------------------------------------------------------------------

def test_the_repr_of_a_vault_shows_no_value():
    vault = _populated()
    for text in (repr(vault), str(vault)):
        assert "Jane Smith" not in text and "412-88-9031" not in text
    assert str(len(vault)) in repr(vault)


@pytest.mark.parametrize("passphrase", ["", "short"])
def test_an_empty_or_short_passphrase_is_refused(tmp_path, passphrase):
    path = tmp_path / "v.enc"
    with pytest.raises(VaultError, match="passphrase"):
        _populated().save(path, passphrase)
    assert not path.exists()


def test_a_save_is_atomic_and_private(tmp_path):
    import stat

    path = tmp_path / "v.json"
    path.write_text("old")
    _populated().save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert Vault.load(path).mapping["[[PERSON_1]]"] == "Jane Smith"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["v.json"]   # no temp file left


def test_a_save_does_not_write_through_a_symlink(tmp_path):
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("untouched")
    link = tmp_path / "v.json"
    link.symlink_to(elsewhere)
    _populated().save(link)
    assert elsewhere.read_text() == "untouched"
    assert not link.is_symlink()
    assert Vault.load(link).mapping["[[PERSON_1]]"] == "Jane Smith"
