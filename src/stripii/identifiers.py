"""The saved identifier list: the user's own values, kept encrypted.

The list is exactly the data the tool exists to keep private -- the user's
name, their family's, their account numbers -- so it is never on disk in the
clear. It is encrypted with AES-256-GCM under a random 32-byte key, and the
key lives in the operating system's credential store (the macOS Keychain,
through ``keyring``), not beside the file. Reading the file gives nothing;
reading the Keychain entry gives nothing without the file.

    from stripii.identifiers import IdentifierStore

    store = IdentifierStore()          # default path, key from the Keychain
    store.add("Margaret Whitfield")
    store.values()                     # ["Margaret Whitfield"]

    redact_file(path, identifiers=store.values())

Callers that manage the key themselves (tests, a CLI run with no Keychain)
pass ``key=``. The file format is a small JSON envelope, versioned, with the
nonce and ciphertext base64-encoded; it is created ``0600``.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import sys
from pathlib import Path

from .vault import VaultError, _aesgcm, write_private

STORE_VERSION = 1
_MAGIC = "stripii-identifiers"
_KEY_LEN = 32

#: Where the key is kept in the credential store.
KEYCHAIN_SERVICE = "stripii"
KEYCHAIN_ACCOUNT = "identifier-list-key"


class IdentifierStoreError(RuntimeError):
    """Raised when the list cannot be read, written or unlocked."""


def default_path() -> Path:
    """Where the list lives: the platform's per-user application data folder.

    Inside a sandboxed Mac app ``Path.home()`` is the app's container, which
    is exactly where this belongs.
    """
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "stripii" / "identifiers.enc"


def keychain_key(*, create: bool = True) -> bytes:
    """The list's key from the credential store, made on first use.

    Needs ``keyring`` (``pip install 'stripii[keychain]'``). The key is stored
    base64-encoded under one service/account pair, so it can be inspected and
    deleted with Keychain Access like any other app password.
    """
    try:
        import keyring
        from keyring.errors import KeyringError
    except ImportError as exc:
        raise IdentifierStoreError(
            "keeping the identifier list needs the credential store: "
            "pip install 'stripii[keychain]'"
        ) from exc
    try:
        stored = keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        if stored:
            return base64.b64decode(stored)
        if not create:
            raise IdentifierStoreError("no identifier-list key in the credential store")
        key = secrets.token_bytes(_KEY_LEN)
        keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, base64.b64encode(key).decode())
        return key
    except KeyringError as exc:
        raise IdentifierStoreError(f"the credential store refused: {exc}") from exc


def forget_keychain_key() -> None:
    """Remove the key. Whatever the list held is unrecoverable afterwards."""
    try:
        import keyring
        from keyring.errors import KeyringError, PasswordDeleteError
    except ImportError:
        return
    with contextlib.suppress(PasswordDeleteError, KeyringError):
        keyring.delete_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)


def encrypt(values: list[str], key: bytes) -> bytes:
    if len(key) != _KEY_LEN:
        raise IdentifierStoreError(f"the key must be {_KEY_LEN} bytes")
    try:
        aesgcm_cls = _aesgcm()
    except VaultError as exc:
        raise IdentifierStoreError(str(exc)) from exc
    nonce = secrets.token_bytes(12)
    payload = json.dumps({"identifiers": values}, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm_cls(key).encrypt(nonce, payload, _MAGIC.encode())
    envelope = {
        "magic": _MAGIC,
        "version": STORE_VERSION,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(envelope, indent=2).encode()


def decrypt(blob: bytes, key: bytes) -> list[str]:
    try:
        aesgcm_cls = _aesgcm()
    except VaultError as exc:
        raise IdentifierStoreError(str(exc)) from exc
    try:
        envelope = json.loads(blob)
        if envelope.get("magic") != _MAGIC:
            raise ValueError("not an identifier list")
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        raise IdentifierStoreError(f"corrupt identifier list: {exc}") from exc
    try:
        payload = aesgcm_cls(key).decrypt(nonce, ciphertext, _MAGIC.encode())
    except Exception as exc:  # cryptography raises InvalidTag
        raise IdentifierStoreError(
            "wrong key, or the identifier list has been tampered with"
        ) from exc
    values = json.loads(payload.decode("utf-8")).get("identifiers", [])
    return [str(v) for v in values]


class IdentifierStore:
    """The saved list, read on first use and written back on every change."""

    def __init__(self, path: str | os.PathLike[str] | None = None, *, key: bytes | None = None):
        self.path = Path(path) if path is not None else default_path()
        self._key = key
        self._values: list[str] | None = None

    def __repr__(self) -> str:
        return f"IdentifierStore({str(self.path)!r})"

    @property
    def key(self) -> bytes:
        if self._key is None:
            self._key = keychain_key()
        return self._key

    def values(self) -> list[str]:
        if self._values is None:
            self._values = self._read()
        return list(self._values)

    def _read(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            return decrypt(self.path.read_bytes(), self.key)
        except OSError as exc:
            raise IdentifierStoreError(f"cannot read {self.path}: {exc}") from exc

    def _write(self, values: list[str]) -> None:
        data = encrypt(values, self.key)
        # A fresh 0600 file with a random name, fsynced, then renamed over the
        # list: a crash never leaves half a list, and a symlink is not followed.
        try:
            write_private(self.path, data)
        except OSError as exc:
            raise IdentifierStoreError(f"cannot write {self.path}: {exc}") from exc
        self._values = list(values)

    def add(self, value: str) -> bool:
        """Add one identifier. Returns False if an equivalent one is already listed."""
        value = " ".join(value.split())
        if not value:
            return False
        current = self.values()
        if any(v.casefold() == value.casefold() for v in current):
            return False
        self._write([*current, value])
        return True

    def remove(self, value: str) -> bool:
        """Remove by value (case-insensitive). Returns False if it was not listed."""
        wanted = " ".join(value.split()).casefold()
        current = self.values()
        kept = [v for v in current if v.casefold() != wanted]
        if len(kept) == len(current):
            return False
        self._write(kept)
        return True

    def replace(self, values: list[str]) -> None:
        cleaned: list[str] = []
        for value in values:
            value = " ".join(value.split())
            if value and not any(v.casefold() == value.casefold() for v in cleaned):
                cleaned.append(value)
        self._write(cleaned)

    def clear(self) -> None:
        self._write([])

    def __len__(self) -> int:
        return len(self.values())
