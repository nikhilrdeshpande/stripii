"""The mapping vault.

The workflow this tool exists for is a round trip:

    scrub report.pdf  ->  paste the redacted text into a model  ->  restore the reply

That only works if the placeholders are stable and reversible, which means the
original values have to be kept somewhere. A vault therefore contains *exactly*
the data the user was trying not to leak, so:

* there is **no vault unless you ask for one** (``--vault``); by default
  scrubbing is one-way and the originals are never written to disk,
* vault files are created ``0600`` before anything is written into them, and
* ``--passphrase`` encrypts the contents with AES-256-GCM (scrypt KDF) when the
  optional ``cryptography`` extra is installed; the command line refuses to
  write an unencrypted vault unless told to with ``--plaintext-vault``.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VAULT_VERSION = 1
_MAGIC = "stripii-vault"

# scrypt parameters: ~64 MB and well above interactive-login cost, because a
# vault is a high-value target that sits on disk indefinitely.
_SCRYPT_N = 2**16
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32
#: A vault passphrase shorter than this is refused: scrypt slows guessing, it
#: does not make a four-letter word safe.
MIN_PASSPHRASE = 8


class VaultError(RuntimeError):
    """Raised when a vault cannot be read, written or decrypted."""


@dataclass
class Vault:
    """A bidirectional map between placeholders and the values they replaced.

    Its repr shows how many entries it holds and never what they are, so a
    vault that ends up in a log line or a traceback does not leak its values.
    """

    #: placeholder -> original text
    mapping: dict[str, str] = field(default_factory=dict, repr=False)
    #: (entity, normalised value) -> placeholder, so repeats reuse one placeholder
    _index: dict[str, str] = field(default_factory=dict, repr=False)
    #: entity -> highest placeholder number issued
    _counters: dict[str, int] = field(default_factory=dict, repr=False)
    meta: dict[str, Any] = field(default_factory=dict)

    # -- allocation ------------------------------------------------------
    @staticmethod
    def _key(entity: str, value: str) -> str:
        return f"{entity}\x00{' '.join(value.split()).casefold()}"

    def placeholder_for(self, entity: str, value: str, template: str) -> str:
        """Return the stable placeholder for ``value``, allocating one if new."""
        key = self._key(entity, value)
        existing = self._index.get(key)
        if existing is not None:
            return existing
        number = self._counters.get(entity, 0) + 1
        self._counters[entity] = number
        placeholder = template.format(entity=entity, n=number)
        self._index[key] = placeholder
        self.mapping[placeholder] = value
        return placeholder

    def record(self, placeholder: str, original: str) -> None:
        """Record a replacement that was not allocated through ``placeholder_for``."""
        self.mapping.setdefault(placeholder, original)

    def __len__(self) -> int:
        return len(self.mapping)

    def __repr__(self) -> str:
        return f"Vault(<{len(self.mapping)} entries>)"

    # -- serialisation ---------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": _MAGIC,
            "version": VAULT_VERSION,
            "meta": self.meta,
            "mapping": self.mapping,
            "index": self._index,
            "counters": self._counters,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Vault:
        if data.get("magic") != _MAGIC:
            raise VaultError("not a stripii vault file")
        if data.get("version") != VAULT_VERSION:
            raise VaultError(
                f"unsupported vault version {data.get('version')!r}; "
                f"this build writes version {VAULT_VERSION}"
            )
        vault = cls(mapping=dict(data.get("mapping", {})), meta=dict(data.get("meta", {})))
        vault._index = dict(data.get("index", {}))
        vault._counters = dict(data.get("counters", {}))
        return vault

    # -- disk ------------------------------------------------------------
    def save(self, path: str | os.PathLike[str], passphrase: str | None = None) -> Path:
        """Write the vault, encrypted under ``passphrase``.

        ``passphrase=None`` writes it in the clear, deliberately; an empty or
        short passphrase is refused rather than taken to mean the same thing.
        """
        if passphrase is not None:
            check_passphrase(passphrase)
        payload = json.dumps(self.to_dict(), ensure_ascii=False, indent=2).encode()
        blob = _encrypt(payload, passphrase) if passphrase is not None else payload
        target = Path(path)
        try:
            write_private(target, blob)
        except OSError as exc:
            raise VaultError(f"cannot write {target}: {exc}") from exc
        return target

    @classmethod
    def load(cls, path: str | os.PathLike[str], passphrase: str | None = None) -> Vault:
        blob = Path(path).read_bytes()
        if blob.lstrip()[:1] == b"{":
            if passphrase:
                raise VaultError(
                    "a passphrase was supplied but this vault is not encrypted"
                )
            payload = blob
        else:
            if not passphrase:
                raise VaultError("this vault is encrypted; supply --passphrase")
            payload = _decrypt(blob, passphrase)
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise VaultError(f"vault file is not valid JSON: {exc}") from exc
        return cls.from_dict(data)


def check_passphrase(passphrase: str) -> None:
    """Refuse a passphrase too short to protect a vault."""
    if not passphrase:
        raise VaultError("the passphrase is empty")
    if len(passphrase) < MIN_PASSPHRASE:
        raise VaultError(f"the passphrase is shorter than {MIN_PASSPHRASE} characters")


def write_private(target: Path, data: bytes) -> None:
    """Write ``data`` to ``target`` readable by the owner only, atomically.

    The bytes go to a new file with a random name in the same folder, created
    exclusively and ``0600`` before anything is written, flushed to disk, then
    renamed over ``target``. Nothing is ever opened through ``target`` itself,
    so a symlink planted there is replaced, not followed; a crash leaves the
    old file or the new one, never half of either.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if hasattr(os, "O_DIRECTORY"):
        try:
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            os.fsync(directory)
        except OSError:
            pass
        finally:
            os.close(directory)


# --------------------------------------------------------------------------
# encryption (optional dependency)
# --------------------------------------------------------------------------

def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except (KeyboardInterrupt, SystemExit):  # pragma: no cover
        raise
    except BaseException as exc:
        # Deliberately BaseException, not ImportError or even Exception: a
        # half-installed `cryptography` (missing cffi backend, ABI mismatch)
        # fails inside its Rust bindings and surfaces as pyo3's PanicException,
        # which inherits from BaseException. A broken optional dependency should
        # produce an actionable message, not a stack trace from a redaction tool.
        raise VaultError(
            "vault encryption needs a working 'cryptography' install "
            f"({type(exc).__name__}: {exc}). "
            "Install it with: pip install 'stripii[crypto]'"
        ) from exc
    return AESGCM


def _derive(passphrase: str, salt: bytes) -> bytes:
    import hashlib

    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_KEY_LEN,
        maxmem=128 * _SCRYPT_N * _SCRYPT_R * 2,
    )


def _encrypt(payload: bytes, passphrase: str) -> bytes:
    aesgcm_cls = _aesgcm()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive(passphrase, salt)
    ciphertext = aesgcm_cls(key).encrypt(nonce, payload, _MAGIC.encode())
    envelope = {
        "magic": _MAGIC,
        "version": VAULT_VERSION,
        "kdf": {"name": "scrypt", "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P},
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return b"STRIPII1\n" + json.dumps(envelope, indent=2).encode()


def _decrypt(blob: bytes, passphrase: str) -> bytes:
    aesgcm_cls = _aesgcm()
    if not blob.startswith(b"STRIPII1\n"):
        raise VaultError("unrecognised vault format")
    try:
        envelope = json.loads(blob[len(b"STRIPII1\n"):])
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        kdf = envelope.get("kdf", {})
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        raise VaultError(f"corrupt vault envelope: {exc}") from exc
    import hashlib

    key = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=int(kdf.get("n", _SCRYPT_N)),
        r=int(kdf.get("r", _SCRYPT_R)),
        p=int(kdf.get("p", _SCRYPT_P)),
        dklen=_KEY_LEN,
        maxmem=128 * int(kdf.get("n", _SCRYPT_N)) * int(kdf.get("r", _SCRYPT_R)) * 2,
    )
    try:
        return aesgcm_cls(key).decrypt(nonce, ciphertext, _MAGIC.encode())
    except Exception as exc:  # cryptography raises InvalidTag
        raise VaultError("wrong passphrase, or the vault has been tampered with") from exc
