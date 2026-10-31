"""Command line interface.

Design notes that matter more than they look:

* the redacted document goes to **stdout**, every report and warning to
  **stderr**, so ``stripii scrub report.txt | pbcopy`` does the obvious thing;
* reports show entity types and positions but **not the values found**, unless
  you ask with ``--show-values`` -- a findings report that quotes the SSN it
  found is the same leak in a smaller font;
* passphrases are never taken as an argument, because arguments are visible in
  ``ps`` and land in shell history.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from getpass import getpass
from pathlib import Path

from . import __version__
from .benchmark import MATCH_MODES
from .detectors.patterns import ALL_ENTITIES
from .document import GRADE_WORDS, STYLES, RedactionResult, _scrub_structured, redact_file
from .document import build_policy as style_policy
from .engine import Scrubber, default_recognizers
from .identifiers import IdentifierStore, IdentifierStoreError, forget_keychain_key
from .ocr import BACKEND_NAMES, OcrUnavailable
from .policy import PROFILES, Policy, get_profile
from .proxy import DEFAULT_UPSTREAM
from .readers import (
    UnsupportedDocument,
    csv_delimiter,
    kind_of,
    pdf_pages_with_images,
    read_text,
)
from .types import Action, ScrubResult
from .vault import Vault, VaultError, check_passphrase

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SECRET_ENTITIES = frozenset({"PRIVATE_KEY", "AWS_ACCESS_KEY", "API_TOKEN", "JWT"})

#: Produced only when the optional spaCy backend is enabled with --ner. They are
#: still valid targets for --set and --disable so that --ner users can steer them.
NER_ONLY_ENTITIES = frozenset({"LOCATION", "ORGANIZATION"})


def known_entities() -> frozenset[str]:
    return frozenset(ALL_ENTITIES) | NER_ONLY_ENTITIES | {"PERSON", "IDENTIFIER"}


def _err(message: str) -> None:
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------
# policy assembly
# --------------------------------------------------------------------------

def build_policy(args: argparse.Namespace) -> Policy:
    policy = Policy.load(args.policy) if args.policy else get_profile(args.profile)
    actions = dict(policy.actions)
    disabled = set(policy.disabled)

    for override in args.set or []:
        if "=" not in override:
            raise ValueError(f"--set expects ENTITY=action, got {override!r}")
        entity, _, action = override.partition("=")
        entity = entity.strip().upper()
        if entity not in known_entities():
            raise ValueError(f"unknown entity {entity!r}; see `stripii entities`")
        try:
            actions[entity] = Action(action.strip().lower())
        except ValueError:
            valid = ", ".join(a.value for a in Action)
            raise ValueError(f"unknown action {action!r}; valid actions: {valid}") from None

    for entity in args.disable or []:
        disabled.add(entity.strip().upper())

    # --style rewrites only the entities a profile would REDACT. Generalisation
    # and masking decisions are left alone, because they are about how much
    # information to keep rather than about what a replacement should look like.
    return style_policy(
        Policy(
            name=policy.name,
            description=policy.description,
            default_action=policy.default_action,
            actions=actions,
            min_score=args.min_score if args.min_score is not None else policy.min_score,
            disabled=frozenset(disabled),
            placeholder=args.placeholder or policy.placeholder,
            mask_keep=policy.mask_keep,
        ),
        getattr(args, "style", "placeholder") or "placeholder",
    )


ARGV_WARNING = (
    "warning: {what} on the command line is visible to other users in `ps` and "
    "is saved in your shell history. Prefer {better}."
)


def _read_lines(stream) -> list[str]:
    return [line.strip() for line in stream.read().splitlines() if line.strip()]


def _identifier_file(spec: str) -> list[str]:
    if spec == "-":
        return _read_lines(sys.stdin)
    with open(spec, encoding="utf-8") as handle:
        return _read_lines(handle)


def resolve_identifiers(args: argparse.Namespace) -> list[str]:
    """``--identifier`` and ``--identifier-file`` values, plus the saved list if asked.

    Resolved once per run and cached on ``args``: a file read from stdin can
    only be read once, and the warning should be printed once.
    """
    cached = getattr(args, "_identifiers", None)
    if cached is not None:
        return list(cached)
    values = list(getattr(args, "identifier", None) or [])
    if values:
        _err(ARGV_WARNING.format(what="--identifier",
                                 better="--identifier-file, or `stripii identifiers add`"))
    spec = getattr(args, "identifier_file", None)
    if spec:
        if spec == "-" and "-" in (getattr(args, "inputs", None) or []):
            raise ValueError("--identifier-file - and an input of - cannot both read stdin")
        values.extend(_identifier_file(spec))
    if getattr(args, "saved_identifiers", False):
        values.extend(IdentifierStore().values())
    args._identifiers = values
    return list(values)


def resolve_keys(args: argparse.Namespace) -> bytes | None:
    """The root secret for hashing, surrogates and format-preserving encryption.

    Without one these are seeded randomly per run, which is fine for
    placeholders but means a hash or an encrypted value will not match across
    runs. Supply it through the environment, never as an argument.

    The value should be random -- ``openssl rand -base64 32`` -- not a word: a
    hash or an encrypted value can be tested against guesses offline by anyone
    holding the output. It is stretched with scrypt, which slows guessing but
    cannot make a guessable secret safe.
    """
    name = getattr(args, "key_env", None)
    if not name:
        return None
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"environment variable {name} is unset or empty")
    return derive_key(value)


#: The fixed salt for --key-env. The secret is meant to be random, so the salt
#: only separates this use of it from any other; scrypt adds the work factor.
KEY_ENV_SALT = b"stripii --key-env v1"


@functools.lru_cache(maxsize=4)
def derive_key(secret: str) -> bytes:
    """The 32-byte root key from a ``--key-env`` secret (scrypt, n=2**15, r=8)."""
    return hashlib.scrypt(secret.encode("utf-8"), salt=KEY_ENV_SALT, n=2**15, r=8, p=1,
                          dklen=32, maxmem=64 * 1024 * 1024)


def resolve_passphrase(args: argparse.Namespace, *, creating: bool = False) -> str | None:
    """The vault passphrase, from the environment or a prompt; never an argument.

    ``creating`` is for writing a vault: the passphrase must be at least
    ``MIN_PASSPHRASE`` characters, and a prompted one is asked for twice.
    """
    value: str | None = None
    if getattr(args, "passphrase_env", None):
        value = os.environ.get(args.passphrase_env)
        if not value:
            raise ValueError(f"environment variable {args.passphrase_env} is unset or empty")
    elif getattr(args, "passphrase", False):
        value = getpass("Vault passphrase: ")
        if creating and value and getpass("Same passphrase again: ") != value:
            raise ValueError("the passphrases do not match")
    if value is None:
        return None
    if creating:
        try:
            check_passphrase(value)
        except VaultError as exc:
            raise ValueError(f"{exc}; a vault holds the original values") from None
    elif not value:
        raise ValueError("the passphrase is empty")
    return value


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def render_report(path: str, result: ScrubResult, *, show_values: bool) -> str:
    lines = [f"{path}: {result.total} replacement(s)"]
    if not result.total:
        lines.append("  no personal data detected")
    for entity, count in result.counts.items():
        lines.append(f"  {entity:<18} {count:>4}")
    if show_values:
        lines.append("  --- values ---")
        for replacement in result.replacements:
            d = replacement.detection
            lines.append(
                f"  @{d.start:<7} {d.entity:<18} {d.score:.2f} "
                f"{d.detector:<22} {d.raw!r} -> {replacement.text!r}"
            )
    below = [d for d in result.skipped if d.score > 0]
    if below:
        lines.append(
            f"  ({len(below)} candidate(s) not replaced: below min-score, or the "
            f"profile keeps them; inspect with --show-values, act on them with "
            f"--min-score)"
        )
    return "\n".join(lines)


def report_json(path: str, result: ScrubResult, *, show_values: bool) -> dict:
    def entry(det, action=None, text=None):
        out = {
            "entity": det.entity,
            "start": det.start,
            "end": det.end,
            "score": round(det.score, 3),
            "detector": det.detector,
        }
        if action:
            out["action"] = action
        if show_values:
            out["value"] = det.raw
            if text is not None:
                out["replacement"] = text
        return out

    return {
        "path": path,
        "total": result.total,
        "counts": result.counts,
        "replacements": [
            entry(r.detection, r.action.value, r.text) for r in result.replacements
        ],
        "skipped": [entry(d) for d in result.skipped],
    }


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

#: Formats OCR can read, and formats a redacted image can be written back to.
OCR_KINDS = {"pdf", "image"}
IMAGE_OUTPUTS = {".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff"}


def _warn_unreadable(spec: str, pages: list[int]) -> None:
    """Say so when OCR could barely read a page.

    Zero findings on a page OCR could not read means "not checked", not
    "clean" -- a photographed ID card came back as three words of watermark.
    """
    if pages:
        listed = ", ".join(str(p) for p in pages)
        _err(
            f"warning: {spec}: OCR recognised almost nothing on page(s) {listed}. "
            "Findings for those pages cannot be trusted; check them by eye, or "
            "rescan them flatter and at higher resolution."
        )


def _warn_images(spec: str) -> None:
    """Say so when a PDF read from its text layer also has images on its pages."""
    if spec == "-" or kind_of(Path(spec)) != "pdf":
        return
    try:
        pages = pdf_pages_with_images(Path(spec))
    except Exception:  # a warning must never be what breaks a run
        return
    if pages:
        listed = ", ".join(str(p) for p in pages)
        _err(
            f"warning: {spec}: page(s) {listed} carry images or form fields, whose "
            "content is not in the text layer and so is missing from this output. "
            "Add --ocr to read them, or write a .pdf to have them read and redacted."
        )


def _load_input(spec: str, fmt: str = "auto") -> tuple[str, str]:
    """Return ``(text, kind)`` for a path or ``-`` meaning stdin.

    ``fmt`` overrides the kind inferred from the extension, which is the only
    way to get structural handling for piped input -- stdin has no filename.
    """
    if spec == "-":
        return sys.stdin.read(), "text" if fmt == "auto" else fmt
    path = Path(spec)
    if not path.exists():
        raise FileNotFoundError(f"no such file: {spec}")
    text = read_text(path)
    return text, kind_of(path) if fmt == "auto" else fmt


def _scrub_document(
    scrubber: Scrubber, text: str, kind: str, vault: Vault, spec: str = "-"
):
    """Scrub, preserving JSON/CSV structure where that applies."""
    if kind in {"json", "csv"}:
        delimiter = csv_delimiter(None if spec == "-" else Path(spec), text)
        merged = _scrub_structured(scrubber, text, kind, vault, delimiter)
        return merged.text, merged
    result, _ = scrubber.scrub(text, vault)
    return result.text, result


def cmd_scrub(args: argparse.Namespace) -> int:
    policy = build_policy(args)
    recognizers = default_recognizers(ner=args.ner, ner_model=args.ner_model, identifiers=resolve_identifiers(args))
    scrubber = Scrubber(policy, recognizers, hash_key=resolve_keys(args))

    passphrase = resolve_passphrase(args, creating=bool(args.vault))
    if passphrase and not args.vault:
        _err("warning: --passphrase has no effect without --vault")
    if args.vault and passphrase is None and not args.plaintext_vault:
        _err(
            "error: a vault holds the original values, so it is encrypted: add "
            "--passphrase (prompt) or --passphrase-env VAR. To write it in the clear "
            "anyway, add --plaintext-vault."
        )
        return EXIT_ERROR

    vault = Vault()
    vault.meta = {"profile": policy.name, "stripii": __version__}

    if args.output and len(args.inputs) > 1 and not Path(args.output).is_dir():
        _err("error: --output must be a directory when scrubbing multiple files")
        return EXIT_ERROR

    reports, findings, secrets_found = [], 0, False
    for spec in args.inputs:
        destination = _destination(spec, args)
        wants_image = destination is not None and destination.suffix.lower() in IMAGE_OUTPUTS
        source_kind = kind_of(Path(spec)) if spec != "-" else "text"
        if wants_image and source_kind not in OCR_KINDS:
            # Writing Markdown into a file named .pdf produced something that
            # looked like a redacted PDF and would not open.
            _err(
                f"error: cannot write {destination.name}: a redacted PDF or image "
                "can only be made from a PDF or an image. Use a .md or .txt output."
            )
            return EXIT_ERROR
        try:
            if wants_image:
                # Paint the redaction onto the page itself, then read the page
                # back to prove it. Nothing is left under the box, unlike a
                # rectangle drawn over a PDF's text layer.
                result = _write_pages(spec, destination, policy, args, vault)
            else:
                if spec != "-" and source_kind in OCR_KINDS and args.ocr:
                    from . import ocr as ocr_module

                    ocr_result = ocr_module.read_document(
                        Path(spec), dpi=args.ocr_dpi, backend=args.ocr_engine
                    )
                    _warn_unreadable(spec, ocr_result.unreadable_pages)
                    text, kind = ocr_result.text, "text"
                else:
                    text, kind = _load_input(spec, args.format)
                    if not args.quiet:
                        _warn_images(spec)
                scrubbed, result = _scrub_document(scrubber, text, kind, vault, spec)
                if destination is None:
                    sys.stdout.write(scrubbed)
                    if not scrubbed.endswith("\n"):
                        sys.stdout.write("\n")
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(scrubbed, encoding="utf-8")
                    if not args.quiet:
                        _err(f"wrote {destination}")
        except (OSError, UnsupportedDocument, OcrUnavailable) as exc:
            _err(f"error: {exc}")
            return EXIT_ERROR

        findings += result.total
        secrets_found |= any(
            r.detection.entity in SECRET_ENTITIES for r in result.replacements
        )
        if args.json:
            reports.append(report_json(spec, result, show_values=args.show_values))
        elif not args.quiet:
            _err(render_report(spec, result, show_values=args.show_values))

    if args.json:
        _err(json.dumps(reports, indent=2))

    if args.vault:
        try:
            saved = vault.save(args.vault, passphrase)
        except VaultError as exc:
            _err(f"error: {exc}")
            return EXIT_ERROR
        if not args.quiet:
            note = "encrypted" if passphrase else "PLAINTEXT - contains the original values"
            _err(f"vault: {saved} ({len(vault)} entries, {note})")

    if args.fail_on_findings and findings:
        return EXIT_FINDINGS
    if args.fail_on_secret and secrets_found:
        _err("error: credentials detected")
        return EXIT_FINDINGS
    return EXIT_OK


def _write_pages(
    spec: str, destination: Path, policy: Policy, args: argparse.Namespace, vault: Vault
) -> ScrubResult:
    """A redacted PDF or image, drawn on the page and read back to grade it."""
    output = "pdf" if destination.suffix.lower() == ".pdf" else "image"
    graded: RedactionResult = redact_file(
        Path(spec),
        profile=policy,
        outputs=(output,),
        identifiers=resolve_identifiers(args),
        ocr=args.ocr_engine,
        verify=not args.no_verify,
        dpi=args.ocr_dpi,
        hash_key=resolve_keys(args),
        force_ocr=args.ocr,
    )
    if output == "image" and destination.suffix.lower() != Path(spec).suffix.lower():
        from . import ocr as ocr_module

        data = ocr_module.image_bytes(graded.pages[0], destination.suffix, dpi=args.ocr_dpi)
    else:
        data = graded.outputs[output]
    _warn_unreadable(spec, graded.unreadable_pages)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    for placeholder, original in graded.vault.mapping.items():
        vault.record(placeholder, original)
    if not args.quiet:
        _err(
            f"wrote {destination} ({graded.page_count} page(s), read with {graded.source}, "
            f"redaction drawn on the image)"
        )
        word = GRADE_WORDS[graded.grade]
        why = f": {'; '.join(graded.reasons)}" if graded.reasons else ""
        checked = f"{graded.checked} value(s) read back" if graded.verified else "not read back"
        _err(f"grade: {word} ({checked}{why})")
    return graded.scrub


def _destination(spec: str, args: argparse.Namespace) -> Path | None:
    if args.stdout or spec == "-":
        return None
    if args.in_place:
        return Path(spec)
    if args.output:
        out = Path(args.output)
        return out / Path(spec).name if out.is_dir() else out
    return None


def cmd_scan(args: argparse.Namespace) -> int:
    policy = build_policy(args)
    scrubber = Scrubber(
        policy,
        default_recognizers(ner=args.ner, ner_model=args.ner_model, identifiers=resolve_identifiers(args)),
        hash_key=resolve_keys(args),
    )
    reports, findings = [], 0
    for spec in args.inputs:
        try:
            if args.ocr and spec != "-" and kind_of(Path(spec)) in OCR_KINDS:
                from . import ocr as ocr_module

                ocr_result = ocr_module.read_document(
                    Path(spec), dpi=args.ocr_dpi, backend=args.ocr_engine
                )
                _warn_unreadable(spec, ocr_result.unreadable_pages)
                text, kind = ocr_result.text, "text"
            else:
                text, kind = _load_input(spec, args.format)
                if not args.quiet:
                    _warn_images(spec)
        except (OSError, UnsupportedDocument, OcrUnavailable) as exc:
            _err(f"error: {exc}")
            return EXIT_ERROR
        _, result = _scrub_document(scrubber, text, kind, Vault(), spec)
        findings += result.total
        if args.quiet:
            continue
        if args.json:
            reports.append(report_json(spec, result, show_values=args.show_values))
        else:
            print(render_report(spec, result, show_values=args.show_values))
    if args.json and not args.quiet:
        print(json.dumps(reports, indent=2))
    return EXIT_FINDINGS if findings else EXIT_OK


def cmd_restore(args: argparse.Namespace) -> int:
    try:
        vault = Vault.load(args.vault, resolve_passphrase(args))
    except (OSError, VaultError, ValueError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    try:
        text, _ = _load_input(args.input)
    except (OSError, UnsupportedDocument) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    restored = Scrubber.restore(text, vault)
    if args.output:
        Path(args.output).write_text(restored, encoding="utf-8")
        _err(f"wrote {args.output}")
    else:
        sys.stdout.write(restored)
        if not restored.endswith("\n"):
            sys.stdout.write("\n")
    return EXIT_OK


def cmd_benchmark(args: argparse.Namespace) -> int:
    from .benchmark import evaluate, load_corpus, render

    try:
        documents = load_corpus(Path(args.corpus), args.corpus_format)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    if not documents:
        _err(f"error: no documents found in {args.corpus}")
        return EXIT_ERROR

    scrubber = Scrubber(
        build_policy(args),
        default_recognizers(ner=args.ner, ner_model=args.ner_model, identifiers=resolve_identifiers(args)),
    )
    report = evaluate(scrubber, documents, mode=args.match)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render(report, show_missed=args.show_missed))
    if args.min_recall is not None and report.overall.recall < args.min_recall:
        _err(
            f"error: recall {report.overall.recall:.3f} is below the "
            f"required {args.min_recall:.3f}"
        )
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_proxy(args: argparse.Namespace) -> int:
    from .proxy import serve

    policy = build_policy(args)
    scrubber = Scrubber(
        policy,
        default_recognizers(ner=args.ner, ner_model=args.ner_model, identifiers=resolve_identifiers(args)),
        hash_key=resolve_keys(args),
    )

    def report(counts: dict[str, int]) -> None:
        if counts and not args.quiet:
            summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            _err(f"redacted: {summary}")

    try:
        server = serve(
            scrubber,
            host=args.host,
            port=args.port,
            upstream=args.upstream,
            verbose=args.verbose,
            on_report=report,
            allow_binary=args.allow_binary_uploads,
        )
    except OSError as exc:
        _err(f"error: cannot bind {args.host}:{args.port} ({exc})")
        return EXIT_ERROR

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        _err(
            f"warning: listening on {args.host}, not loopback. This proxy has no "
            "authentication and forwards whatever API key it is given -- anyone "
            "who can reach it can spend your quota."
        )
    if args.allow_binary_uploads:
        _err("warning: --allow-binary-uploads: images, PDFs and files are forwarded "
             "as they are, unredacted")
    _err(f"stripii proxy on http://{args.host}:{args.port} -> {args.upstream}")
    _err(f"profile: {policy.name}, style: {args.style}. Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _err("")
    finally:
        server.shutdown()
        server.server_close()
    stats = server.stats
    _err(f"handled {stats.requests} request(s), {stats.redactions} redaction(s)")
    return EXIT_OK


def _identifier_values(args: argparse.Namespace) -> list[str]:
    """Values for ``identifiers add``/``remove``: stdin, a prompt, or (warned) argv."""
    if args.values == ["-"]:
        return _read_lines(sys.stdin)
    if args.values:
        _err(ARGV_WARNING.format(what="an identifier",
                                 better="`stripii identifiers add` with no value (it prompts), "
                                        "or `... add -` to read them from stdin"))
        return list(args.values)
    if not sys.stdin.isatty():
        return _read_lines(sys.stdin)
    values = []
    _err("One value per line; an empty line finishes.")
    while True:
        try:
            line = input("identifier: ").strip()
        except EOFError:
            break
        if not line:
            break
        values.append(line)
    return values


def cmd_identifiers(args: argparse.Namespace) -> int:
    """Manage the encrypted list of the user's own values."""
    from .document import shape

    try:
        store = IdentifierStore(args.file)
        if args.action in {"add", "remove"}:
            values = _identifier_values(args)
        if args.action == "add":
            added = [v for v in values if store.add(v)]
            _err(f"{len(added)} added, {len(store)} in the list")
        elif args.action == "remove":
            removed = [v for v in values if store.remove(v)]
            missing = len(values) - len(removed)
            _err(f"{len(removed)} removed" + (f", {missing} not found" if missing else ""))
        elif args.action == "clear":
            store.clear()
            _err("the list is empty")
        elif args.action == "forget-key":
            forget_keychain_key()
            store.path.unlink(missing_ok=True)
            _err("key and list removed")
        elif args.action == "path":
            print(store.path)
        else:  # list
            values = store.values()
            if not values:
                _err("the list is empty; add with: stripii identifiers add \"Your Name\"")
            for value in values:
                print(value if args.show_values else shape(value))
            if values and not args.show_values:
                _err(f"({len(values)} value(s), shown as shapes; --show-values to see them)")
    except (IdentifierStoreError, OSError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    return EXIT_OK


def cmd_profiles(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps({n: p.to_dict() for n, p in PROFILES.items()}, indent=2))
        return EXIT_OK
    for name, policy in PROFILES.items():
        print(f"{name}")
        print(f"  {policy.description}")
        print(f"  default action: {policy.default_action.value}, min score: {policy.min_score}")
        if policy.actions:
            overrides = ", ".join(f"{k}={v.value}" for k, v in sorted(policy.actions.items()))
            print(f"  overrides: {overrides}")
        print()
    return EXIT_OK


def cmd_entities(args: argparse.Namespace) -> int:
    entities = sorted(known_entities())
    if args.json:
        print(json.dumps(entities, indent=2))
    else:
        for entity in entities:
            suffix = "  (requires --ner)" if entity in NER_ONLY_ENTITIES else ""
            print(f"{entity}{suffix}")
    return EXIT_OK


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------

def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-p", "--profile", default="default", choices=sorted(PROFILES),
        help="built-in policy profile (default: %(default)s)",
    )
    parser.add_argument("--policy", metavar="FILE", help="JSON policy file, may 'extends' a profile")
    parser.add_argument(
        "--set", action="append", metavar="ENTITY=ACTION",
        help="override one entity, e.g. --set DATE=redact (repeatable)",
    )
    parser.add_argument(
        "--disable", action="append", metavar="ENTITY",
        help="ignore an entity entirely (repeatable)",
    )
    parser.add_argument(
        "--format", default="auto", choices=["auto", "text", "json", "csv"],
        help="treat input as this format instead of guessing from the extension; "
             "needed for structural handling of piped input (default: %(default)s)",
    )
    parser.add_argument(
        "--style", default="placeholder", choices=sorted(STYLES),
        help="what a redaction looks like: placeholder [[PERSON_1]], surrogate "
             "(a realistic stand-in from a reserved range), encrypt "
             "(format-preserving, NIST SP 800-38G FF1), hash, or mask "
             "(default: %(default)s)",
    )
    parser.add_argument(
        "--key-env", metavar="VAR",
        help="environment variable holding the secret that seeds hashing, "
             "surrogates and encryption; without it they are random per run. Use a "
             "random value (openssl rand -base64 32), not a password",
    )
    parser.add_argument(
        "--ocr", action="store_true",
        help="read PDFs and images with local OCR, even a PDF that has a text layer; "
             "writing to .pdf or an image draws the redaction onto the page itself "
             "(text-layer pages with images are OCR'd then anyway)",
    )
    parser.add_argument(
        "--ocr-engine", default="auto", choices=list(BACKEND_NAMES),
        help="which local OCR engine: vision (Apple, macOS only), tesseract, or auto "
             "-- Vision where it runs, Tesseract otherwise (default: %(default)s)",
    )
    parser.add_argument(
        "--ocr-dpi", type=_dpi, default=200, metavar="N",
        help="rasterisation resolution for OCR, 72 to 600 (default: %(default)s)",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="when writing a redacted PDF or image, skip reading it back to grade it",
    )
    parser.add_argument(
        "--identifier", action="append", metavar="TEXT",
        help="a value of your own -- a name, an account number -- to redact wherever "
             "it appears, whatever the context (repeatable; lands in shell history, "
             "so prefer --identifier-file)",
    )
    parser.add_argument(
        "--identifier-file", metavar="FILE",
        help="read your own values from FILE, one per line; - reads them from stdin",
    )
    parser.add_argument(
        "--saved-identifiers", action="store_true",
        help="also redact everything in the saved list (see `stripii identifiers`)",
    )
    parser.add_argument("--min-score", type=float, help="confidence threshold override")
    parser.add_argument("--placeholder", help="placeholder template, e.g. '<{entity}-{n}>'")
    parser.add_argument("--ner", action="store_true", help="enable the optional spaCy name backend")
    parser.add_argument("--ner-model", default="en_core_web_sm", help="spaCy model (default: %(default)s)")
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    parser.add_argument(
        "--show-values", action="store_true",
        help="include the detected values in the report (they are personal data)",
    )


def _dpi(text: str) -> int:
    from .ocr import MAX_DPI, MIN_DPI

    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not MIN_DPI <= value <= MAX_DPI:
        raise argparse.ArgumentTypeError(f"must be between {MIN_DPI} and {MAX_DPI}")
    return value


def _add_vault_args(parser: argparse.ArgumentParser, *, required: bool = False) -> None:
    parser.add_argument(
        "--vault", required=required, metavar="FILE",
        help="mapping file enabling `stripii restore`; contains the original values",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--passphrase", action="store_true",
        help="prompt for a passphrase and encrypt the vault (AES-256-GCM)",
    )
    group.add_argument(
        "--passphrase-env", metavar="VAR",
        help="read the vault passphrase from this environment variable",
    )
    group.add_argument(
        "--plaintext-vault", action="store_true",
        help="write the vault unencrypted (it holds the original values in the clear)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stripii",
        description="Strip personal data out of documents before they reach an AI tool. "
                    "Runs entirely locally: no network calls, no telemetry.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"stripii {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scrub = subparsers.add_parser("scrub", help="redact a document")
    scrub.add_argument("inputs", nargs="+", metavar="FILE", help="files to scrub, or - for stdin")
    scrub.add_argument("-o", "--output", metavar="PATH", help="output file, or directory for many inputs")
    scrub.add_argument("--stdout", action="store_true", help="always write to stdout")
    scrub.add_argument("-i", "--in-place", action="store_true", help="overwrite the input files")
    scrub.add_argument("-q", "--quiet", action="store_true", help="suppress the summary report")
    scrub.add_argument("--fail-on-findings", action="store_true", help="exit 1 if anything was redacted")
    scrub.add_argument("--fail-on-secret", action="store_true", help="exit 1 if a credential was found")
    _add_policy_args(scrub)
    _add_vault_args(scrub)
    scrub.set_defaults(func=cmd_scrub)

    scan = subparsers.add_parser("scan", help="report findings without writing output")
    scan.add_argument("inputs", nargs="+", metavar="FILE", help="files to scan, or - for stdin")
    scan.add_argument(
        "-q", "--quiet", action="store_true",
        help="report nothing; use the exit status alone (0 clean, 1 findings)",
    )
    _add_policy_args(scan)
    scan.set_defaults(func=cmd_scan)

    restore = subparsers.add_parser("restore", help="put the original values back into a model's reply")
    restore.add_argument("input", metavar="FILE", help="file to restore, or - for stdin")
    restore.add_argument("-o", "--output", metavar="PATH", help="output file (default: stdout)")
    _add_vault_args(restore, required=True)
    restore.set_defaults(func=cmd_restore)

    benchmark = subparsers.add_parser(
        "benchmark",
        help="measure precision and recall against a gold-annotated corpus",
    )
    benchmark.add_argument("corpus", metavar="PATH",
                           help="JSONL corpus file, or a directory of i2b2/n2c2 XML")
    benchmark.add_argument("--corpus-format", default="auto",
                           choices=["auto", "jsonl", "i2b2"])
    benchmark.add_argument(
        "--match", default="binary", choices=list(MATCH_MODES),
        help="strict: exact span and type. relaxed: overlapping span, same type. "
             "binary: overlapping span, any type -- the number that says whether "
             "an identifier survives into the output (default: %(default)s)",
    )
    benchmark.add_argument("--show-missed", type=int, default=0, metavar="N",
                           help="also list N missed spans (they are personal data)")
    benchmark.add_argument("--min-recall", type=float, metavar="R",
                           help="exit 1 if recall falls below R, for use in CI")
    _add_policy_args(benchmark)
    benchmark.set_defaults(func=cmd_benchmark)

    proxy = subparsers.add_parser(
        "proxy",
        help="run a local proxy that redacts requests and restores replies",
    )
    proxy.add_argument("--host", default="127.0.0.1",
                       help="interface to bind (default: %(default)s, loopback only)")
    proxy.add_argument("--port", type=int, default=8080, help="(default: %(default)s)")
    proxy.add_argument("--upstream", default=DEFAULT_UPSTREAM,
                       help="API to forward to (default: %(default)s)")
    proxy.add_argument("-q", "--quiet", action="store_true",
                       help="do not print a per-request redaction summary")
    proxy.add_argument("-v", "--verbose", action="store_true",
                       help="log request lines (paths only, never bodies)")
    proxy.add_argument(
        "--allow-binary-uploads", action="store_true",
        help="forward base64 images, PDFs, audio and files, which cannot be redacted "
             "(refused by default)",
    )
    _add_policy_args(proxy)
    proxy.set_defaults(func=cmd_proxy)

    identifiers = subparsers.add_parser(
        "identifiers",
        help="keep a list of your own values (name, family, account numbers) that are "
             "always redacted; encrypted, key in the system credential store",
    )
    identifiers.add_argument(
        "action", choices=["add", "remove", "list", "clear", "path", "forget-key"],
    )
    identifiers.add_argument(
        "values", nargs="*", metavar="TEXT",
        help="for add/remove: - reads values from stdin, one per line; with none, "
             "they are prompted for. Values given here land in shell history.",
    )
    identifiers.add_argument("--file", metavar="PATH", help="the list file (default: per-user data folder)")
    identifiers.add_argument("--show-values", action="store_true",
                             help="print the values themselves rather than their shapes")
    identifiers.set_defaults(func=cmd_identifiers)

    profiles = subparsers.add_parser("profiles", help="list the built-in policy profiles")
    profiles.add_argument("--json", action="store_true")
    profiles.set_defaults(func=cmd_profiles)

    entities = subparsers.add_parser("entities", help="list every detectable entity type")
    entities.add_argument("--json", action="store_true")
    entities.set_defaults(func=cmd_entities)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, KeyError) as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    except RuntimeError as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - `| head` and friends
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        _err("interrupted")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
