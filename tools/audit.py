#!/usr/bin/env python3
"""Audit stripii against your own documents -- without printing them.

    python tools/audit.py private/records            # text-layer documents
    python tools/audit.py private/records --ocr      # also read scans

Runs every replacement style over every document and checks what comes out:

* LEAK -- a value redacted in one place still readable as a whole token
  elsewhere, including a detected name written without spaces
* RESTORE -- the vault does not reproduce the original (letter-case-only
  differences are reported separately; they are expected)
* MASK -- a masked name, email or address still shows some of its letters
* ENCRYPT -- an enciphered card, routing number or Aadhaar fails its checksum
* SURROGATE -- two values share one surrogate, or a surrogate already occurs
  in the document (restoring a reply would then rewrite real text)
* STRUCTURE -- line count or table grid changed
* UNREADABLE -- OCR could barely read a page, so "0 findings" means unchecked

Nothing a document contains is printed. Findings are counts, plus the *shape*
of a value with every letter and digit masked ("XXXX9999X"), so the output can
be pasted into an issue without leaking what it is about. Keep the documents
themselves in private/, which is gitignored and blocked by the pre-commit hook.

Exits 1 if any LEAK, RESTORE, MASK, ENCRYPT, SURROGATE or STRUCTURE check fires.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from stripii import Action, Policy, Scrubber, get_profile
from stripii.checksums import aba_routing, luhn, verhoeff
from stripii.readers import UnsupportedDocument, kind_of, read_text

logging.disable(logging.CRITICAL)  # pdfplumber and pypdf are chatty about fonts

STYLES = {
    "placeholder": Action.REDACT,
    "mask": Action.MASK,
    "hash": Action.HASH,
    "surrogate": Action.SURROGATE,
    "encrypt": Action.ENCRYPT,
}
#: Folder name -> profile, matching private/records/{medical,financial,...}.
PROFILE_BY_FOLDER = {"medical": "health", "financial": "finance"}
TEXT_ENTITIES = {"PERSON", "EMAIL", "STREET_ADDRESS", "CITY", "LOCATION", "ORGANIZATION"}
KEY = b"stripii-audit-key-not-a-secret!"
FAILING = ("LEAK", "RESTORE", "MASK", "ENCRYPT", "SURROGATE", "STRUCTURE")


def shape(value: str) -> str:
    value = value.replace("\n", "↵")
    return re.sub(r"[a-z]", "x", re.sub(r"[A-Z]", "X", re.sub(r"\d", "9", value)))[:48]


def styled(profile: Policy, action: Action) -> Policy:
    """What --style does: remap only the entities the profile would redact."""
    actions = {e: (action if a is Action.REDACT else a) for e, a in profile.actions.items()}
    default = action if profile.default_action is Action.REDACT else profile.default_action
    return Policy(name=profile.name, default_action=default, actions=actions,
                  min_score=profile.min_score, disabled=profile.disabled)


def load(root: Path, use_ocr: bool) -> tuple[dict[str, tuple[str, str]], Counter, list[str]]:
    texts, skipped, unreadable = {}, Counter(), []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.name.startswith(".")):
        profile = PROFILE_BY_FOLDER.get(path.parent.name, "paranoid")
        try:
            if use_ocr and kind_of(path) in {"pdf", "image"}:
                try:
                    text = read_text(path)
                except UnsupportedDocument:
                    from stripii import ocr

                    result = ocr.read_document(path)
                    text = result.text
                    unreadable += [f"{path.name}: page {p}" for p in result.unreadable_pages]
            else:
                text = read_text(path)
        except UnsupportedDocument as exc:
            skipped["needs --ocr" if "--ocr" in str(exc) else "unsupported"] += 1
            continue
        except Exception as exc:  # an audit reports, it does not stop
            skipped[type(exc).__name__] += 1
            continue
        texts[path.name] = (profile, text)
    return texts, skipped, unreadable


def audit(texts: dict[str, tuple[str, str]]):
    findings: dict[str, Counter] = defaultdict(Counter)
    examples: dict[str, set[str]] = defaultdict(set)
    totals = Counter()

    def flag(check: str, style: str, example: str | None = None) -> None:
        findings[check][style] += 1
        if example:
            examples[check].add(example)

    for name, (profile_name, text) in texts.items():
        base = get_profile(profile_name)
        for style, action in STYLES.items():
            result, _ = Scrubber(styled(base, action), hash_key=KEY).scrub(text)
            out = result.text
            totals[style] += result.total

            names = []
            for r in result.replacements:
                raw = r.detection.raw.strip()
                if r.detection.entity == "PERSON":
                    names.append(re.findall(r"[A-Za-z]{3,}", raw))
                if len(re.sub(r"[^A-Za-z0-9]", "", raw)) >= 5:
                    whole = re.search(rf"(?<![A-Za-z0-9]){re.escape(raw)}(?![A-Za-z0-9])", out)
                    if whole:
                        flag("LEAK: value still readable elsewhere", style,
                             f"{r.detection.entity}:{shape(raw)}")

                if (
                    r.action is Action.MASK
                    and r.detection.entity in TEXT_ENTITIES
                    and re.sub(r"[^A-Za-z0-9]", "", r.text)
                ):
                    flag("MASK: letters of a name/email/address still visible", style,
                         f"{r.detection.entity}:{shape(raw)} -> {shape(r.text)}")
                if r.action is Action.ENCRYPT:
                    check = {"CREDIT_CARD": luhn, "US_ROUTING": aba_routing, "AADHAAR": verhoeff}
                    validator = check.get(r.detection.entity)
                    if validator and not validator(r.text):
                        flag("ENCRYPT: enciphered value fails its checksum", style,
                             f"{r.detection.entity}:{shape(raw)}")
                if r.action is Action.SURROGATE and r.text in text:
                    flag("SURROGATE: surrogate already occurs in the document", style,
                         f"{r.detection.entity}:{shape(r.text)}")

            # a detected name glued back together without spaces
            for parts in names:
                if len(parts) >= 2:
                    glued = "".join(parts)
                    if len(glued) >= 8 and re.search(
                        rf"(?<![A-Za-z]){re.escape(glued)}(?![A-Za-z])", out, re.IGNORECASE
                    ):
                        flag("LEAK: detected name readable without spaces", style,
                             shape(glued))

            by_replacement = defaultdict(set)
            for r in result.replacements:
                if r.action in (Action.SURROGATE, Action.ENCRYPT, Action.HASH):
                    by_replacement[r.text].add(r.detection.raw.strip().casefold())
            for replacement, raws in by_replacement.items():
                if len(raws) > 1:
                    flag("SURROGATE: two different values share one replacement", style,
                         shape(replacement))

            if out.count("\n") != text.count("\n"):
                flag("STRUCTURE: line count changed", style)
            if out.count("|") != text.count("|"):
                flag("STRUCTURE: table grid changed", style)

            # reversibility, isolated: every entity gets the style, nothing kept
            if action in (Action.REDACT, Action.SURROGATE, Action.ENCRYPT, Action.HASH):
                pure = Policy(name="pure", default_action=action, min_score=base.min_score)
                iso, vault = Scrubber(pure, hash_key=KEY).scrub(text)
                restored = Scrubber.restore(iso.text, vault)
                if restored != text:
                    if restored.casefold() == text.casefold():
                        flag("(restore differs only in letter case -- expected)", style)
                    else:
                        flag("RESTORE: vault does not reproduce the original", style, name[:30])
    return findings, examples, totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folder", type=Path, help="folder of documents, e.g. private/records")
    parser.add_argument("--ocr", action="store_true", help="read scans with local OCR")
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error(f"{args.folder} is not a folder")

    texts, skipped, unreadable = load(args.folder, args.ocr)
    print(f"{len(texts)} document(s) read, {sum(len(t) for _, t in texts.values()):,} characters")
    for reason, count in skipped.items():
        print(f"  skipped {count}: {reason}")
    for page in unreadable:
        print(f"  UNREADABLE: OCR could barely read {page} -- check it by eye")
    if not texts:
        return 0

    findings, examples, totals = audit(texts)
    print(f"\nreplacements per style: {dict(totals)}\n")
    if not findings:
        print("no problems found in any style")
        return 0

    print(f"{'check':<56}" + "".join(f"{s[:11]:>12}" for s in STYLES))
    print("-" * (56 + 12 * len(STYLES)))
    for check in sorted(findings, key=lambda c: (c.startswith("("), c)):
        print(f"{check:<56}" + "".join(f"{findings[check].get(s, 0):>12}" for s in STYLES))
    for check, shapes in sorted(examples.items()):
        print(f"\n[{check}] {len(shapes)} distinct, e.g.:")
        for example in sorted(shapes)[:6]:
            print(f"    {example}")

    failed = [c for c in findings if c.startswith(FAILING)]
    print(f"\n{'FAIL' if failed else 'PASS'}: {len(failed)} failing check(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
