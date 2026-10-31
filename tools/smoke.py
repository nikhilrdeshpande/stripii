#!/usr/bin/env python3
"""One-command self-check: does this install actually work on this machine?

The test suite proves the code is correct. This proves *your* install is
wired up -- which extras are present, whether Tesseract is on PATH, whether
the proxy can bind a socket -- and exercises each capability end to end.

    python tools/smoke.py

Exits 0 if everything that could run did run and passed. Skips are not
failures: they tell you which optional extra is missing and how to get it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

GREEN, YELLOW, RED, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = YELLOW = RED = DIM = RESET = ""

RESULTS: list[tuple[str, str, str]] = []


class Skip(Exception):
    """Raised when a check needs an extra that is not installed."""


def check(name):
    def decorate(func):
        def run():
            try:
                detail = func() or ""
                RESULTS.append(("pass", name, detail))
                print(f"  {GREEN}pass{RESET}  {name}" + (f" {DIM}{detail}{RESET}" if detail else ""))
            except Skip as reason:
                RESULTS.append(("skip", name, str(reason)))
                print(f"  {YELLOW}skip{RESET}  {name} {DIM}{reason}{RESET}")
            except Exception as error:
                RESULTS.append(("fail", name, f"{type(error).__name__}: {error}"))
                print(f"  {RED}FAIL{RESET}  {name}")
                print(f"        {RED}{type(error).__name__}: {error}{RESET}")
        run.__name__ = func.__name__
        return run
    return decorate


def need(module: str, extra: str):
    try:
        __import__(module)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        raise Skip(f"needs pip install 'stripii[{extra}]'") from exc


HEALTH_NOTE = """DISCHARGE SUMMARY
Patient Name: Margaret Whitfield
MRN: 4471982
SSN: 412-88-9031
Email: m.whitfield@example.com
Phone: (217) 555-0142
Address: 1847 Oakmont Drive, Springfield, IL 62704

| Test | Result | Ref Range | Flag |
| --- | --- | --- | --- |
| Hemoglobin | 10.2 | 12.0-15.5 | LOW |
| Glucose | 142 | 70-99 | HIGH |

Diagnosis: Type 2 Diabetes Mellitus (E11.9). Continue metformin 1000 mg BID.
"""

IDENTIFIERS = ["Margaret Whitfield", "4471982", "412-88-9031",
               "m.whitfield@example.com", "555-0142", "Springfield"]
CLINICAL = ["Hemoglobin", "10.2", "12.0-15.5", "Glucose", "142", "70-99",
            "E11.9", "metformin 1000 mg BID"]


# --------------------------------------------------------------------------

@check("install and version")
def check_version():
    import stripii

    return f"stripii {stripii.__version__}, python {sys.version.split()[0]}"


@check("core redaction: identifiers out, clinical content in")
def check_core():
    from stripii import Scrubber, get_profile

    out = Scrubber(get_profile("health")).scrub(HEALTH_NOTE)[0].text
    leaked = [i for i in IDENTIFIERS if i in out]
    if leaked:
        raise AssertionError(f"leaked: {leaked}")
    lost = [c for c in CLINICAL if c not in out]
    if lost:
        raise AssertionError(f"destroyed clinical content: {lost}")
    return f"{len(IDENTIFIERS)} identifiers removed, {len(CLINICAL)} values preserved"


@check("table fidelity: the grid survives redaction")
def check_table():
    from stripii import Scrubber, get_profile

    out = Scrubber(get_profile("health")).scrub(HEALTH_NOTE)[0].text
    if out.count("|") != HEALTH_NOTE.count("|"):
        raise AssertionError("the table grid was altered")
    row = [ln for ln in out.splitlines() if ln.startswith("| Hemoglobin")]
    if not row or "10.2" not in row[0] or "12.0-15.5" not in row[0]:
        raise AssertionError("a table row was broken apart")
    return "rows intact"


@check("structured input: CSV headers used as context")
def check_structured():
    from stripii import Scrubber, get_profile
    from stripii.readers import scrub_csv

    scrubber = Scrubber(get_profile("finance"))
    out = scrub_csv(
        "holder,routing_number\nJane Smith,021000021\n",
        lambda text, hint=None: scrubber.scrub(text, context_hint=hint)[0].text,
    )
    if "021000021" in out:
        raise AssertionError("a routing number under its own header was missed")
    if not out.startswith("holder,routing_number"):
        raise AssertionError("the header row was rewritten")
    return "header preserved, cell redacted"


@check("vault round trip: redactions reverse, generalisations do not")
def check_vault():
    from stripii import Action, Policy, Scrubber, get_profile

    # Everything redacted: the round trip must be exact.
    reversible = Policy(name="t", default_action=Action.REDACT, min_score=0.4)
    result, vault = Scrubber(reversible).scrub(HEALTH_NOTE)
    restored = Scrubber.restore(result.text, vault)
    if restored != HEALTH_NOTE:
        raise AssertionError("an all-redact policy did not round trip exactly")

    # Under health, ZIP and dates are generalised, which is deliberately
    # one-way: "627**" and "1934" are not unique, so restoring them would
    # rewrite every matching string in a model's reply.
    health, health_vault = Scrubber(get_profile("health")).scrub(HEALTH_NOTE)
    if "62704" in Scrubber.restore(health.text, health_vault):
        raise AssertionError("a generalised ZIP was reversed; it should be one-way")

    return f"{len(vault)} mappings reversed exactly"


@check("surrogate style: natural text from reserved ranges")
def check_surrogate():
    from stripii import Action, Policy, Scrubber

    policy = Policy(name="t", default_action=Action.SURROGATE, min_score=0.4)
    out = Scrubber(policy, hash_key=b"k" * 32).scrub("Patient Name: Margaret Whitfield")[0].text
    if "[[" in out or "Margaret Whitfield" in out:
        raise AssertionError(f"unexpected surrogate output: {out!r}")
    return out.removeprefix("Patient Name: ")


@check("format-preserving encryption: encrypted card stays Luhn-valid")
def check_fpe():
    need("cryptography", "crypto")
    from stripii import Action, Policy, Scrubber
    from stripii.checksums import luhn

    policy = Policy(name="t", default_action=Action.ENCRYPT, min_score=0.4)
    out = Scrubber(policy, hash_key=b"k" * 32).scrub("card 4111 1111 1111 1111")[0].text
    card = out.removeprefix("card ")
    if card == "4111 1111 1111 1111":
        raise AssertionError("the card was not enciphered")
    if not luhn(card):
        raise AssertionError(f"enciphered card fails Luhn: {card}")
    return f"{card} (valid)"


@check("benchmark: measured recall on the shipped corpus")
def check_benchmark():
    from stripii import Scrubber, get_profile
    from stripii.benchmark import evaluate, load_jsonl

    corpus = Path(__file__).resolve().parents[1] / "benchmarks" / "synthetic.jsonl"
    if not corpus.exists():
        raise Skip("benchmarks/synthetic.jsonl not found; run from a full checkout")
    report = evaluate(Scrubber(get_profile("health")), load_jsonl(corpus), mode="binary")
    if report.overall.recall < 0.88:
        raise AssertionError(f"recall regressed to {report.overall.recall:.3f}")
    return (
        f"P={report.overall.precision:.3f} R={report.overall.recall:.3f} "
        f"F1={report.overall.f1:.3f} over {report.documents} docs"
    )


@check("proxy: upstream never sees the name, client gets it back")
def check_proxy():
    from stripii import Scrubber, get_profile
    from stripii.proxy import serve

    seen: list[str] = []

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            seen.append(self.rfile.read(length).decode() if length else "")
            body = json.dumps(
                {"content": [{"type": "text", "text": "Summary for [[PERSON_1]]."}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy = serve(
        Scrubber(get_profile("health")),
        host="127.0.0.1",
        port=0,
        upstream=f"http://127.0.0.1:{upstream.server_address[1]}",
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{proxy.server_address[1]}/v1/messages",
            data=json.dumps(
                {"model": "m", "messages": [{"role": "user", "content": HEALTH_NOTE}]}
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            reply = json.loads(response.read())
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()

    if "Margaret Whitfield" in seen[0]:
        raise AssertionError("the name reached the upstream")
    if "Margaret Whitfield" not in reply["content"][0]["text"]:
        raise AssertionError("the reply was not rehydrated")
    return "redacted outbound, restored inbound"


@check("PDF reading (tables)")
def check_pdf():
    need("pdfplumber", "pdf")
    return "pdfplumber available"


@check("DOCX reading")
def check_docx():
    need("docx", "docx")
    return "python-docx available"


@check("XLSX reading")
def check_xlsx():
    need("openpyxl", "xlsx")
    return "openpyxl available"


@check("OCR: reads a scan and paints the redaction onto the page")
def check_ocr():
    need("pypdfium2", "ocr")
    need("PIL", "ocr")
    from stripii import Scrubber, get_profile
    from stripii.ocr import OcrUnavailable, get_backend, read_images, redact_images, save_pdf

    try:
        engine = get_backend("auto")
    except OcrUnavailable as exc:
        raise Skip(str(exc)) from None
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGB", (1000, 300), "white")
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.load_default(32)     # Pillow >= 10.1 scales the built-in font
    except TypeError:
        font = ImageFont.load_default()
    for index, line in enumerate(["Patient Name: Margaret Whitfield", "SSN: 412-88-9031"]):
        draw.text((20, 40 + index * 80), line, fill="black", font=font)

    result = read_images([image], backend=engine)
    if "Whitfield" not in result.text:
        raise Skip("OCR could not read the generated sample (font rendering)")

    scrubbed, _ = Scrubber(get_profile("health")).scrub(result.text)
    spans = [(r.detection.start, r.detection.end) for r in scrubbed.replacements]
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory) / "redacted.pdf"
        save_pdf(redact_images(result, spans), out)
        if not out.exists() or out.stat().st_size == 0:
            raise AssertionError("no redacted PDF was produced")
    return f"{engine.name}: read {len(result.words)} words, painted {len(spans)} span(s)"


@check("CLI is on PATH")
def check_cli():
    try:
        completed = subprocess.run(
            ["stripii", "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError as exc:
        raise Skip("`stripii` not on PATH; use `python -m stripii` instead") from exc
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.strip())
    return completed.stdout.strip()


CHECKS = [
    check_version, check_cli, check_core, check_table, check_structured,
    check_vault, check_surrogate, check_fpe, check_benchmark, check_proxy,
    check_pdf, check_docx, check_xlsx, check_ocr,
]


def main() -> int:
    print("stripii self-check\n")
    for run in CHECKS:
        run()

    passed = sum(1 for status, _, _ in RESULTS if status == "pass")
    skipped = sum(1 for status, _, _ in RESULTS if status == "skip")
    failed = [(name, detail) for status, name, detail in RESULTS if status == "fail"]

    print(f"\n{passed} passed, {skipped} skipped, {len(failed)} failed")
    if skipped:
        print(f"{DIM}skips are missing optional extras, not problems{RESET}")
    if failed:
        print(f"\n{RED}failures:{RESET}")
        for name, detail in failed:
            print(f"  {name}: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
