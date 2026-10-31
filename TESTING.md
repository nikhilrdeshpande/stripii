# Testing Stripii

## 1. Get it running locally

```console
git clone https://github.com/nikhilrdeshpande/stripii
cd stripii
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev,crypto,pdf,docx,xlsx,ocr]"
stripii --version
```

Requires Python 3.10+. `dev` brings pytest and ruff; `crypto` enables encrypted
vaults and format-preserving encryption; `pdf`, `docx` and `xlsx` read those
formats; `ocr` reads scans. OCR also needs the Tesseract engine itself
(`apt install tesseract-ocr`, or `brew install tesseract`). Everything else is optional — `pip install -e .` alone works
and pulls in **no third-party packages at all**, which is worth confirming:

```console
pip list --format=freeze        # stripii and nothing else
```

## 1a. One-command self-check

Before anything else, confirm your install actually works on this machine:

```console
python tools/smoke.py
```

It exercises each capability end to end — redaction, table fidelity, the
vault, surrogates, format-preserving encryption, the benchmark, the proxy
(against a fake upstream on loopback) and OCR — and tells you which optional
extras are missing rather than failing on them. Exits 0 when everything that
could run did.

## 2. Automated tests

```console
pytest                      # 559 tests, ~11s without OCR
pytest -m "not slow"        # skip the OCR tests, which rasterise real pages
ruff check .
```

**559 tests are collected regardless of which extras you installed.** Skips are
per-test and each names the extra it needs, so `pytest -rs` tells you exactly
what did not run. A different collected total means something is wrong.

| Install | Result |
|---|---|
| everything, incl. Vision (macOS) and tesseract | `558 passed, 1 skipped` |
| `.[dev,crypto,pdf,docx,xlsx]` | `392 passed, 12 skipped` |
| `.[dev]` only | fewer still, each skip named |

The suite is in layers, most valuable first:

| File | What it protects |
|---|---|
| `test_no_leak.py` | **The promise.** Scrubs a sample discharge summary and bank statement, then asserts every identifier is gone *and* every clinical value and transaction survived. |
| `test_detectors.py` | Each entity has a positive case, plus the false positives that matter — clinical terms, amounts, digits inside words, failed checksums. |
| `test_checksums.py` | Every validator accepts a real identifier and rejects a tampered one. |
| `test_engine.py` | Overlap resolution, the five actions, placeholder stability, restore correctness. |
| `test_vault.py` | File permissions, encryption, and the refusals. |
| `test_cli.py` | Exit codes, and that stdout stays clean for piping. |
| `test_benchmark.py` | The scorer, plus a recall floor that fails if coverage regresses. |
| `test_proxy.py` | The round trip, against a fake upstream that records what it received. |
| `test_fpe.py` | FF1 against the NIST SP 800-38G sample vectors. |
| `test_ocr.py` | Re-OCRs the redacted image to prove the ink is really on the page. Runs once per installed engine (Vision, Tesseract). |
| `test_document.py` | `redact_file`: what earns each grade, and that a page with a survivor is red with spots. |
| `test_photos.py` | Sideways photos are turned upright before reading; a photo goes out in its own format with no metadata. |
| `test_identifiers.py` | A listed name is found however it is written; the list is never on disk in the clear, and the key comes from the credential store. |

Run one layer: `pytest tests/test_no_leak.py -v`

## 2a. The benchmark

Golden tests prove specific identifiers are caught. The benchmark reports a
number:

```console
stripii benchmark benchmarks/synthetic.jsonl -p health --match binary
```

Expect micro precision 1.000, recall 0.903. `--min-recall 0.88` exits 1 below
the floor, which is how CI catches a detector change that quietly loses
coverage. See `benchmarks/README.md` for what the misses are and why the
precision figure deserves suspicion.

## 3. Smoke-test the CLI

Synthetic documents ship in `examples/`, so start there — nothing sensitive:

```console
stripii scan   examples/discharge-summary.txt -p health --show-values
stripii scrub  examples/bank-statement.txt    -p finance
stripii scrub  examples/clinic-note.txt       -p health
stripii profiles
stripii entities
```

`clinic-note.txt` is the honest one — narrative prose where names have no
label. Compare it against `discharge-summary.txt` to see the difference
between the structured case and the hard case.

Round trip:

```console
stripii scrub examples/bank-statement.txt -p finance -o safe.txt --vault v.vault --passphrase
echo 'Ask [[PERSON_1]] about [[US_ROUTING_1]].' | stripii restore - --vault v.vault --passphrase
```

Exit codes, for scripting: `scan` returns 0 when clean, 1 when it finds
something, 2 on error.

```console
stripii scan examples/discharge-summary.txt -q; echo $?    # 1
```

## 4. Testing against your own documents

This is the part that matters, and it needs care: the point of the tool is that
your data never leaves the machine, so **test offline and never paste a real
document anywhere to check the result**.

**Step 0 — keep real documents in `private/`.** That directory is gitignored,
and a pre-commit hook refuses anything under it — or any PDF, Office file or
image anywhere in the repo — even past `git add -f`. Enable the hook once per
clone:

```console
git config core.hooksPath .githooks
```

**Step 0b — audit everything at once.** Before reading outputs one by one:

```console
python tools/audit.py private/records --ocr
```

Runs every replacement style over every document and checks what comes out:
values still readable elsewhere, names readable without spaces, masks that
show letters, enciphered values that fail their checksum, surrogates that
collide, vaults that do not restore, tables that lost their grid, and pages
OCR could not read. It prints counts and masked shapes (`XXXX9999X`) only, so
its output is safe to paste into an issue. Exits 1 if anything fails.

Sort documents into `private/records/medical/` and `.../financial/` to have
them audited under the `health` and `finance` profiles; anything else gets
`paranoid`.

**Step 0c — redacted PDFs.** To get redacted PDFs rather than text, and to
prove the ink covers what was found:

```console
python tools/redact_folder.py private/records private/redacted --verify
```

It OCRs every original and every redacted page and reports how many detected
values that were legible before are still legible after -- counts and masked
shapes only. It is slow, since every page is recognised twice.

**Step 1 — scrub a copy.**

```console
mkdir -p private
cp ~/real-report.pdf private/testcase.pdf
stripii scrub private/testcase.pdf -p health -o private/scrubbed.md
```

If it is a scan, add `--ocr`. To get a redacted PDF back instead of text, give
it a `.pdf` output path and the redaction is drawn onto the page:

```console
stripii scrub private/testcase.pdf -p health --ocr -o private/redacted.pdf
```

**Step 2 — hunt for false negatives.** This is the only measurement that
counts. Write down the identifiers you know are in the document, then check
none survived:

```console
cat > private/known.txt <<'IDS'
Margaret Whitfield
412-88-9031
4471982
m.whitfield@example.com
IDS

grep -F -f private/known.txt private/scrubbed.md        # prints nothing = nothing leaked
```

For a redacted **image**, grep cannot help — re-run OCR over the output and
grep that instead, which is exactly what `test_ocr.py` does:

```console
stripii scrub private/redacted.pdf --ocr -p secrets -q | grep -F -f private/known.txt
```

Anything that prints is a miss. That is the number to care about.

**Step 3 — check for false positives.** Read `private/scrubbed.md` and confirm the
content you wanted to ask a model about is still there — lab values, codes,
amounts, dates, and **tables with their rows intact**.

**Step 4 — see the reasoning.** `--show-values` prints every match with its
score, the detector that found it, and what it became:

```console
stripii scan private/testcase.pdf -p health --show-values
```

Note that `--show-values` prints your personal data to the terminal. That is
why it is off by default. Don't pipe it into a log or a shared session.

**Step 5 — tune.** If something was missed, lower the threshold and look at
what the extra candidates were:

```console
stripii scan private/testcase.pdf -p health --min-score 0.3 --show-values
```

If something was over-redacted, keep it:

```console
stripii scrub private/testcase.pdf -p health --set DATE=keep --disable CITY
```

## 5. Known things to test for, because they are the weak points

Try each of these against your own data — these are where it will fail first:

- **An unlabelled surname in prose** (`reviewed with Kowalczyk`). Caught only
  if the name is in the bundled given-name list. Try `--ner` after
  `pip install "stripii[ner]" && python -m spacy download en_core_web_sm`.
- **A city with no state abbreviation after it.** Detected via the
  `City, ST` shape; a bare city name in a sentence is missed.
- **A scanned PDF.** Should be *rejected* with a message about OCR, not
  silently passed through. Verify that — a silent pass would be the worst
  failure mode.
- **A CSV or JSON export.** Headers and keys are used as context, so
  `account_number,483920175` is caught while a bare unlabelled column is not.
  Pipe input needs `--format csv` or `--format json`, since stdin has no
  filename.
- **A table in a PDF or DOCX.** It should come back as a Markdown pipe table
  with every cell in place, not one cell per line. Borderless tables use
  alignment detection, which is the shakier path.
- **The proxy.** `stripii proxy --profile health`, then point a client at
  `http://127.0.0.1:8080` and confirm the reply names the real person while
  the request never carried it.
- **Narrative that identifies without an identifier** — *"the patient's
  daughter who teaches at the high school on Elm"*. This will not be caught,
  by this or any regex. Read the output before you send it.

## 6. Testing a change you make

```console
pytest                        # must stay green
ruff check .
```

If you add a detector, add both a positive case and a negative case to
`tests/test_detectors.py` — `test_every_catalogued_entity_has_a_positive_case`
fails if you add an entity with no test. If you change a profile's actions, the
golden tests in `test_no_leak.py` will tell you whether you broke the
identifiers-out / content-in balance.
