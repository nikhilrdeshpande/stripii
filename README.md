# Stripii

Strip personal data out of health and financial documents **before** you paste
them into an AI tool.

```console
$ stripii scrub discharge-summary.txt --profile health
Patient Name: [[PERSON_1]]
MRN: [[MRN_1]]
Date of Birth: 1934
Age: 90+
Address: [[STREET_ADDRESS_1]], [[CITY_1]], IL 627**
SSN: [[SSN_1]]

ASSESSMENT
Complete Blood Count showed Hemoglobin 10.2 g/dL (low), Hematocrit 31%.
Diagnosis: Type 2 Diabetes Mellitus (E11.9), Hypertension (I10).
Plan: continue metformin 1000 mg BID, follow up in Cardiology in 2 weeks.
```

The identifiers are gone. The medicine is still there — because a report with
the clinical content stripped out is not worth asking a model about.

## Why this exists

The useful thing to do with a lab report or a bank statement is to ask a model
to explain it. The problem is that doing so hands your name, your account
number and your medical record number to a third party, permanently and
irreversibly.

Stripii sits in between. It runs **entirely on your machine**: no network
calls, no telemetry, no model download, and zero runtime dependencies in the
default install.

**Not a terminal person?** Stripii for Mac does the same thing with drag and
drop: PDFs, scans and iPhone photos in, a redacted copy and paste-ready text
out. It runs in the macOS App Sandbox with no network permission at all, so
macOS itself stops it from sending anything anywhere. It is free, and not notarised by
Apple, so macOS asks you to approve it once. Download it from
[stripii.nikhilrdeshpande.com](https://stripii.nikhilrdeshpande.com).

How the two are built, what they promise and where the limits are:
[`docs/architecture.md`](docs/architecture.md).

## Install

Stripii is not on PyPI yet. Install it from GitHub:

```console
pip install "stripii @ git+https://github.com/nikhilrdeshpande/stripii@v0.3.1"
# or, as an isolated command:
pipx install "git+https://github.com/nikhilrdeshpande/stripii@v0.3.1"
```

Optional extras, each adding one capability (for example
`pip install "stripii[pdf,ocr] @ git+https://github.com/nikhilrdeshpande/stripii@v0.3.1"`):

| Extra | Adds |
|---|---|
| `stripii[crypto]` | encrypted vaults (AES-256-GCM) |
| `stripii[pdf]` | reading `.pdf` |
| `stripii[docx]` | reading `.docx` |
| `stripii[xlsx]` | reading `.xlsx` workbooks |
| `stripii[ocr]` | reading scanned PDFs and images locally |
| `stripii[vision]` | Apple's on-device OCR on macOS (reads photos Tesseract cannot) |
| `stripii[photo]` | iPhone HEIC photos in and out |
| `stripii[keychain]` | the saved identifier list's key in the macOS Keychain |
| `stripii[ner]` | spaCy name detection for unlabelled names |
| `stripii[all]` | all of the above |

The package, the import and the command are all `stripii`.

## Use

**Scrub a file** (redacted document to stdout, report to stderr, so pipes stay clean):

```console
stripii scrub report.pdf --profile health | pbcopy
```

**Check before you paste**, without writing anything:

```console
stripii scan statement.csv --profile finance
```

**Round-trip.** Keep a vault, paste the redacted text into a model, then put the
real values back into its reply:

```console
stripii scrub report.txt -o safe.txt --vault .keys.vault --passphrase
# ... paste safe.txt into the model, save its answer to reply.txt ...
stripii restore reply.txt --vault .keys.vault --passphrase
```

Placeholders are stable within a run, so `[[PERSON_1]]` is the same person
everywhere in the document and the model can still reason about relationships
between people, accounts and dates.

**As a guard in a pipeline** — `scan` exits 1 when it finds something, 0 when
it does not, so it composes like a linter:

```console
stripii scan report.txt --profile secrets --quiet && echo "clean"
git diff --cached | stripii scan - --profile secrets --quiet
```

`examples/pre-commit` is a ready-made git hook that blocks a commit containing
credentials.

## Redacted PDFs

Give it a `.pdf` output and the redaction is drawn onto the page itself --
black boxes on a rendered image, with no text layer left underneath to select
or copy:

```console
stripii scrub statement.pdf -p finance -o redacted.pdf        # PDF with a text layer
stripii scrub scan.pdf -p health --ocr -o redacted.pdf        # scans and photos
```

A PDF with a real text layer is redacted from that layer's exact word
positions; scans go through local OCR, and `--ocr` forces OCR for any PDF.
A text-layer page that also carries an **image or a drawn annotation** -- an ID
card pasted onto a statement, a scanner app's "searchable PDF" whose invisible
text layer may have misread the digits, a typed-in form field -- is OCR'd as
well, and whatever either reading finds is redacted from both sets of boxes.
Those pages take an OCR pass more to read; pages of plain text do not. Text
found only in images is added, redacted, to the text output. A PDF with
image-only pages is read entirely with OCR.

**Every redacted PDF or image is read back and graded.** After drawing the
boxes, Stripii OCRs every output page and runs every detector over it, so
anything detectable that is still legible -- whether or not the first pass
found it -- makes the grade red, with the spots marked. The report says
`grade: ready`, `check` or `HELD`, and why. `--no-verify` skips it, and an
output that was not read back is never graded ready.

The text output of a PDF (`-o out.md`, or stdout) is read from the text layer
alone unless you pass `--ocr`; when pages carry images, stripii warns that their
content is missing from it.

**Two OCR engines.** On macOS, Apple's on-device text recognition
(`stripii[vision]`) is used by default: it read a photographed ID card that
Tesseract returned nothing for. Elsewhere, Tesseract (`stripii[ocr]`). Pick
one with `--ocr-engine vision|tesseract`.

**Photos.** A `.jpg`, `.png` or `.heic` in gives the same format out, turned
the right way up (the EXIF orientation is applied before reading), with the
redaction drawn on and **no EXIF, GPS or XMP metadata carried across**.

```console
stripii scrub card.heic -p paranoid -o redacted.heic
```

For a whole folder, with the read-back check on every output:

```console
python tools/redact_folder.py private/records private/redacted --verify
```

## As a proxy

A command-line tool only helps people willing to run a command line. The proxy
sits between any client and the model API, so redaction happens whether or not
anyone remembers to ask for it:

```console
stripii proxy --profile health --upstream https://api.anthropic.com
```

Then point a client at it:

```console
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
```

The model sees `[[PERSON_1]]` and reasons about it perfectly well; the reply is
rehydrated before the client ever sees it, so the answer names the actual
person. Streaming works — a placeholder split across two deltas (`[[PER` then
`SON_1]]`) is held back until it can be resolved, rather than leaking the
marker.

Every string in the request is scrubbed -- message text, system prompts,
document blocks, tool inputs and results, tool-call `arguments` (parsed out of
their JSON string), metadata -- except structural fields the API needs as
sent: `model`, `role`, `type`, ids, and tool names. Numbers and booleans pass
through untouched, and your API key is forwarded but never logged.

What it **refuses** rather than forward unredacted:

- a body that is not JSON, or is compressed (`Content-Encoding`): 415;
- base64 images, PDFs, audio and files (400), because nothing inside them can
  be redacted -- unless you start it with `--allow-binary-uploads`;
- a `Host` header that does not name this machine (403), which is what a web
  page using DNS rebinding sends;
- bodies over 32 MB, chunked bodies, and request targets that are not a path;
- a plain-`http` upstream anywhere but loopback. Redirects from the upstream
  are passed back to the client, not followed with your key.

It binds to loopback by default, because a redaction proxy reachable from the
network is an unauthenticated relay to a paid API.

## Structured files

JSON and CSV are scrubbed **structurally**: you get back a valid JSON document
or a valid CSV grid, with keys and headers intact.

```console
$ stripii scrub accounts.csv --profile finance -q
holder,account_number,routing_number,balance
[[PERSON_1]],*****0175,[[US_ROUTING_1]],14209.87
```

Keys and headers survive because they are schema, not secrets — and because
they are the only thing that makes the values readable. A cell containing
`021000021` is an unremarkable nine-digit number; under a `routing_number`
header it is a routing number, so the header is passed to the detectors as
context. Scrubbing cells in isolation would find neither.

Piped input has no filename to infer from, so say what it is:

```console
cat accounts.csv | stripii scrub - --format csv --profile finance
```

## Profiles

`stripii profiles` prints these. The interesting decisions are not "can it find
an SSN" but what happens to a date.

| Profile | Built for | Notable choices |
|---|---|---|
| `default` | general use | dates and URLs kept; cards and accounts masked to the last 4 |
| `health` | HIPAA Safe Harbor | dates → year, ages > 89 → `90+`, ZIP → first 3 digits, URLs redacted |
| `finance` | statements | transaction **dates and amounts kept** so the document stays analysable |
| `paranoid` | maximum removal | everything detectable, including low-confidence matches |
| `secrets` | pre-commit / pre-paste | credentials only, nothing else touched |

Override any single decision without writing a policy file:

```console
stripii scrub notes.md --profile health --set DATE=keep --disable CITY
```

Or extend a profile in JSON:

```json
{
  "name": "clinic",
  "extends": "health",
  "min_score": 0.35,
  "actions": { "DATE": "keep", "NPI": "keep" }
}
```

```console
stripii scrub notes.md --policy clinic.json
```

## What it detects

44 entity types out of the box, plus `LOCATION` and `ORGANIZATION` with
`--ner`. `stripii entities` lists them all; they group roughly as:

- **Identity** — names, emails, phones, street addresses, cities, ZIP/postcodes,
  IPs, MACs, geo-coordinates
- **Government** — SSN, EIN, passport, driver's licence, VIN, UK NINO,
  Aadhaar, PAN, GSTIN
- **Health** — MRN, NHS number, NPI, DEA, health plan / member IDs, device serials
- **Financial** — card numbers, CVV, expiry, IBAN, SWIFT/BIC, ABA routing,
  account numbers, IFSC, UPI IDs
- **Credentials** — private keys, AWS keys, JWTs, GitHub/Slack/API tokens

Where an identifier carries a check digit, Stripii verifies it rather than
trusting the shape. Luhn for cards, the 3-7-1 weighting for ABA routing
numbers, mod-97 for IBAN, Verhoeff for Aadhaar, mod-11 for NHS numbers, the
`80840` Luhn prefix for NPIs, and the position-9 check digit for VINs. Nine
digits are only a routing number if they add up like one.

### What it deliberately leaves alone

ICD-10 and CPT codes, lab values and units, drug names and dosages, medical
terminology, transaction amounts, and the schema of a JSON or CSV file. None of
them identify a person, and removing them is what makes redacted documents
useless.

## How it decides

Every candidate gets a confidence score. Three things move it:

1. **A validated checksum** — strong evidence, high score.
2. **A nearby keyword** — `Routing Number:` next to nine digits is worth more
   than nine digits alone. The window is capped at the adjacent line, so a label
   two fields up cannot vouch for an unrelated number.
3. **The pattern's own specificity** — `[A-Z]{5}\d{4}[A-Z]` is a PAN; `\d{9}`
   on its own is nothing much.

Candidates below the profile's `min_score` are reported but not replaced, and
overlapping matches resolve by confidence first, length second — which is how
an email inside a URL still gets redacted even when the URL does not.

## Security notes

- **Vaults contain the data you were trying not to leak.** There is no vault
  unless you pass `--vault`, and `stripii scrub` will not write one in the clear
  unless you also pass `--plaintext-vault`. `--passphrase` encrypts with
  AES-256-GCM over an scrypt-derived key; passphrases shorter than 8
  characters are refused, and a prompted one is asked for twice. Files are
  written `0600` under a fresh random name and renamed into place, so a crash
  never leaves half a vault and a symlink at the destination is not followed.
  `*.vault` is in the shipped `.gitignore`.
- **Passphrases are never command-line arguments** — arguments are visible in
  `ps` and land in shell history. Use `--passphrase` to be prompted, or
  `--passphrase-env VAR`. The same goes for your own identifiers: prefer
  `stripii identifiers add` (it prompts) or `--identifier-file`, and
  `--identifier VALUE` prints a warning saying so.
- **`--key-env` wants a random secret**, e.g. `openssl rand -base64 32`. It
  seeds hashing, surrogates and format-preserving encryption; anyone holding
  the output can test guesses against it offline, so a password-like value is
  only as strong as it is unguessable. It is stretched with scrypt.
- **Reports do not quote what they found** unless you pass `--show-values`. A
  findings report containing the SSN it found is the same leak in a smaller font.
- `MASK` and `GENERALIZE` are **one-way on purpose**. `****1111` and `2025` are
  not unique, so they are never written to the vault — restoring them would
  rewrite every matching string in the model's reply.
- Scanned PDFs with no text layer are **rejected, not silently passed through**
  when there is no OCR to read them; Stripii will not pretend to redact an image
  it cannot read. Pages with images that no OCR engine could read grade red.
- **Rasterising has limits**: 500 pages, 60 megapixels a page, 1.5 gigapixels
  in all, and `--ocr-dpi` between 72 and 600, so a crafted PDF fails with a
  message rather than exhausting memory. Tesseract is handed each page as a
  temporary image file, which pytesseract deletes afterwards; a process killed
  mid-page can leave one in the system temp folder.

## Limits — read this part

This is a strong filter, not a guarantee.

- **Names are the weak point.** Four cues catch them reliably: a label
  (`Patient Name:`), a title (`Dr. Chen`), a credential (`Chen, MD`) and a
  relationship word (`her daughter Elena`). An unlabelled name with none of
  those is caught only if it appears in the bundled given-name list — so a bare
  surname in prose, `reviewed with Kowalczyk`, gets through. For prose-heavy
  documents install `stripii[ner]` and pass `--ner`.
  `examples/clinic-note.txt` demonstrates exactly this failure mode.
- **Free-text narrative leaks.** "the patient's daughter who teaches at the
  high school on Elm" identifies someone without containing an identifier.
- **Rare and local formats** — regional hospital MRN schemes, non-listed
  national IDs — may not be recognised.
- **The read-back grade is only as good as OCR and the detectors.** "Ready"
  means nothing a detector recognises could be read on the output by the OCR
  engine used; it cannot vouch for a name no detector would find, text too
  small or faint for OCR, or handwriting.
- **Photographed ID cards defeat Tesseract.** A PAN card photo yielded three
  words of watermark. Such pages are now reported as unreadable rather than
  counted as clean, but they still need checking by eye or a flatter,
  higher-resolution scan.
- **A surname that is also an English word, written alone in lower case, can
  survive.** Name parts spread to their other mentions, except a part that is
  a dictionary word the document also uses as a word -- otherwise a
  false-positive "Name: Test Case" redacts every "Test" in the file. The word
  check uses the system word list (`/usr/share/dict/words`); where there is
  none, every part spreads and the tool over-redacts instead.
- **Restore returns the first spelling it saw.** "MARGARET WHITFIELD" and
  "Margaret Whitfield" share one placeholder -- the model should know they are
  the same person -- so restoring either gives back whichever came first.
- **A reversible vault is pseudonymisation, not anonymisation.** Under GDPR
  Art. 4(5) the scrubbed text is still personal data as long as you hold the
  key. Scrub without `--vault` if you want the output to stand alone.
- **Values with no label and no format** are invisible. An account number in a
  bare text column with no header, no cue word and no check digit looks exactly
  like any other number.
- **HIPAA Safe Harbor is one of two de-identification methods**, and this tool
  automates the mechanical part of it. It is not legal advice and it is not an
  expert determination under §164.514(b)(1). `docs/hipaa-safe-harbor.md` maps
  all 18 identifier classes to what the tool does, and names the gaps in each.

Use `scan --show-values` to see exactly what was caught, and read the output
before you paste it. The tool is here to make that review short, not to
replace it.

## Library use

```python
from stripii import Scrubber, get_profile

scrubber = Scrubber(get_profile("health"))
result, vault = scrubber.scrub(report_text)

result.text     # redacted, safe to send
result.counts   # {'PERSON': 3, 'DATE': 2, ...}

answer = Scrubber.restore(model_reply, vault)
```

For a file, with a grade measured on the output:

```python
from stripii import redact_file

result = redact_file("scan.pdf", profile="health", outputs=("text", "pdf"),
                     identifiers=["Margaret Whitfield", "4471982"])
result.grade            # "green", "amber" or "red", with result.reasons
result.outputs["pdf"]   # bytes; the caller decides where they go
result.spots            # (page, box, masked shape, why) -- where to look
```

When the grade says to look, `redact_boxes(result, [(page, box), ...])`
paints the boxes a person drew, removes the words under them from the text
too, reads the pages back and grades again -- the review step of an
application.

`identifiers` are values of your own that are always redacted, whatever the
context and however they are written (see below). The grade is **red** when a detected
value can still be read on the output or a page could not be read at all,
**amber** when a name was found on a weak signal or nothing was found, and
**green** otherwise -- and never green unless the output was read back.

## Your own identifiers

The detectors find what *looks like* personal data. Some things only you
know are yours: a surname that is also an English word, an uncommon name
with no label beside it, your account number. List them once and they are
always redacted, in every form a document writes them -- capitals, glued
together, with initials, inside an email address:

```console
stripii identifiers add                  # prompts, one per line; blank line ends
stripii identifiers add - < mine.txt     # or one per line from stdin
stripii identifiers list                 # shapes only: Xxxxxxxx Xxxxxxxxx
stripii scrub report.pdf --saved-identifiers -o redacted.pdf
stripii scrub note.txt --identifier-file mine.txt   # one-off, not saved
```

Values can also be given as arguments (`stripii identifiers add "Margaret
Whitfield"`, `--identifier "Whitfield"`), but then they are in your shell
history and visible in `ps`, so stripii prints a warning when you do.

The list is what the tool exists to protect, so it is stored encrypted
(AES-256-GCM) and the key is kept in the system credential store -- the
macOS Keychain -- through `keyring` (`pip install 'stripii[keychain]'`).
The file alone is useless without the key, and the key alone is useless
without the file. `stripii identifiers forget-key` removes both.

## Measured performance

On an 84-document synthetic corpus (688 gold spans), `health` profile, scoring
whether an identifier was covered at all:

| | Precision | Recall | F1 |
|---|---|---|---|
| Micro | 1.000 | **0.927** | 0.962 |

The misses are concentrated where the limits section says they are: `PERSON`
recall is 0.787 and `CITY` is 0.500; the other fourteen entity types are at
1.000.

**A synthetic corpus only measures what its author thought of.** The first run
against 51 real medical and financial documents found that names printed in
capitals -- the norm on Indian forms, statements and payslips -- were missed
184 times out of 184, while this corpus reported 0.903 recall because it had
none. Those shapes are in the corpus now, and `tools/audit.py` runs the same
checks over your own documents without printing them (see `TESTING.md`).

Read the precision figure sceptically as well: twelve documents contain no
identifiers at all and are filled with lab ranges, ICD codes and amounts that
have caused false positives before, but hindsight-chosen distractors are not
unseen data. The real benchmark is i2b2/n2c2, which needs a data use agreement
and is not bundled; `stripii benchmark` reads its format directly if you have
a copy. See `benchmarks/README.md`.

```console
stripii benchmark benchmarks/synthetic.jsonl -p health --match binary
```

## Documentation

- `docs/architecture.md` — how the tool and the Mac app are built, the
  read-back grade, the sandbox, and the limits.
- `benchmarks/README.md` — measured precision and recall, what the misses are,
  and why the precision number deserves suspicion.
- `docs/hipaa-safe-harbor.md` — all 18 Safe Harbor identifier classes, mapped
  to entities and actions, with the gaps stated per row.
- `examples/` — synthetic documents to try it on, including one that shows
  what still gets through.

## Development

```console
pip install -e ".[dev]"
python tools/smoke.py     # end-to-end self-check of this install
pytest
ruff check .
```

`TESTING.md` covers running it locally, and how to measure whether it actually
caught everything on documents of your own.

CI runs the suite on Python 3.10–3.13, and separately with **no extras
installed at all**, so an optional dependency can never quietly become a
required one. Optional-dependency tests skip individually and name the extra
they need, rather than taking their whole module with them.

**Contributing.** Enable the repository's pre-commit hook once per clone:

```console
git config core.hooksPath .githooks
```

It refuses anything under `private/`, binary documents (PDFs, images, office
files), vaults, and scrubbed or redacted outputs, so a real document cannot be
committed by accident. Test data must be synthetic. Security issues: see
`SECURITY.md`.

## License

MIT
