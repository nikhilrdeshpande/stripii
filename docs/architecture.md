# How Stripii works

Stripii removes personal details from medical and financial documents on your own computer,
before you paste them into an AI tool. It comes in two forms that share one engine:

- **The Stripii command line tool and Python library** (`stripii`, MIT, this repository).
- **Stripii for Mac**, a desktop app for people who will never open a terminal. It is a free
  download, distributed as a `.dmg` that is not notarised by Apple (see below).

This page explains how both are built, what they promise, and where the limits are.

## The promise, and how it is kept

Nothing you give Stripii leaves your computer. Two different mechanisms enforce that, one for
each form.

**The command line tool** has no runtime dependencies in its default install. It makes no
network calls, sends no telemetry and downloads no models. CI runs the full test suite with no
optional packages installed, so a network library cannot creep in as a hidden requirement. The
one network feature, an opt-in local proxy for AI APIs, is described separately below.

**The Mac app** goes further: macOS itself stops it from reaching the network. The app runs in
the App Sandbox and holds no network entitlement, neither `network.client` nor
`network.server`. Without one of those, the kernel refuses every connection the app tries to
make: DNS lookups, TCP connections, HTTPS and even listening on localhost. Anyone can check
the signature of the installed app:

```console
codesign -d --entitlements - /Applications/Stripii.app
```

It lists two entitlements: the sandbox, and read/write access to files you pick or drop.
Nothing else. The app also runs these checks on itself, from inside the sandbox, under
**Help ▸ Check Stripii's Privacy**.

This constraint shaped the app's design. A web view (WebKit) will not render inside a sandbox
with no network entitlement, so the app's interface is native SwiftUI.

## The pipeline

Every document goes through the same five steps, in the library and in the app:

```
 read ─▶ detect ─▶ decide ─▶ redact ─▶ read back and grade
```

### 1. Read

| Input | How it is read |
|---|---|
| Text, Markdown, CSV, TSV, JSON | parsed directly; structure (columns, keys) is kept |
| Word (`.docx`), Excel (`.xlsx`) | python-docx and openpyxl, XML entity resolution off |
| PDF with a text layer | exact word positions from pdfplumber |
| Scanned PDF, photo (JPEG, PNG, HEIC…) | on-device OCR: **Apple Vision** on macOS, Tesseract elsewhere |
| PDF pages that mix text and images | both: the text layer *and* OCR of the rendered page |

The last row matters. A letter with a photographed ID card pasted in, or a "searchable PDF"
from a scanner app whose hidden text layer misreads the numbers, has personal details that the
text layer does not contain. Stripii OCRs any page that carries images or drawn annotations and
redacts what either reading finds.

Photos are turned upright using their EXIF orientation before anything is read. Limits stop a
crafted file from exhausting memory: 500 pages, 60 megapixels a page, 1.5 gigapixels in total.

### 2. Detect

Stripii recognises 48 kinds of identifier (`stripii entities` lists them). They group roughly as:

- **People and places:** names, street addresses, cities, ZIP, PIN and UK postcodes, coordinates.
- **Health:** medical record numbers, insurance member IDs, NPI and DEA numbers, NHS numbers, ages over 89.
- **Government IDs:** SSN, Aadhaar, PAN, passport, driving licence, UK National Insurance, EIN, GSTIN.
- **Money:** card numbers, expiry dates and CVVs, bank accounts, IBAN, IFSC, SWIFT, routing numbers, UPI IDs.
- **Contact and devices:** phone, email, URLs, IP and MAC addresses, VINs, number plates, serials.
- **Secrets:** API tokens, AWS keys, JWTs, private keys.

Each candidate gets a confidence score built from three kinds of evidence:

- **A validated checksum** is strong evidence. Card numbers are checked with Luhn and Aadhaar with Verhoeff, among others.
- **A nearby label** adds weight. `Routing Number:` beside nine digits counts for more than nine digits alone, and the label must sit on the same or the adjacent line.
- **The pattern's own specificity** matters. `ABCDE1234F` has the exact shape of a PAN, while nine digits on their own could be anything.

Names are the hard case. Stripii finds them through labels (`Patient Name:`), titles
(`Dr. Chen`), credentials (`Chen, MD`), relationship words (`her daughter Elena`), names
printed in capitals as on Indian forms and statements, and a bundled list of given names. Once a
name is found anywhere in a document, every other occurrence is replaced too: other casings,
the surname alone, initials with the surname, and the name written without spaces.

**Your own details.** You can save the identifiers you know appear in your documents: your
name, family members' names, account numbers. They are always removed, in every written form.
The list is encrypted with AES-256-GCM. The key is a random 32-byte value kept in the macOS
Keychain, never beside the file.

### 3. Decide

A **profile** says what to do with each kind of detail:

| Profile | For | Notable choices |
|---|---|---|
| `default` | general use | dates kept; card and account numbers masked to the last four |
| `health` | HIPAA Safe Harbor | all 18 identifier classes; dates to the year; ZIPs to three digits; ages over 89 to "90+" |
| `finance` | statements | identity removed; transaction dates and amounts kept so the numbers still add up |
| `paranoid` | when in doubt (the Mac app uses this) | everything detectable, including low-confidence matches |

The possible actions are **redact** (`[[PERSON_1]]`), **mask** (`****1111`), **generalise**
(`1934`, `627**`) and **keep**. Replacements are consistent within a document, so the same
person is `[[PERSON_1]]` every time and a model can still follow who did what.

The clinical and financial content is left alone on purpose. A lab report with its results
removed is not worth asking a model about.

### 4. Redact

- **Text output** replaces each value with its placeholder.
- **Page output** (a PDF or a photo) paints solid boxes over each value on the rendered page
  image, then writes the page *as an image*. The output has no text layer, no annotations, no
  form fields, no attachments and none of the original metadata. Photos lose all EXIF, GPS and
  XMP data. Nothing under a black box can be selected, copied or recovered. This answers the
  most common redaction failure: a black rectangle drawn over text that is still underneath.

Optionally, the text output can be **restored**: Stripii writes a vault mapping each placeholder
to its original, encrypted under your passphrase (scrypt, then AES-256-GCM). Paste the model's
reply into `stripii restore` and the real names come back, on your machine.

### 5. Read back and grade

Stripii does not assume the redaction worked. It checks:

1. The output pages are OCR'd with the same engine.
2. Every value that was detected is looked for in what can now be read.
3. Every detector runs again over the read-back text, to catch anything that was never detected
   in the first place.

The result gets a grade measured on that output, not a statistic from other files:

| Grade | Meaning | In the Mac app |
|---|---|---|
| 🟢 **ready** | read back; nothing detected is legible; every page was readable | Copy and Save available |
| 🟡 **check** | something was found on a weak signal, such as a lone given name; the spots are outlined | Copy and Save available, "check these N spots" |
| 🔴 **review** | a detected value is still legible, or a page could not be read | **held**: Copy and Save stay locked until the pages read back clean |

A held result is not a dead end. The review screen shows each page with the flagged spots
outlined. You click a spot to black it out, or drag a box over anything else. Stripii paints the
boxes, removes the words under them from the text as well, reads the pages back and grades
the result again. If the pages now read back clean, the result is released. If something is
still legible after your boxes, it stays held, and sharing it anyway takes an explicit
confirmation. Anything that was still legible can be added to your saved details in the same
step, if you tick the box (it is off by default).

If your saved details cannot be opened (the Keychain refused, for example), the result is held
and says so, rather than looking clean with your own name still on it.

## Stripii for Mac

```
Stripii.app
├── Contents/MacOS/Stripii                SwiftUI app
│     sandboxed · files you choose · no network
│     windows, open/save panels, clipboard, Keychain
│
└── Contents/Helpers/StripiiEngine.app    the Python engine (this repository's core)
      sandbox inherited from the app · same container · no network
      reads, detects, redacts, reads back, grades
```

**Two processes, one sandbox.** The interface is a native SwiftUI app. The engine is the same
Python core as the command line tool, frozen into a helper bundle with PyInstaller. The helper
is signed with exactly two entitlements, `app-sandbox` and `inherit`, so it runs *inside the
app's sandbox*. It has the same lack of network access and can reach nothing outside the app's
own container.

**One line at a time.** The app starts the engine once and talks to it over stdin and stdout,
one JSON object per line: `redact`, `review`, the saved-details operations and a self-check.
Documents travel as bytes, never as paths, so the engine never needs access to your folders.
The engine keeps the channel clean: anything a library prints goes to stderr. Errors come back
as a kind such as "unreadable" or "password-protected", never as exception text, because an
exception about a document can quote the document. When the app quits, the engine's stdin
closes and the engine exits.

**Nothing on disk until you save.** Results live in memory. The engine copies an input into a
private temporary folder inside the container (mode 0700) for the core to open, and deletes it
when the job ends. Leftovers from a crash are removed at the next start. Closing a document
discards its result in both processes. Saving into iCloud Drive, Dropbox, OneDrive, Google
Drive or Box asks first, because those folders upload what you put in them.

**Not notarised, by choice for now.** Stripii is a free download without an Apple Developer
account, so the app is ad-hoc signed rather than notarised, and you download it at your own
risk. macOS blocks the first launch; open System Settings ▸ Privacy & Security and click
**Open Anyway** once. Check the download against the SHA-256 on the download page first. The
sandbox and the missing network entitlement are part of the signature either way, so the
`codesign` check above works on the downloaded app. The build script fails if a network
entitlement, a web view or a networking library ever appears in the bundle.

**Clipboard and file names.** Copy puts the text on this Mac's clipboard only, not on your other
Apple devices through Universal Clipboard, and marks it so clipboard managers skip their history.
A saved copy gets a neutral name such as `Redacted document 2026-10-31.pdf`, because original
file names often contain the patient's or account holder's name.

**Size.** About 77 MB installed, 38 MB to download. Most of it is Python, pdfium and Pillow.

## The AI proxy (command line only, opt-in)

`stripii proxy` runs a small local server that sits between an AI client and the provider's API.
It scrubs every string in each request before forwarding it, and restores the placeholders in
the reply. It is the only part of Stripii that uses the network, and only when you start it. The
Mac app does not include it.

It is built to fail closed:

- It listens on `127.0.0.1` and rejects requests whose `Host` is not loopback. This blocks DNS rebinding from a web page.
- It refuses anything it cannot scrub: non-JSON bodies, compressed bodies, chunked uploads, and base64 images or documents unless `--allow-binary-uploads` is given.
- It requires HTTPS to the upstream, and verifies certificates.
- It never logs request bodies, and does not follow redirects that would carry your API key elsewhere.

## Limits

Stripii is a strong filter, not a guarantee. Read this before trusting it with something that
matters.

- **Names are the weak point.** An unlabelled surname in running prose ("reviewed with
  Kowalczyk") can get through. The saved-details list closes this for your own names, and
  `--ner` adds a statistical name model on the command line.
- **Narrative can identify without an identifier.** "The patient's daughter who teaches at the
  high school on Elm Street" contains no name and no number.
- **Rare formats.** Regional MRN schemes and unlisted national IDs may not be recognised.
- **The grade checks what can be read.** A value that OCR cannot read back is neither found nor
  flagged. Handwriting and very low-quality photos are the usual cause.

**Measured performance.** On an 84-document synthetic corpus with 688 labelled identifiers,
using the `health` profile, Stripii scores 1.000 precision and 0.927 recall. Names (0.79 recall)
and cities (0.50) account for the misses. Read those numbers sceptically: a synthetic corpus
only measures what its author thought of. The benchmark and its caveats are in
[`benchmarks/README.md`](../benchmarks/README.md).

## Security

The core was audited before release. The fixes covered images in text-layer PDFs, proxy
request handling, CSV headers and JSON keys, vault passphrases, `repr` output that could print
originals, atomic and symlink-safe file writes, and dependency floors above known advisories.
CI runs `pip-audit` and pins its actions by commit.

Report vulnerabilities privately; see [`SECURITY.md`](../SECURITY.md).

## Source

- Command line tool and library: [github.com/nikhilrdeshpande/stripii](https://github.com/nikhilrdeshpande/stripii) (MIT)
- HIPAA Safe Harbor mapping: [`docs/hipaa-safe-harbor.md`](hipaa-safe-harbor.md)
