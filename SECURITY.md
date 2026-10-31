# Security policy

Stripii exists to keep personal data out of AI tools, so a way for that data to
get through is a security bug, not a feature request. Please report one.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:

**https://github.com/nikhilrdeshpande/stripii/security/advisories/new**

Please do not open a public issue, pull request or discussion for a
vulnerability, and **never attach a real document**. Reproduce with synthetic
data -- invented names, test numbers such as `219-09-9999` -- and include the
smallest input that shows the problem, the command or API call, the version
(`stripii --version`), the platform, and which optional extras and OCR engine
are installed.

You should get an acknowledgement within a week. Fixes are released as soon as
they are ready, with credit in the advisory unless you would rather not.

## In scope

- **Leaks through redaction**: a value Stripii detects (or is told about with
  `stripii identifiers`) that survives into an output -- the text, a redacted
  PDF or image, the file's metadata -- or a redacted page graded "ready" while
  a detectable value is still legible on it.
- **Network access**: any network connection made by the default install, or
  by any command other than `stripii proxy`; the proxy forwarding unredacted
  content, sending your API key anywhere but the configured upstream, or being
  usable from outside the machine when bound to loopback.
- **Vault and identifier-list cryptography**: weaknesses in the encryption,
  key derivation or file handling of vaults (`--vault`) and the saved
  identifier list, including file permissions and symlink handling.
- **Parser crashes and resource exhaustion** from a crafted PDF, image, DOCX,
  XLSX, CSV or JSON file, where Stripii's own code is at fault or applies no
  limit. Vulnerabilities in a dependency itself (Pillow, pypdf, pdfplumber,
  pdfium) belong upstream, but tell us if Stripii's floor needs raising.
- **Values printed where they should not be**: reports, warnings, exception
  messages or `repr()` output that quote an original value without
  `--show-values`.

## Out of scope

- **Detection misses on their own.** Recall is not 100% and is documented as
  such (see "Limits" in the README). A name with no label, title or other cue
  that no detector recognises is a known limitation; a report is still welcome
  as a detector improvement, through a normal issue with synthetic data.
- Anything requiring an attacker who already controls your user account, your
  credential store, or the Python environment Stripii runs in.
- `--show-values`, `--plaintext-vault`, `--allow-binary-uploads` and binding
  the proxy to a non-loopback address doing what they say.

## What Stripii guarantees, and what it does not

**No network in the default install.** `pip install stripii` has no
dependencies, and nothing in it opens a connection. No telemetry, no model
downloads, no update checks. Optional extras (OCR, PDF, NER) run locally too.
The only component that talks to a network is `stripii proxy`, and only to the
upstream you give it.

**The proxy is loopback-only by default.** It binds to `127.0.0.1`, refuses
requests whose `Host` header does not name this machine (DNS rebinding),
requires `https` for any upstream that is not loopback, and does not follow
redirects. It scrubs every string in a request except structural fields
(model, role, type, ids, tool names), and refuses what it cannot scrub:
non-JSON or compressed bodies, and base64 images, PDFs, audio and files unless
started with `--allow-binary-uploads`. It has no authentication: anyone who
can reach its port can use the API key a client sends through it.

**What is redacted.** Every entity the active profile acts on (see
`stripii profiles` and `stripii entities`), wherever the detectors find it: in
text, in every string and key of JSON, in every cell of CSV/TSV including the
header row, and on PDF and image pages, where boxes are painted onto the
rendered page so no text layer remains beneath them. Text-layer PDF pages that
carry images or drawn annotations are OCR'd as well. Redacted PDFs are
rasterised: no text layer, annotations, form fields or document metadata from
the original survive, and redacted photos carry no EXIF, GPS or XMP metadata.

**The grade.** A redacted PDF or image is read back with OCR and every
detector is run over it; any detectable value still legible makes it red.
"Ready" therefore means: nothing *a detector recognises* could be read on the
output *by the OCR engine used*. It does not mean the document is anonymous.

**What is not guaranteed.**

- Recall is high on structured identifiers (numbers with check digits or
  labels) and lower on names, addresses and free narrative. Measured figures,
  and their caveats, are in `benchmarks/README.md`. A bare surname in prose, a
  description that identifies someone without naming them, an unusual local ID
  format, handwriting, or text too small or faint for OCR can all get through.
- Placeholders and surrogates are pseudonymisation: whoever holds the vault,
  or the `--key-env` secret, can reverse them.
- Format-preserving encryption and hashing are only as strong as the
  `--key-env` secret, which must be random (`openssl rand -base64 32`).
- Unencrypted vaults (`--plaintext-vault`) hold the original values in the
  clear.
- While a PDF is being read with Tesseract, page images are written to the
  system temporary folder and deleted after each page; a process killed
  mid-page can leave one behind.

Always look at the output before you paste it.
