# Benchmarks

Golden tests prove that particular identifiers in particular documents are
caught. They say nothing about the ones nobody thought to write down. This
directory exists so the tool reports a recall *number* rather than a claim.

```console
stripii benchmark benchmarks/synthetic.jsonl --profile health --match binary
```

## Match modes

| Mode | Counts a hit when | Answers |
|---|---|---|
| `strict` | exact span **and** exact entity type | how good is the labelling |
| `relaxed` | overlapping span, same entity type | the usual way de-identification results are reported |
| `binary` | overlapping span, **any** entity type | **did the identifier get covered at all** |

`binary` is the number that matters for privacy. A name detected as an MRN is
still redacted and the reader still cannot see it. Recall under `binary` is the
probability that an identifier survives into the output — the only failure that
hurts anyone. `strict` penalises getting a boundary one character wrong, which
is a labelling error, not a leak.

The scorer evaluates what the tool **actually emits**, after overlap
resolution — not every candidate it considered. Scoring the unresolved
candidate set counts discarded alternatives (a routing number is also a
plausible account number) as false positives that never reach the page. Doing
that understated precision here by 12 points.

## Results — synthetic corpus

84 documents, 688 gold spans, `health` profile, `binary` matching:

| | Precision | Recall | F1 |
|---|---|---|---|
| **Micro** | **1.000** | **0.927** | **0.962** |
| Macro F1 | | | 0.972 |

The only two entity types that miss anything:

| Entity | Precision | Recall | Support |
|---|---|---|---|
| PERSON | 1.000 | **0.787** | 150 |
| CITY | 1.000 | **0.500** | 36 |
| everything else (14 types) | 1.000 | 1.000 | 502 |

### What the misses are

- **Names absent from the bundled given-name list, in prose with no label,
  title or relationship word** -- `Agnieszka Wisniewska`, `Xiulan Zhuang`.
- **Cities with no state abbreviation after them** -- `Nagercoil`, `Wexford`.

`--ner` is the lever for the first. Neither has a regex answer.

## What real documents taught this corpus

The first version of this corpus reported 0.903 recall. The first run against
51 real medical and financial records then found:

- names printed in capitals missed **184 times out of 184** -- this corpus had
  no capitalised names, so it could not see the failure;
- a value redacted in one place and readable in another, **78 times** --
  context-gated detectors only fire beside their label;
- names written without spaces in payment narrations ("RAJESHKUMAR");
- "Dr" (debit) read as "Drive", **98 times in one statement**, each eating part
  of an amount.

All are fixed, and the `indian_statement` documents reproduce their shapes so
a regression shows up here. The lesson stands, though: a synthetic corpus only
measures what its author thought of. Run `tools/audit.py` over documents of
your own; it prints counts and masked shapes, never contents.

## Read the precision figure sceptically

**1.000 precision on a corpus written by the same person who wrote the
detectors is weak evidence.** It means this corpus contains nothing that
tempts a false positive, not that the tool never produces one.

To make it mean something, 12 of the 84 documents have **no gold spans at
all** and are filled with shapes that have actually caused false positives in
this codebase: lab reference ranges containing a date-shaped substring
(`12.0-15.5`), ICD-10 and CPT codes, blood pressures, version strings, batch
quantities and currency amounts. Those 12 documents currently produce zero
false positives, which is a real result — but a corpus of adversarial examples
chosen in hindsight is still not the same as unseen data.

## The real benchmark is i2b2/n2c2, and it is not here

The standard evaluation for clinical de-identification is the i2b2 2014 /
n2c2 corpora of real de-identified discharge summaries with expert PHI
annotations. They require a **data use agreement** and cannot be
redistributed, so they are not bundled.

If you have a copy, point the benchmark at it — the i2b2 XML format and its
PHI tag vocabulary are already supported:

```console
stripii benchmark /path/to/i2b2/xml --corpus-format i2b2 --profile health --match binary
```

Treat that number as the real one. Expect it to be **lower** than the figures
above: real notes contain misspellings, inconsistent formats, names from a far
wider distribution, and identifiers embedded in prose in ways no synthetic
generator thought of.

## Regenerating the corpus

```console
python tools/generate_corpus.py benchmarks/synthetic.jsonl
```

The generator is seeded, so the corpus is reproducible. Every value is
invented; check digits are computed so the values are well formed, because a
detector that validates checksums would otherwise never see a positive case.
Annotation covers every identifier present, including ones a given profile
chooses to keep — a transaction date is a date whether or not `finance`
redacts it.

## Guarding against regressions

```console
stripii benchmark benchmarks/synthetic.jsonl -p health --match binary --min-recall 0.88
```

Exits 1 if recall drops below the threshold, so a detector change that quietly
loses coverage fails CI instead of shipping.

## Corpus format

One JSON object per line:

```json
{"id": "doc-001", "text": "Patient: Jane Smith", "spans": [{"start": 9, "end": 19, "entity": "PERSON"}]}
```
