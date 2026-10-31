# HIPAA Safe Harbor coverage

The `health` profile targets the Safe Harbor method of de-identification,
**45 CFR § 164.514(b)(2)**. Safe Harbor lists 18 classes of identifier that must
be removed from a record — of the individual, and of their relatives, employers
and household members — after which the record is no longer protected health
information.

This table maps each class to what Stripii actually does. Read the
**Gaps** column before relying on it.

| # | Safe Harbor identifier | Entities | Action in `health` | Gaps |
|---|---|---|---|---|
| 1 | Names | `PERSON` | redact | Unlabelled surnames absent from the given-name list are missed unless introduced by a title, credential or relationship word. `--ner` helps. |
| 2 | All geographic subdivisions smaller than a state | `STREET_ADDRESS`, `CITY`, `US_ZIP`, `UK_POSTCODE`, `IN_PINCODE`, `GEO_COORDS` | redact; ZIP generalized | A city is detected when followed by a state abbreviation. A bare city name in prose is missed. County and precinct are not detected. |
| 3 | All elements of dates except year, and all ages over 89 | `DATE`, `AGE_OVER_89` | date → year; age → `90+` | Relative dates ("three weeks ago") and seasons are not dates to a regex. |
| 4 | Telephone numbers | `PHONE` | redact | Extensions are kept unless adjacent to the number. |
| 5 | Fax numbers | `PHONE` | redact | Same detector; a fax is a phone number. |
| 6 | Email addresses | `EMAIL` | redact | — |
| 7 | Social security numbers | `SSN` | redact | A bare nine-digit run needs a nearby `SSN` cue. |
| 8 | Medical record numbers | `MRN` | redact | Requires a nearby cue (`MRN`, `chart number`, `accession`…); a bare institutional number is missed. |
| 9 | Health plan beneficiary numbers | `HEALTH_PLAN_ID` | redact | Requires a nearby cue. |
| 10 | Account numbers | `BANK_ACCOUNT`, `IBAN`, `UPI_ID` | redact | Requires a nearby cue. |
| 11 | Certificate/license numbers | `DRIVER_LICENSE`, `DEA`, `NPI` | redact | State licence formats vary; detection is cue-driven. |
| 12 | Vehicle identifiers and serial numbers, incl. licence plates | `VEHICLE_VIN`, `LICENSE_PLATE` | redact | VIN is checksum-verified. Plate detection covers the Indian format; US state formats vary too much to pattern reliably. |
| 13 | Device identifiers and serial numbers | `DEVICE_SERIAL` | redact | Requires a nearby cue (`serial`, `UDI`, `implant`…). |
| 14 | Web URLs | `URL` | redact | — |
| 15 | IP addresses | `IP_ADDRESS` | redact | Loopback and broadcast addresses are excluded; they identify nobody. |
| 16 | Biometric identifiers | `BIOMETRIC_ID` | redact | Only a textual *reference* to a template can be detected. Biometric data itself is not text. |
| 17 | Full-face photographs and comparable images | — | **not covered** | Out of scope: this is a text tool. Strip images separately. |
| 18 | Any other unique identifying number, characteristic or code | partial | — | **Inherently open-ended.** A catch-all cannot be automated. This is the clause that makes human review mandatory. |

## What this does not give you

Safe Harbor also requires that the covered entity have **no actual knowledge**
that the remaining information could identify the individual
(§ 164.514(b)(2)(ii)). No tool can evaluate that clause, because it is about
what *you* know, not about what is in the file.

A narrative sentence can identify someone while containing zero listed
identifiers:

> "the patient's daughter who teaches at the high school on Elm"

Stripii will not catch that. Neither will any regex.

Safe Harbor is also only one of the two de-identification methods. The other,
**Expert Determination** (§ 164.514(b)(1)), requires a qualified statistician.
This tool automates the mechanical part of Safe Harbor. It is not legal advice,
it is not an expert determination, and it does not make you compliant on its
own.

## Practical use

```console
# See exactly what would be removed, and what was found but not acted on
stripii scan report.txt --profile health --show-values

# Then scrub, and read the result before you send it
stripii scrub report.txt --profile health -o safe.txt
```

Lower `--min-score` to act on weaker candidates at the cost of more false
positives. For health records, over-redaction is usually the cheaper error —
which is why the `health` profile already sits at `0.4` rather than the
default `0.5`.
