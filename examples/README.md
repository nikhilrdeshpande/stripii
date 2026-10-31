# Examples

Synthetic documents for trying `stripii` out. Every name, number and address
here is invented; the identifier formats are real so that the checksum
validators have something to chew on.

```console
stripii scan examples/discharge-summary.txt --profile health --show-values
stripii scrub examples/bank-statement.txt --profile finance
stripii scrub examples/clinic-note.txt --profile health
```

`clinic-note.txt` is the honest one. It is narrative prose with unlabelled
names and a city that never appears next to a state abbreviation, and it shows
what still gets through — compare its output against `discharge-summary.txt`,
which is the structured case the tool handles well.
