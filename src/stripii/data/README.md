# Bundled data

`words.txt.gz` — lower-case English words, one per line, from Webster's Second
International Dictionary (1934, the `web2` list shipped with BSD and macOS
as `/usr/share/dict/words`). Its copyright has lapsed. Only the lower-case
entries are kept: proper nouns are capitalised in that list, so this is
"words that are not names", which is exactly what the engine needs it for.
Bundled so that redaction behaves the same on every operating system.
