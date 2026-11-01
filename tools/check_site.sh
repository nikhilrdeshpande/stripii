#!/usr/bin/env bash
# Check the landing page in site/ keeps the promises it makes about itself.
# Run locally, and by .github/workflows/pages.yml before every publish.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
bad() { echo "FAIL: $*"; fail=1; }
page=site/index.html
grep -q '<script' "$page" && bad "a <script> tag"
grep -Eo '(src|srcset)="[^"]*"' "$page" | grep -q 'https\?:' && bad "an image or script from another host"
grep -Eo '<link[^>]+>' "$page" | grep -v 'rel="canonical"' | grep -q 'href="https\?:' && bad "a stylesheet from another host"
grep -q 'url(http' site/style.css && bad "a CSS url() to another host"
grep -q 'url(data:' site/style.css && bad "a data: URL the page's own CSP would block"
grep -q $'\xe2\x80\x94' "$page" site/style.css && bad "an em-dash in the copy"
grep -q 'StripPII\|strippii\|Stripy' "$page" && bad "a retired name"
grep -q "Content-Security-Policy\" content=\"default-src 'none'" "$page" || bad "the CSP meta tag is missing"
grep -q 0fbbc4954c1db495b0f3ae6f7f1017f3f27fae66f720e6485d1bafa5ecc49fde "$page" || bad "checksum does not match the 0.3.0 release"
[ "$(cat site/CNAME)" = stripii.nikhilrdeshpande.com ] || bad "site/CNAME is not stripii.nikhilrdeshpande.com"
for f in $(grep -Eo '(src|href)="img/[^"]+"' "$page" | sed -E 's/.*"(.*)"/\1/'); do
  [ -f "site/$f" ] || bad "missing site/$f"
done
# Every image shipped must be one the owner approved, byte for byte.
for f in site/img/*.webp site/img/*.png; do
  grep -qx "$(git hash-object "$f") $f" site/img/APPROVED || bad "$f is not in site/img/APPROVED"
done
[ "$fail" = 0 ] && echo "ok: no scripts, nothing from other hosts, CSP present, every image approved"
exit "$fail"
