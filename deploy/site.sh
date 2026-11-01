#!/usr/bin/env bash
# Deploy the landing page in site/ to stripii.nikhilrdeshpande.com as an atomic release.
#
#   deploy/site.sh            check, upload a new release, switch, smoke-test, prune
#   deploy/site.sh --setup    install the nginx site and directories on the host (idempotent), then deploy
#   deploy/site.sh --rollback switch `current` back to the previous release
#   deploy/site.sh --check    run the local checks only
#
# Touches only /var/www/stripii.nikhilrdeshpande.com and /etc/nginx/sites-{available,enabled}/stripii.nikhilrdeshpande.com.
# The host is never written in this repository: set DEPLOY_HOST=user@host, or put that line in
# deploy/.env.deploy (ignored by git).
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f deploy/.env.deploy ] && . deploy/.env.deploy
NAME=stripii.nikhilrdeshpande.com
BASE=/var/www/$NAME
CONF_LOCAL=deploy/nginx/$NAME.conf
CONF_REMOTE=/etc/nginx/sites-available/$NAME
KEEP=5
mode="${1:-deploy}"
say() { printf '\n== %s\n' "$*"; }

# ---- local checks: the page makes promises about itself, so hold it to them
say "check"
fail=0
bad() { echo "  FAIL: $*"; fail=1; }
grep -q '<script' site/index.html && bad "a <script> tag"
grep -Eo '(src|srcset)="[^"]*"' site/index.html | grep -q 'https\?:' && bad "an image or script from another host"
grep -Eo '<link[^>]+>' site/index.html | grep -v 'rel="canonical"' | grep -q 'href="https\?:' && bad "a stylesheet or font from another host"
grep -q 'url(http' site/style.css && bad "a CSS url() to another host"
grep -rq $'\xe2\x80\x94' site/index.html site/style.css && bad "an em-dash in the copy"
grep -q 'StripPII\|strippii\|Stripy' site/index.html && bad "a retired name"
for f in $(grep -Eo '(src|href)="(img|fonts)/[^"]+"' site/index.html | sed -E 's/.*"(.*)"/\1/') $(grep -Eo 'url\(fonts/[^)]+\)' site/style.css | sed -E 's/url\((.*)\)/\1/'); do
  [ -f "site/$f" ] || bad "missing site/$f"
done
grep -q 0fbbc4954c1db495b0f3ae6f7f1017f3f27fae66f720e6485d1bafa5ecc49fde site/index.html || bad "checksum on the page does not match the 0.3.0 release"
[ "$fail" = 0 ] || exit 1
echo "  ok: no scripts, nothing from other hosts, no em-dashes, every file present"
[ "$mode" = "--check" ] && exit 0

: "${DEPLOY_HOST:?set DEPLOY_HOST=user@host (or create deploy/.env.deploy) before deploying}"
HOST="$DEPLOY_HOST"; IP="${HOST#*@}"
remote() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" "$@"; }

if [ "$mode" = "--rollback" ]; then
  say "rollback"
  remote "set -e; cd $BASE; cur=\$(readlink current); prev=\$(ls -1 releases | sort | grep -v \"\$(basename \$cur)\" | tail -1); \
    [ -n \"\$prev\" ] || { echo 'no previous release'; exit 1; }; ln -sfn releases/\$prev current.tmp && mv -T current.tmp current; echo \"current -> \$prev\""
  exit 0
fi

if [ "$mode" = "--setup" ]; then
  say "setup host"
  remote "set -e; mkdir -p $BASE/releases /var/lib/letsencrypt; \
    test -f /etc/nginx/snippets/cloudflare-realip.conf || { echo 'missing cloudflare-realip snippet'; exit 1; }"
  scp -q "$CONF_LOCAL" "$HOST:$CONF_REMOTE"
  remote "set -e; ln -sfn $CONF_REMOTE /etc/nginx/sites-enabled/$NAME; nginx -t"
fi

REL="$(date -u +%Y%m%d-%H%M%S)-$(git rev-parse --short HEAD)"
[ -n "$(git status --porcelain site)" ] && echo "note: site/ has uncommitted changes; the release is named after the last commit anyway"

say "upload $REL"
rsync -a --delete --exclude '.DS_Store' site/ "$HOST:$BASE/releases/$REL/"

say "switch"
remote "set -e; cd $BASE; ln -sfn releases/$REL current.tmp && mv -T current.tmp current; chown -R root:root releases; chmod -R a+rX releases; \
  nginx -t 2>/dev/null && systemctl reload nginx; echo \"current -> \$(readlink current)\""

say "smoke"
sleep 2
ok=1
scheme=https; curl -sS -o /dev/null --resolve "$NAME:443:$IP" "https://$NAME/" 2>/dev/null || scheme=http
port=443; [ "$scheme" = http ] && port=80
check() { local path="$1" want="$2" got; for _ in 1 2 3; do got=$(curl -sS -o /dev/null -w '%{http_code}' --resolve "$NAME:$port:$IP" "$scheme://$NAME$path"); [ "$got" = "$want" ] && break; sleep 1; done
  printf '  %s %s (want %s)\n' "$got" "$path" "$want"; [ "$got" = "$want" ] || ok=0; }
check / 200
check /style.css 200
check /img/hero.webp 200
check /img/icon-64.png 200
check /index.html 404
check /.git/config 404
check /img/nope.webp 404
csp=$(curl -sS -I --resolve "$NAME:$port:$IP" "$scheme://$NAME/" | grep -ci "default-src 'none'"); printf '  csp header present: %s\n' "$csp"; [ "$csp" = 1 ] || ok=0
[ "$scheme" = http ] && echo "  note: served over http only; run certbot on the host (see $CONF_LOCAL)"
[ "$ok" = 1 ] || { echo "smoke test failed; run: deploy/site.sh --rollback"; exit 1; }

say "prune"
remote "cd $BASE/releases && cur=\$(basename \$(readlink ../current)); ls -1 | sort | grep -v \"^\$cur\$\" | head -n -$((KEEP-1)) | xargs -r rm -rf; ls -1"
say "done: https://$NAME/"
