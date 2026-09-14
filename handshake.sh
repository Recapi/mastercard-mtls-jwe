#!/usr/bin/env bash
# Diagnostico da camada mTLS, isolada do resto.
# Responde: o servidor pede cert? ele aceita o MEU cert? o par confere?
#
# Uso: ./handshake.sh [host]
set -uo pipefail
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a

HOST=${1:-$(echo "${MC_BASE_URL:-https://mtf.services.mastercard.com}" | sed -E 's#https?://([^/]+).*#\1#')}
hr(){ printf '\n\033[1m%s\033[0m\n' "──── $* ────"; }

hr "1. O servidor $HOST pede certificado de cliente?"
OUT=$(timeout 25 openssl s_client -connect "$HOST:443" -servername "$HOST" </dev/null 2>&1)
if grep -qi "Acceptable client certificate CA names" <<<"$OUT"; then
  echo "sim. CAs aceitas (5 primeiras):"
  sed -n '/Acceptable client certificate CA names/,/Requested Signature/p' <<<"$OUT" | sed -n '2,6p'
else
  echo "nao - esse host nao exige mTLS"
fi

[ -n "${MC_P12:-}" ] && [ -f "${MC_P12:-}" ] || { echo; echo "defina MC_P12 no .env para testar o seu certificado"; exit 0; }

hr "2. A senha abre o keystore e o par confere?"
if openssl pkcs12 -in "$MC_P12" -passin env:MC_P12_PASS -noout 2>/dev/null; then
  echo "senha OK"
  openssl pkcs12 -in "$MC_P12" -passin env:MC_P12_PASS -clcerts -nokeys 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates
else
  echo "❌ senha errada para $MC_P12"; exit 1
fi

hr "3. O servidor aceita o SEU certificado?"
timeout 25 openssl s_client -connect "$HOST:443" -servername "$HOST" \
  -cert <(openssl pkcs12 -in "$MC_P12" -passin env:MC_P12_PASS -clcerts -nokeys 2>/dev/null) \
  -key  <(openssl pkcs12 -in "$MC_P12" -passin env:MC_P12_PASS -nocerts -nodes 2>/dev/null) \
  </dev/null 2>&1 | grep -iE "^CONNECTED|Protocol *:|Cipher *:|Verify return code|alert"
echo
echo "Sem linha 'alert' e com 'Verify return code: 0 (ok)' = handshake mTLS completo."
