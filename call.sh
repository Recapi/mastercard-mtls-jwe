#!/usr/bin/env bash
# Uma chamada a API: mTLS + corpo cifrado em JWE + decifragem opcional da resposta.
#
# Uso: ./call.sh <METODO> <caminho> '<json>'
# Ex:  ./call.sh POST /card-segments '{"cardNumber":5291070000000000,
#        "segments":[{"code":"LAC_BBC","effectiveDate":"2026-09-14"}]}'
set -uo pipefail
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a

METHOD=${1:?metodo HTTP}
PATH_=${2:?caminho, ex: /card-segments}
BODY=${3:?corpo JSON}

: "${MC_BASE_URL:?defina MC_BASE_URL}"
: "${MC_P12:?defina MC_P12}"
: "${MC_P12_PASS:?defina MC_P12_PASS}"
: "${MC_ENC_CERT:?defina MC_ENC_CERT}"

echo ">> payload em claro: $BODY" >&2
JWE=$(printf '%s' "$BODY" | python3 jwe_encrypt.py "$MC_ENC_CERT")
echo ">> corpo cifrado   : $(cut -c1-70 <<<"$JWE")..." >&2

RESP=$(curl -sS -w '\n%{http_code}' \
  --cert "$MC_P12:$MC_P12_PASS" --cert-type P12 \
  -H 'Content-Type: application/json' \
  -X "$METHOD" "$MC_BASE_URL$PATH_" -d "$JWE")

CODE=$(tail -n1 <<<"$RESP")
BODY_OUT=$(sed '$d' <<<"$RESP")
echo ">> HTTP $CODE" >&2

if [ -n "${MC_DEC_P12:-}" ] && [ -f "${MC_DEC_P12:-}" ]; then
  printf '%s' "$BODY_OUT" | python3 jwe_decrypt.py "$MC_DEC_P12" "${MC_DEC_P12_PASS:-}"
else
  printf '%s' "$BODY_OUT" | (jq . 2>/dev/null || cat)
fi
