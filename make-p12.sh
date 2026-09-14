#!/usr/bin/env bash
# Monta o keystore PKCS#12 (mTLS) a partir do .crt + .key que o portal entrega.
# O portal NAO entrega p12 pra mTLS - ele manda cert e chave separados num zip.
#
# Uso:  ./make-p12.sh <cadeia.crt> <chave.key> <saida.p12> [alias]
#   pede a senha da .key e a senha do p12 de saida (podem ser diferentes)
set -euo pipefail

CRT=${1:?cadeia de certificados (.crt/.pem que o portal deu)}
KEY=${2:?chave privada (.key)}
OUT=${3:?arquivo .p12 de saida}
ALIAS=${4:-keyalias}

read -rsp "senha da chave privada (.key): " IN_PASS;  echo
read -rsp "senha para o .p12 de saida   : " OUT_PASS; echo
export IN_PASS OUT_PASS

# 1) confere que a chave realmente casa com o certificado antes de empacotar
a=$(openssl x509 -in "$CRT" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
b=$(openssl pkey -in "$KEY" -passin env:IN_PASS -pubout -outform DER | sha256sum)
[ "$a" = "$b" ] || { echo "❌ a chave NAO corresponde ao certificado"; exit 1; }
echo "✅ par cert/chave confere"

# 2) empacota (a cadeia inteira entra: leaf + subCA + root)
# -iter 600000: o padrao do PKCS#12 e' 2048 iteracoes, KDF dos anos 2000.
# Se o arquivo vazar, a senha e' a unica barreira - encarecer cada tentativa
# em ~30x custa 150ms uma vez no startup. Java (keytool/KeyStore) le normal.
openssl pkcs12 -export \
  -inkey "$KEY" -passin env:IN_PASS \
  -in "$CRT" -name "$ALIAS" \
  -iter 600000 -macalg sha256 -maciter \
  -out "$OUT" -passout env:OUT_PASS
chmod 600 "$OUT"

# 3) valida o resultado do jeito que o Java vai ler
echo "✅ $OUT criado:"
keytool -list -keystore "$OUT" -storetype PKCS12 -storepass "$OUT_PASS" 2>/dev/null \
  | grep -E "entry|PrivateKeyEntry"
openssl x509 -in <(openssl pkcs12 -in "$OUT" -passin env:OUT_PASS -clcerts -nokeys 2>/dev/null) \
  -noout -subject -dates
echo
echo "secret P12      = base64 -w0 $OUT"
echo "secret PASSWORD = a senha do p12 que voce acabou de digitar"
echo
echo "Use a senha aleatoria que o portal sugere, nao uma memorizavel:"
echo "o material que o portal entrega usa KDF fraco (SHA-1/3DES, 2048 iter)."
