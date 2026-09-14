#!/usr/bin/env python3
"""
Decifra uma resposta JWE da Mastercard usando a sua chave privada (keystore p12).

So e' necessario se o servico devolver {"encryptedValue": "..."} na resposta.
Varios servicos mTLS so cifram a REQUEST - veja a secao "Preciso da chave de
decifragem?" no README.

Uso:
  echo '{"encryptedValue":"eyJ..."}' | python3 jwe_decrypt.py chave.p12 "$SENHA"
"""
import base64, json, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import pkcs12


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decrypt(jwe: str, private_key) -> bytes:
    protected, enc_key, iv, ct, tag = jwe.split(".")
    header = json.loads(b64u_decode(protected))

    if header.get("alg") != "RSA-OAEP-256":
        raise ValueError(f"alg nao suportado: {header.get('alg')}")

    cek = private_key.decrypt(b64u_decode(enc_key), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

    enc = header.get("enc")
    if enc == "A256GCM":
        # AAD = bytes ASCII do header protegido, exatamente como veio na wire
        return AESGCM(cek).decrypt(b64u_decode(iv),
                                   b64u_decode(ct) + b64u_decode(tag),
                                   protected.encode())
    raise ValueError(f"enc nao suportado: {enc}")


def main():
    p12_path, p12_pass = sys.argv[1], sys.argv[2]
    field = sys.argv[3] if len(sys.argv) > 3 else "encryptedValue"

    key, _cert, _chain = pkcs12.load_key_and_certificates(
        open(p12_path, "rb").read(), p12_pass.encode())

    body = json.loads(sys.stdin.read())
    if field not in body:
        print(json.dumps(body, indent=2))      # resposta ja veio em claro
        print(f"[aviso] sem campo '{field}' - nada para decifrar", file=sys.stderr)
        return

    plaintext = decrypt(body[field], key)
    print(json.dumps(json.loads(plaintext), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
