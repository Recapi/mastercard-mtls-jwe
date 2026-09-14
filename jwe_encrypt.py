#!/usr/bin/env python3
"""
Monta o JWE (compact serialization) que a Mastercard espera no corpo da request.

Equivalente ao que o client-encryption-java faz no reference app:
    JweConfigBuilder.aJweEncryptionConfig()
        .withEncryptionCertificate(<Client Encryption Key .pem>)
        .withEncryptedValueFieldName("encryptedValue")

alg = RSA-OAEP-256   (envelopa a chave AES com a chave publica da Mastercard)
enc = A256GCM        (cifra o payload com AES-256-GCM)
kid = SHA-256 hex da chave publica (o "Fingerprint" que aparece no dashboard)

Uso:  echo '{"cardNumber":123}' | python3 jwe_encrypt.py certs/...clientenc....pem
Saida: {"encryptedValue":"<header>.<key>.<iv>.<ct>.<tag>"}
"""
import base64, hashlib, json, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def main():
    cert_path = sys.argv[1]
    field = sys.argv[2] if len(sys.argv) > 2 else "encryptedValue"
    payload = sys.stdin.read().strip().encode()

    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    pub = cert.public_key()

    # kid = fingerprint SHA-256 da chave publica em DER (SubjectPublicKeyInfo)
    spki = pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = hashlib.sha256(spki).hexdigest()

    header = {"kid": kid, "cty": "application/json",
              "enc": "A256GCM", "alg": "RSA-OAEP-256"}
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())

    cek = os.urandom(32)                    # chave AES-256 de uso unico
    iv  = os.urandom(12)                    # IV do GCM

    enc_key = pub.encrypt(cek, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

    # AAD = os bytes ASCII do header protegido em base64url
    ct_and_tag = AESGCM(cek).encrypt(iv, payload, protected.encode())
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    jwe = ".".join([protected, b64u(enc_key), b64u(iv), b64u(ct), b64u(tag)])
    print(json.dumps({field: jwe}, separators=(",", ":")))
    print(f"[kid usado] {kid}", file=sys.stderr)

if __name__ == "__main__":
    main()
