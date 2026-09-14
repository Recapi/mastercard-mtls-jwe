# Mastercard mTLS + JWE — scripts de diagnóstico

Ferramentas mínimas para integrar com uma API Mastercard que usa **mTLS** e
**payload encryption (JWE)**, sem depender das bibliotecas Java da Mastercard.

Escrito enquanto eu integrava o **Benefit Allocation Service (MTLS)**, mas a
mecânica vale para qualquer API do portal com `auth_type: MTLS`.

Só precisa de `openssl`, `curl` e Python com a lib `cryptography`.

---

## As três camadas

O erro mais comum é tratar isso como uma coisa só. São três, independentes, e
cada uma falha de um jeito diferente:

```
1. mTLS            você prova quem é, no handshake TLS
                   → certificado de cliente + chave privada (keystore .p12)

2. JWE             o corpo da request vira {"encryptedValue": "<jwe>"}
                   → certificado público da Mastercard (.pem)

3. Negócio         só aqui a API olha o seu payload
```

Diagnosticar é descobrir em qual camada você parou:

| Sintoma | Camada |
|---|---|
| `alert` no handshake, `INVALID_CLIENT_CERT` | 1 — mTLS |
| HTTP 500 genérico, "unexpected error" | 2 — o corpo chegou, mas não decifrou |
| `ReasonCode 57` *Invalid encryption key used* | 2 — cifrou com o certificado errado |
| Erro de negócio com `ReasonCode` específico | 3 — **a parte técnica está OK** |

Um HTTP 500 virando um erro de negócio é sinal de **progresso**: significa que
o mTLS passou e o JWE foi decifrado.

---

## Formato do JWE

```
alg = RSA-OAEP-256    envelopa a chave AES com a pública da Mastercard
enc = A256GCM         cifra o payload com AES-256-GCM
kid = SHA-256 hex da chave pública (o "Fingerprint" que aparece no dashboard)
```

Serialização compacta, cinco partes separadas por ponto, dentro de um campo JSON:

```json
{"encryptedValue":"<header>.<chave>.<iv>.<ciphertext>.<tag>"}
```

O `kid` é o jeito mais rápido de confirmar que você está usando o certificado
certo: ele tem que bater com o fingerprint mostrado no dashboard do projeto.
O `jwe_encrypt.py` imprime o `kid` em stderr a cada chamada.

---

## Credenciais: o que é cada arquivo

O portal entrega materiais diferentes com nomes parecidos. O que importa:

| Material | Contém | Formato | Onde entra |
|---|---|---|---|
| Certificado mTLS | cert + **chave privada** | `.crt` + `.key` → vire `.p12` | handshake TLS |
| Senha | — | texto | abre o `.p12` |
| Client Encryption Key | só o **certificado público** da Mastercard | `.pem` | cifrar a request |
| Chave de decifragem | seu par privado | `.p12` | decifrar a resposta (*talvez*) |

### `.p12` não é "outro formato de certificado"

`PKCS#12` é um **container** protegido por senha que guarda certificado **e**
chave privada juntos. O `.pem` que o portal te dá para o certificado mTLS tem
só a metade pública — sozinho ele **não faz mTLS**, porque o servidor exige que
você prove posse da chave privada durante o handshake.

O portal **não entrega um `.p12` pronto** para mTLS: manda `.crt` + `.key`
cifrada. Você monta:

```bash
./make-p12.sh cadeia.crt chave.key mtls-client.p12
```

### Java lê PEM?

Depende do material — e é por isso que confunde:

| | PEM serve? |
|---|---|
| Client Encryption Key (só público) | **sim** — `EncryptionUtils.loadEncryptionCertificate("...pem")` |
| Identidade mTLS (cert + chave privada) | **não** — `KeyStore.getInstance("PKCS12")` quer `.p12` |

`KeyStore` não lê chave privada em PEM. Dá para fazer na unha com
`PKCS8EncodedKeySpec` + `EncryptedPrivateKeyInfo`, mas o caminho normal é
converter para `.p12`.

### Senhas: uma para os dois keystores?

Pode ser a mesma. Os dois arquivos vivem no mesmo cofre, com a mesma ACL — quem
lê um lê o outro, então senhas distintas não isolam nada. Só vale separar se as
chaves forem para sistemas ou times diferentes.

O que importa é a **entropia**, porque o KDF é fraco. Inspecionando o material
que o portal entrega:

```
p12 do portal   pbeWithSHA1And3-KeyTripleDES-CBC, 2048 iterações, MAC sha1
.key do portal  pbeWithSHA1And3-KeyTripleDES-CBC, 2048 iterações
```

SHA-1 + 3DES com 2048 iterações. Se o arquivo vazar, a senha é a única barreira,
e uma senha memorizável cai em brute force de GPU. Use a aleatória que o portal
sugere.

No p12 que **você** monta dá para melhorar: o `make-p12.sh` usa
`-iter 600000 -macalg sha256`, o que encarece cada tentativa em ~30x
(5 ms → 145 ms). O custo é uma vez, no startup, e `KeyStore`/`keytool` leem
normalmente.

> Atenção: o zip de credenciais contém **chaves privadas** (a `.key` do mTLS e o
> p12 da chave de decifragem). O portal só guardou as metades públicas, então
> esse zip é a única cópia — perdeu, revoga e gera outro. Ele não pertence à
> pasta de downloads.

### Preciso da chave de decifragem?

Nem sempre. Vários serviços mTLS cifram só a **request**. Para descobrir, veja
se a config da sua aplicação registra uma chave de decifragem:

```bash
grep -rn "withDecryptionKey" src/
```

```java
JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(cert)
    .withDecryptionKey(privateKey)         // ← se esta linha não existe,
    .withEncryptedValueFieldName("encryptedValue")   //   a resposta vem em claro
    .build();
```

Na prática: se a resposta chega sem o campo `encryptedValue`, não há nada para
decifrar. O `jwe_decrypt.py` detecta isso e só repassa o JSON.

---

## Uso

```bash
cp .env.example .env      # preencha; .env está no .gitignore
```

**1. A camada mTLS está de pé?**

```bash
./handshake.sh
```

Mostra se o servidor pede certificado, quais CAs aceita, se a senha abre o seu
keystore e se o handshake fecha. `Verify return code: 0 (ok)` sem linha `alert`
= mTLS completo.

**2. Uma chamada**

```bash
./call.sh POST /card-segments \
  '{"cardNumber":5291070000000000,"segments":[{"code":"SEU_SEGMENTO","effectiveDate":"2026-01-31"}]}'
```

**3. Utilitários**

```bash
./make-p12.sh cadeia.crt chave.key saida.p12   # monta o keystore, validando o par
python3 gen_card.py gen 529107 5               # PANs válidos por Luhn
python3 gen_card.py check 5291070000000898     # valida e mostra o dígito correto
echo '{"encryptedValue":"..."}' | python3 jwe_decrypt.py chave.p12 'senha'
```

> Os PANs dos guias de teste da Mastercard nem sempre são Luhn-válidos.
> `5291070000000898`, por exemplo, não é — o dígito verificador correto é `3`.

---

## Sandbox → produção

Três coisas mudam **juntas**, e esquecer a segunda é o erro clássico:

| | Sandbox / MTF | Produção |
|---|---|---|
| Host | `mtf.services.mastercard.com` | `services.mastercard.com` |
| Certificado mTLS | CN com `-Client-MTF-` | certificado novo |
| **Client Encryption Key** | um `.pem` | **outro `.pem`** |

Subir com o encryption key do sandbox passa no mTLS e morre em
**`ReasonCode 57 — Invalid encryption key used`**. Logar o `kid` na subida pega
isso em segundos.

Se você deixar o portal gerar o par **no navegador**, a chave privada nasce ali
e o download acontece **uma vez só**. Perdeu, não recupera: revoga e gera outro.

---

## Achando a documentação

O portal da Mastercard é uma SPA — `curl` na URL da doc devolve página vazia.
Mas existe versão Markdown de tudo, e um índice `llms.txt` por serviço:

```bash
curl https://developer.mastercard.com/llms.txt
curl https://developer.mastercard.com/<servico>/documentation/llms.txt
curl https://developer.mastercard.com/<servico>/documentation/index.md
curl https://developer.mastercard.com/<servico>/documentation/api-basics/index.md
```

O `llms.txt` do serviço traz o `auth_type` e a URL do OpenAPI spec. No spec,
`x-mastercard-api-encrypted: true` numa operação significa que o corpo **inteiro**
precisa ir cifrado.

---

## Segurança

`.gitignore` bloqueia `*.p12 *.key *.pem *.crt .env senha*`. Nenhum material
criptográfico deve entrar aqui. Guarde chave privada em cofre de secrets — `.p12`
é binário, então normalmente vai em base64:

```bash
base64 -w0 mtls-client.p12
```

## Licença

MIT
