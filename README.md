# Mastercard mTLS + JWE

Scripts para integrar com APIs Mastercard que usam **mTLS** e **payload
encryption (JWE)**, sem as bibliotecas Java da Mastercard.

Precisa de `openssl`, `curl` e Python com a lib `cryptography`.

---

## Antes de começar: os dois `.p12`

A maior fonte de confusão. São **dois arquivos diferentes**, com papéis diferentes:

| | p12 de **identidade** (mTLS) | p12 de **decifragem** |
|---|---|---|
| Para quê | provar quem você é no handshake TLS | decifrar a resposta da API |
| De onde vem | **você monta** do `.crt` + `.key` | **já vem pronto** no zip do portal |
| Precisa? | **sempre** | só se a resposta vier cifrada |

> **"Se eu não uso decrypt, não preciso gerar o p12?"**
> Precisa sim — o do mTLS, sempre. Sem ele você não conecta.
> O que você ignora é o **outro** p12, o de decifragem. E esse você nunca gera:
> ele já vem gerado dentro do zip.

---

## O que o portal te entrega

Ao criar o projeto, você baixa um zip com 4 arquivos:

| Arquivo | O que é | Tem segredo? |
|---|---|---|
| `...-signing.crt` | cadeia de certificados do seu cliente mTLS | não |
| `...-private-key.key` | a chave privada dele, cifrada | **sim** |
| `...client-encryption-key.pem` | certificado público da Mastercard | não |
| `...client-signature-verification-key.p12` | seu par de chaves para decifragem | **sim** |

Os dois primeiros são as metades do mesmo par — você junta num `.p12` no Passo 2.

---

## Passo a passo

### Passo 1 — clonar e preparar

```bash
git clone https://github.com/Recapi/mastercard-mtls-jwe.git
cd mastercard-mtls-jwe
mkdir -p certs          # está no .gitignore
```

Descompacte o zip do portal dentro de `certs/`.

### Passo 2 — montar o p12 do mTLS

```bash
./make-p12.sh certs/*-signing.crt certs/*-private-key.key certs/mtls-client.p12
```

Ele pede duas senhas: a da `.key` (que você definiu no portal) e a do `.p12` que
vai sair. Antes de empacotar, confere que a chave realmente corresponde ao
certificado — se não corresponder, ele para aí.

### Passo 3 — configurar

```bash
cp .env.example .env
```

```bash
MC_BASE_URL='https://mtf.services.mastercard.com/loyalty/benefits'
MC_P12='certs/mtls-client.p12'
MC_P12_PASS='a-senha-do-p12'
MC_ENC_CERT='certs/...client-encryption-key.pem'
```

Use **aspas simples** — senhas costumam ter `!` e `$`, que o shell interpreta.
Deixe `MC_DEC_P12` vazio por enquanto (Passo 6 decide se você precisa dele).

### Passo 4 — testar o mTLS isolado

```bash
./handshake.sh
```

Você quer ver `Verify return code: 0 (ok)` **sem** nenhuma linha `alert`.
Se falhar aqui, o problema é certificado ou senha — não adianta seguir.

### Passo 5 — fazer uma chamada

```bash
./call.sh POST /card-segments \
  '{"cardNumber":5291070000000000,"segments":[{"code":"SEU_SEGMENTO","effectiveDate":"2026-01-31"}]}'
```

O script cifra o corpo em JWE, envia por mTLS e imprime a resposta.

### Passo 6 — a resposta veio cifrada?

Olhe o que o Passo 5 devolveu:

- **JSON normal** → acabou. Você não precisa do p12 de decifragem. Ignore-o.
- **`{"encryptedValue": "..."}`** → preencha no `.env`:

```bash
MC_DEC_P12='certs/...signature-verification-key.p12'
MC_DEC_P12_PASS='a-senha-que-voce-definiu-no-portal'
```

Rode o Passo 5 de novo — agora o `call.sh` decifra sozinho.

No código da sua aplicação, o equivalente é uma linha só:

```java
JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(cert)
    .withDecryptionKey(privateKey)      // ← existe? então usa decrypt
    .withEncryptedValueFieldName("encryptedValue")
    .build();
```

Para conferir num projeto existente: `grep -rn "withDecryptionKey" src/`

---

## Em Java

### Com a biblioteca da Mastercard

Não existe método que você escreve. O `OkHttpJweInterceptor` intercepta a
resposta, decifra e entrega o JSON já em claro para o client gerado. A única
alavanca é uma linha na config:

```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
        .withEncryptionCertificate(encryptionCertificate)   // cifra a request
        .withDecryptionKey(privateKey)                      // decifra a resposta
        .withEncryptedValueFieldName("encryptedValue")
        .build();

httpClientBuilder.addInterceptor(new OkHttpJweInterceptor(config));
```

Sem `.withDecryptionKey(...)`, o interceptor só cifra a request e repassa a
resposta como veio.

### Sem a biblioteca

Se você precisa decifrar na mão, é isto — só `javax.crypto`, sem dependência:

```java
/** Decifra o conteúdo do campo "encryptedValue" de uma resposta da Mastercard. */
public static String decrypt(String jwe, PrivateKey privateKey) throws Exception {
    String[] p = jwe.split("\\.");
    Base64.Decoder b64 = Base64.getUrlDecoder();

    // 1. desembrulha a chave AES de uso único com a SUA chave privada
    Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsa.init(Cipher.DECRYPT_MODE, privateKey, new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    SecretKey cek = new SecretKeySpec(rsa.doFinal(b64.decode(p[1])), "AES");

    // 2. decifra o payload. O header em base64url, como veio na wire, é o AAD
    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    aes.init(Cipher.DECRYPT_MODE, cek, new GCMParameterSpec(128, b64.decode(p[2])));
    aes.updateAAD(p[0].getBytes(StandardCharsets.US_ASCII));

    byte[] ct = b64.decode(p[3]), tag = b64.decode(p[4]);
    byte[] sealed = ByteBuffer.allocate(ct.length + tag.length).put(ct).put(tag).array();
    return new String(aes.doFinal(sealed), StandardCharsets.UTF_8);
}
```

Carregando a chave privada do `.p12`:

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
ks.load(new FileInputStream(p12Path), password.toCharArray());
String alias = ks.aliases().nextElement();
PrivateKey pk = (PrivateKey) ks.getKey(alias, password.toCharArray());
```

> **Armadilha:** o `OAEPParameterSpec` explícito não é opcional. Sem ele o Java
> usa MGF1 com **SHA-1**, mesmo o nome do algoritmo dizendo SHA-256, e você leva
> `javax.crypto.BadPaddingException: Padding error in decryption` — erro que não
> dá nenhuma pista da causa real.

---

## Como descobrir se o seu projeto usa decrypt

Quatro buscas, na ordem:

```bash
# 1. a aplicação registra chave de decifragem?
grep -rn "withDecryptionKey" src/

# 2. onde o secret é lido?
grep -rn "DESCRIP" src/ --include=*.java --include=*.yaml --include=*.properties

# 3. decifragem manual, sem a lib?
grep -rn "OAEPWithSHA-256AndMGF1Padding\|AES/GCM/NoPadding\|encryptedValue" src/
```

| Resultado | Significa |
|---|---|
| (1) retorna algo | usa decrypt — o secret é necessário |
| (1) vazio, (3) retorna | decifra na mão — o secret é necessário |
| (1) e (3) vazios, (2) retorna | o secret é lido e descartado — **secret morto** |
| tudo vazio | o secret nem é referenciado |

A confirmação definitiva não está no código, e sim na resposta: se ela chega sem
o campo `encryptedValue`, não há nada para decifrar. O Passo 6 responde isso em
uma chamada.

---

## Onde cada arquivo entra na aplicação

| Secret | Conteúdo | Formato |
|---|---|---|
| `P12` | `mtls-client.p12` do Passo 2 | base64 (`base64 -w0`) |
| `PASSWORD` | senha do p12 acima | texto |
| `ENCRIPT` | `...client-encryption-key.pem` | **PEM, não converta** |
| `DESCRIP` | p12 de decifragem | base64 — só se o Passo 6 pediu |

**Java lê PEM?** Depende do material:

- Encryption key (só público) → **sim**: `EncryptionUtils.loadEncryptionCertificate("...pem")`
- Identidade mTLS (cert + chave privada) → **não**: `KeyStore.getInstance("PKCS12")` quer `.p12`

`KeyStore` não lê chave privada em PEM. Por isso o Passo 2 existe.

---

## Quando der erro

As três camadas falham de jeitos distintos. O erro diz onde você parou:

| Sintoma | Camada | O que olhar |
|---|---|---|
| `alert` no handshake, `INVALID_CLIENT_CERT` | mTLS | certificado, senha, cadeia |
| HTTP 500 genérico | JWE | corpo chegou mas não decifrou |
| `ReasonCode 57` *Invalid encryption key* | JWE | cifrou com o `.pem` errado |
| `ReasonCode` de negócio | — | **a parte técnica está OK** |

Um 500 que vira erro de negócio é **progresso**: mTLS passou e o JWE foi decifrado.

O `jwe_encrypt.py` imprime o `kid` em stderr a cada chamada. Ele tem que bater
com o *Fingerprint* mostrado no dashboard — é o jeito mais rápido de confirmar
que você está usando o certificado certo.

---

## Sandbox → produção

Três coisas mudam **juntas**:

| | Sandbox / MTF | Produção |
|---|---|---|
| Host | `mtf.services.mastercard.com` | `services.mastercard.com` |
| Certificado mTLS | CN com `-Client-MTF-` | certificado novo |
| **Encryption key** | um `.pem` | **outro `.pem`** |

Esquecer o terceiro é o erro clássico: passa no mTLS e morre em
**`ReasonCode 57`**. Refaça o Passo 2 com o zip novo e troque as duas linhas
no `.env`.

Se o portal gerar o par **no navegador**, o download acontece **uma vez só**.
Perdeu, não recupera: revoga e gera outro.

---

## Utilitários

```bash
python3 gen_card.py gen 529107 5            # PANs válidos por Luhn
python3 gen_card.py check 5291070000000898  # valida e mostra o dígito correto
echo '{"encryptedValue":"..."}' | python3 jwe_decrypt.py chave.p12 'senha'
```

> PANs de guias de teste nem sempre são Luhn-válidos. `5291070000000898`, por
> exemplo, não é — o dígito correto é `3`.

---

## Referência

### Formato do JWE

```
alg = RSA-OAEP-256    envelopa a chave AES com a pública da Mastercard
enc = A256GCM         cifra o payload com AES-256-GCM
kid = SHA-256 hex da chave pública (o "Fingerprint" do dashboard)
```

```json
{"encryptedValue":"<header>.<chave>.<iv>.<ciphertext>.<tag>"}
```

### Achando a documentação

O portal é uma SPA — `curl` na URL da doc devolve página vazia. Mas existe
versão Markdown de tudo:

```bash
curl https://developer.mastercard.com/<servico>/documentation/llms.txt
curl https://developer.mastercard.com/<servico>/documentation/index.md
curl https://developer.mastercard.com/<servico>/documentation/api-basics/index.md
```

O `llms.txt` traz o `auth_type` e a URL do OpenAPI spec. No spec,
`x-mastercard-api-encrypted: true` significa que o corpo **inteiro** vai cifrado.

### Senhas

Pode usar a mesma nos dois keystores — eles vivem no mesmo cofre com a mesma
ACL, então senhas distintas não isolam nada.

O que importa é a entropia, porque o KDF do portal é fraco
(`pbeWithSHA1And3-KeyTripleDES-CBC`, 2048 iterações, MAC sha1). Se o arquivo
vazar, a senha é a única barreira. Use a aleatória que o portal sugere.

No p12 que você monta dá para melhorar, e o `make-p12.sh` já faz:
`-iter 600000 -macalg sha256` encarece cada tentativa em ~30x (5 ms → 145 ms),
custo pago uma vez no startup.

### Segurança

`.gitignore` bloqueia `*.p12 *.key *.pem *.crt .env senha*`.

O zip do portal contém **chaves privadas sem cópia de recuperação** — ele não
pertence à pasta de downloads.

## Licença

MIT
