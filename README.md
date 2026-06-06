# Criptografia Aplicada em Java — Cifra Simétrica e Assinatura Digital

Sistema de segurança informática que implementa **cifra autenticada com AES-CBC + HMAC-SHA256** e **assinatura/verificação digital com RSA**, desenvolvido no âmbito da unidade curricular de **Segurança Informática** do curso de Engenharia Informática e Multimédia no ISEL.

---

## Contexto e Motivação

Este projeto foi desenvolvido como trabalho prático da unidade curricular de **Segurança Informática**, com o objetivo de implementar, de raiz em Java, dois mecanismos fundamentais de segurança criptográfica:

- **Confidencialidade e integridade** de ficheiros através de cifra simétrica autenticada
- **Autenticidade e não-repúdio** através de assinatura digital com cadeia de certificados PKI

O projeto obrigou a trabalhar diretamente com as APIs da JCA/JCE (*Java Cryptography Architecture/Extension*), sem recorrer a bibliotecas de alto nível, o que proporcionou uma compreensão aprofundada dos mecanismos subjacentes.

---

## Principais Funcionalidades

- **Cifra de ficheiros** com AES-CBC (128-bit) e padding PKCS5, com geração automática de IV aleatório por operação
- **Autenticação da cifra** via HMAC-SHA256, seguindo o esquema *Encrypt-then-MAC* — a integridade é verificada antes de qualquer decifra
- **Assinatura digital RSA** de ficheiros arbitrários (suporta SHA-1 e SHA-256), com leitura de chave privada a partir de KeyStore PKCS12
- **Verificação de assinatura** com validação completa da cadeia de certificados X.509 (folha → intermédia → âncora de confiança)
- **Gestão automática de chaves** — geração e persistência em ficheiro binário quando a chave ainda não existe
- **Suporte a ficheiros de grande dimensão** através de leitura incremental por blocos de 8KB

---

## Tecnologias Empregues

- **Java 25**
- **JCA/JCE** (Java Cryptography Architecture/Extension)
- **AES-CBC com PKCS5Padding**
- **HMAC-SHA256**
- **RSA** (SHA1withRSA / SHA256withRSA)
- **X.509 / PKIX** — validação de cadeia de certificados
- **PKCS12** — formato de KeyStore para chave privada + certificado

---

## Arquitetura

| Pacote / Classe | Responsabilidade |
|---|---|
| `seginf.CriptoUtil` | Utilitários de geração de chaves, IV, HMAC e codificação Base64 |
| `seginf.AEEengine` | Motor de cifra/decifra autenticada (Encrypt-then-MAC) |
| `seginf.AEapp` | Aplicação CLI para cifrar/decifrar ficheiros |
| `AssinaturaDigital.RSASignVerify` | Assinatura e verificação com RSA + validação PKIX |

---

## Impacto e Aprendizagem

- **Encrypt-then-MAC** — compreensão da ordem correta de operações numa cifra autenticada e das consequências de a inverter
- **Gestão de IV** — importância da aleatoriedade e unicidade do vetor de inicialização por operação de cifra
- **PKI e cadeias de confiança** — validação PKIX com âncoras de confiança configuráveis, distinguindo certificados válidos de inválidos para diferentes hierarquias de CA
- **Leitura incremental** — processamento seguro de ficheiros de grande dimensão sem carregar o conteúdo integralmente em memória
- **Separação de chaves** — uso de chaves distintas para AES e HMAC, evitando reutilização de material criptográfico
