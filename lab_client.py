#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lab_client.py — cliente do LABORATORIO SINTETICO (CommandGateLab.java).

Mostra como um gatilho "OOB" leva, numa aplicacao com gate proprio, a execucao
de um comando fixo/benigo (id / whoami). Isto e DIDATICO: a aplicacao e que
decide executar, nao o bug do JVM. Nao e um exploit de CVE-2026-114938.
"""

import argparse
import http.client
import sys

TRIGGER = "A" * 64 + "="  # gatilho publico documentado (JDK 21/25)
CLEAN = "A" * 64          # sem padding -> nao dispara o gate do laboratorio


def post(host, port, path, payload):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("POST", path, body=payload.encode("ascii"),
                     headers={"Content-Type": "text/plain"})
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Cliente do laboratorio sintetico")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/decode")
    a = ap.parse_args()

    print("=== 1) payload LIMPO (sem gate) ===")
    print(post(a.host, a.port, a.path, CLEAN)[1])

    print("=== 2) payload GATILHO (gate da aplicacao -> id/whoami) ===")
    print(post(a.host, a.port, a.path, TRIGGER)[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
