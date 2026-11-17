"""Gera tráfego SINTÉTICO contra o servidor em execução, para a demonstração do painel.

Uso (com o servidor rodando com MODO_DEMO=1 e o MESMO APP_SECRET):
    python scripts/gerar_trafego.py normal     # uso comum: nada de grave (painel fica VERDE)
    python scripts/gerar_trafego.py amarelo    # 2 vazamentos de CPF bloqueados (16 pontos)
    python scripts/gerar_trafego.py vermelho   # + 2 tentativas de vazar senha (alta) -> 47 pontos no total
Os cenários se acumulam: rode em sequência para ver o indicador subindo.
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from app.auth import emitir_token  # noqa: E402

CPF_SINTETICO = "529.982.247-25"  # CPF de teste (dígitos válidos), não pertence a ninguém conhecido


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cenario", choices=["normal", "amarelo", "vermelho"])
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    args = ap.parse_args()
    if not os.getenv("APP_SECRET"):
        sys.exit("Defina APP_SECRET igual ao do servidor.")
    anonimo = httpx.Client(base_url=args.url, timeout=10)
    logado = httpx.Client(base_url=args.url, timeout=10,
                          headers={"Authorization": f"Bearer {emitir_token('demo')}"})

    def mostrar(rotulo, resp):
        print(f"{rotulo:<52} -> HTTP {resp.status_code}")

    if args.cenario == "normal":
        mostrar("usuário logado envia CPF (permitido, auditado)",
                logado.post("/demo/eco-inseguro", json={"obs": f"cpf {CPF_SINTETICO}"}))
    if args.cenario == "amarelo":
        for _ in range(2):
            mostrar("anônimo tenta receber CPF de volta (bloqueado)",
                    anonimo.post("/demo/eco-inseguro", json={"documento": "123.456.789-00"}))
    if args.cenario == "vermelho":
        for _ in range(2):
            mostrar("tentativa de devolver SENHA (bloqueada)",
                    logado.post("/demo/eco-inseguro", json={"senha": "senha-de-teste-123"}))


main()
