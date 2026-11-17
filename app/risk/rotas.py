"""Rotas do painel (Parte 4).

- GET /dashboard (+ painel.js/painel.css): arquivos estáticos, sem nenhum dado, com CSP
  restritiva (mitiga XSS: PDF [07], sanitização de saída).
- GET /risco: indicador + explicações em linguagem de cidadão. EXIGE token (os eventos
  de segurança são sensíveis). A resposta só contém números, categorias e texto validado.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

from app.ai import traduzir_evento
from app.audit import get_auditoria

from .formula import JANELA_PADRAO_MIN, agrupar_ocorrencias, calcular_risco

PASTA = Path(__file__).resolve().parent.parent.parent / "dashboard"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
CABECALHOS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
              "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}
ARQUIVOS = {"/dashboard": "index.html", "/dashboard/painel.js": "painel.js",
            "/dashboard/painel.css": "painel.css"}
LIMITE_EVENTOS = 1000


def _janela() -> int:
    try:
        return max(1, int(os.getenv("RISCO_JANELA_MIN", JANELA_PADRAO_MIN)))
    except ValueError:
        return JANELA_PADRAO_MIN


def registrar_rotas(app: FastAPI) -> None:
    for caminho, arquivo in ARQUIVOS.items():
        def _servir(arquivo=arquivo):
            async def rota():
                return FileResponse(PASTA / arquivo, headers=CABECALHOS)
            return rota
        app.add_api_route(caminho, _servir(), methods=["GET"], include_in_schema=False)

    @app.get("/risco")
    async def risco(request: Request):
        if not getattr(request.state, "autenticado", False):
            raise HTTPException(status_code=401, detail="Autenticação necessária.")
        agora = datetime.now(timezone.utc)
        janela = _janela()
        eventos = get_auditoria().listar(LIMITE_EVENTOS)
        resumo = calcular_risco(eventos, janela_min=janela, agora=agora)
        grupos = agrupar_ocorrencias(eventos, janela_min=janela, agora=agora)
        traducoes = await asyncio.gather(*(traduzir_evento(g) for g in grupos))
        resumo["explicacoes"] = [
            {
                "evento": g["evento"],
                "areas": g["categorias"],
                "ocorrencias": g["ocorrencias"],
                "pontos": g["pontos"],
                "mensagem": t.mensagem,
                "origem": t.origem,
            }
            for g, t in zip(grupos, traducoes)
        ]
        resumo["atualizado_em"] = agora.isoformat(timespec="seconds")
        resumo["truncado"] = len(eventos) >= LIMITE_EVENTOS
        return resumo
