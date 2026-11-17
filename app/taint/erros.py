"""Taint Analysis — SINK "erro" (Parte 2): erros nunca devolvem dados nem stack trace.

- 422 do FastAPI normalmente devolve `input` com o corpo enviado (reflete a senha!).
  Aqui devolvemos só o nome do campo e o motivo.
- 500 devolve mensagem genérica; o detalhe técnico vai para o log (já sanitizado).
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.audit import contexto, get_auditoria, severidade_maxima
from app.pii.scanner import escanear

logger = logging.getLogger("cuidadados.erros")


def _contexto(request: Request) -> dict:
    return {
        "trace_id": getattr(request.state, "trace_id", "-"),
        "rota": request.url.path,
        "metodo": request.method,
        "autenticado": getattr(request.state, "autenticado", False),
    }


def registrar_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validacao(request: Request, exc: RequestValidationError):
        erros = exc.errors()
        achados = escanear(erros).achados  # 'input' pode refletir o corpo enviado
        if achados:
            get_auditoria().registrar(
                "ENTRADA_REFLETIDA_BLOQUEADA", "erro", "bloqueado",
                categorias=[a.categoria for a in achados],
                quantidade=len(achados),
                severidade=severidade_maxima(achados),
                **_contexto(request),
            )
        campos = [
            {"campo": ".".join(str(p) for p in e.get("loc", ())), "motivo": e.get("msg", "inválido")}
            for e in erros
        ]
        return JSONResponse(
            status_code=422,
            content={"erro": "Dados inválidos", "campos": campos, "trace_id": _contexto(request)["trace_id"]},
        )

    @app.exception_handler(Exception)
    async def interno(request: Request, exc: Exception):
        ctx = _contexto(request)
        marca = contexto.set(ctx)  # este handler roda fora do middleware: leva o contexto junto
        try:
            logger.error("erro interno na requisição", exc_info=(type(exc), exc, exc.__traceback__))
            get_auditoria().registrar("ERRO_INTERNO", "erro", "bloqueado", severidade="media")
        finally:
            contexto.reset(marca)
        return JSONResponse(
            status_code=500,
            content={"erro": "Erro interno. Tente novamente mais tarde.", "trace_id": ctx["trace_id"]},
        )
