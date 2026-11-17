"""CuidaDados — app FastAPI (Partes 1 a 4).

Rotas /demo/* existem só com MODO_DEMO=1 (padrão: desligado). Endpoint de teste
esquecido em produção é uma das exposições acidentais do PDF [07].
"""
import logging
import os
from typing import Any

from fastapi import Body, Depends, FastAPI, Request
from pydantic import BaseModel

from app.audit import configurar as configurar_auditoria
from app.pii import PIIMiddleware
from app.risk.rotas import registrar_rotas as registrar_rotas_risco
from app.taint import (
    TaintMiddleware,
    corpo_marcado,
    instalar_protecao_de_logs,
    registrar_handlers,
)

logger = logging.getLogger("cuidadados")

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
configurar_auditoria(saida_console=True, arquivo_log=os.getenv("AUDIT_LOG_FILE"))
instalar_protecao_de_logs()


class Cadastro(BaseModel):
    nome: str
    idade: int


def criar_app(modo_demo: bool | None = None) -> FastAPI:
    if modo_demo is None:
        modo_demo = os.getenv("MODO_DEMO", "0") == "1"
    app = FastAPI(title="CuidaDados")
    app.add_middleware(TaintMiddleware)  # interno: lê o state preenchido pelo PII
    app.add_middleware(PIIMiddleware)  # externo: roda primeiro
    registrar_handlers(app)
    registrar_rotas_risco(app)  # Parte 4: /risco (autenticado) e /dashboard
    if modo_demo:
        _rotas_demo(app)
    return app


def _rotas_demo(app: FastAPI) -> None:
    @app.post("/demo/pii")
    async def demo_pii(request: Request, payload: Any = Body(default=None)):
        """Parte 1: devolve só a versão sanitizada e os achados."""
        return {
            "trace_id": request.state.trace_id,
            "achados": [a.como_dict() for a in request.state.pii_achados],
            "corpo_sanitizado": request.state.corpo_sanitizado,
            "query_sanitizada": request.state.query_sanitizada,
        }

    @app.post("/demo/eco-inseguro")
    async def eco_inseguro(payload: Any = Body(default=None)):
        """INSEGURA DE PROPÓSITO: devolve o corpo cru. Serve para provar que o sink de
        resposta bloqueia PII para quem não está autenticado."""
        return payload

    @app.post("/demo/fonte")
    async def fonte(corpo: Any = Depends(corpo_marcado)):
        """Source: o corpo chega marcado; logar o corpo não vaza (aparece [REDACTED])."""
        logger.info("corpo recebido: %s", corpo)
        return {"recebido": True}

    @app.post("/demo/cadastro")
    async def cadastro(dados: Cadastro):
        """Valida com Pydantic: um 422 não pode refletir o corpo enviado."""
        return {"ok": True}

    @app.get("/demo/erro")
    async def erro():
        raise RuntimeError("falha ao processar cpf 529.982.247-25")


app = criar_app()
