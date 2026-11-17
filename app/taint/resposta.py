"""Taint Analysis — SINK "resposta HTTP" (Parte 2).

Fica entre o app e o cliente e inspeciona o corpo de cada resposta.

Política:
- requisição NÃO autenticada: qualquer PII na resposta bloqueia (403, sem o dado);
- requisição autenticada: PII é permitida e auditada, MAS senha nunca sai.
Também registra na auditoria o PII que ENTROU na requisição (source), usando os
achados que o PIIMiddleware deixou em request.state.

Ordem no app: adicione este middleware ANTES do PIIMiddleware (o último adicionado
é o mais externo e roda primeiro, e precisa ter preenchido o state).
"""
from __future__ import annotations

import json

from app.audit import contexto, get_auditoria, severidade_maxima
from app.auth import validar_token
from app.pii.scanner import Achado, escanear

from .texto import sanitizar_texto

_TIPOS_TEXTO = ("json", "text/", "xml", "x-www-form-urlencoded")
LIMITE_PADRAO = 1_000_000


class TaintMiddleware:
    def __init__(self, app, limite_bytes: int = LIMITE_PADRAO):
        self.app = app
        self.limite = limite_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        autenticado, usuario = self._autenticar(scope)
        state["autenticado"], state["usuario"] = autenticado, usuario
        ctx = {
            "trace_id": state.get("trace_id", "-"),
            "rota": scope.get("path", "-"),
            "metodo": scope.get("method", "-"),
            "autenticado": autenticado,
        }
        marca = contexto.set(ctx)
        try:
            entrada = state.get("pii_achados", [])
            if entrada:  # source: PII que chegou na requisição
                get_auditoria().registrar(
                    "PII_RECEBIDA", "entrada", "marcada",
                    categorias=[a.categoria for a in entrada],
                    quantidade=len(entrada),
                    severidade=severidade_maxima(entrada),
                )
            await self._com_filtro_de_resposta(scope, receive, send, ctx)
        finally:
            contexto.reset(marca)

    @staticmethod
    def _autenticar(scope):
        for nome, valor in scope.get("headers", []):
            if nome == b"authorization":
                esquema, _, token = valor.decode("latin-1").partition(" ")
                if esquema.lower() == "bearer":
                    usuario = validar_token(token.strip())
                    if usuario:
                        return True, usuario
        return False, None

    async def _com_filtro_de_resposta(self, scope, receive, send, ctx):
        inicio, partes, total, repassar = None, [], 0, False

        async def interceptar(msg):
            nonlocal inicio, total, repassar
            if msg["type"] == "http.response.start":
                if self._escaneavel(msg):
                    inicio = msg  # segura até ver o corpo inteiro
                else:
                    repassar = True
                    await send(msg)
                return
            if msg["type"] != "http.response.body" or repassar:
                await send(msg)
                return
            partes.append(msg.get("body", b""))
            total += len(partes[-1])
            if msg.get("more_body", False):
                return
            await self._finalizar(inicio, b"".join(partes), total, send, ctx)

        await self.app(scope, receive, interceptar)

    @staticmethod
    def _tipo(inicio) -> str:
        for nome, valor in inicio.get("headers", []):
            if nome == b"content-type":
                return valor.decode("latin-1").lower()
        return ""

    def _escaneavel(self, inicio) -> bool:
        tipo = self._tipo(inicio)
        return tipo == "" or any(t in tipo for t in _TIPOS_TEXTO)  # sem tipo: inspeciona

    async def _finalizar(self, inicio, corpo: bytes, total: int, send, ctx):
        texto = corpo.decode("utf-8", "replace")
        if total > self.limite:  # grande demais para inspecionar
            achados = [Achado("resposta", "ESTRUTURA", "media", "valor")]
        elif "json" in self._tipo(inicio):
            try:
                achados = escanear(json.loads(texto)).achados
            except (ValueError, RecursionError):
                achados = sanitizar_texto(texto)[1]
        else:
            achados = sanitizar_texto(texto)[1]

        categorias = sorted({a.categoria for a in achados})
        bloquear = bool(achados) if not ctx["autenticado"] else "SENHA" in categorias

        if achados:
            get_auditoria().registrar(
                "RESPOSTA_BLOQUEADA" if bloquear else "PII_EM_RESPOSTA_AUTENTICADA",
                "resposta",
                "bloqueado" if bloquear else "permitido",
                categorias=categorias,
                quantidade=len(achados),
                severidade=severidade_maxima(achados) if bloquear else "baixa",
            )

        if bloquear:
            await self._enviar_bloqueio(send, ctx["trace_id"])
        else:
            await send(inicio)
            await send({"type": "http.response.body", "body": corpo})

    @staticmethod
    async def _enviar_bloqueio(send, trace_id: str):
        corpo = json.dumps(
            {"erro": "Resposta bloqueada para proteger dados pessoais.", "trace_id": trace_id}
        ).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(corpo)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": corpo})
