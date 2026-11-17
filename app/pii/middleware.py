"""Middleware de PII (Parte 1): intercepta cada requisição, marca e sanitiza.

O handler continua recebendo o corpo ORIGINAL (precisa dele para, por exemplo, fazer
hash da senha). O que o middleware entrega são as versões sanitizadas, que são as
únicas que podem ir para log, banco ou resposta:

    request.state.trace_id          id da requisição (também vai no header X-Trace-Id)
    request.state.pii_achados       lista de Achado (sem valores originais)
    request.state.corpo_sanitizado  corpo com PII mascarada
    request.state.query_sanitizada  query string com PII mascarada
    request.state.varredura_ignorada  True se o corpo passou do limite e não foi lido
"""
from __future__ import annotations

import json
import uuid
from urllib.parse import parse_qsl

from .detectors import SEVERIDADE
from .scanner import Achado, escanear

LIMITE_PADRAO = 1_000_000  # bytes


class PIIMiddleware:
    def __init__(self, app, limite_bytes: int = LIMITE_PADRAO):
        self.app = app
        self.limite = limite_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        trace_id = uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["trace_id"] = trace_id

        # Lê o corpo inteiro e o reentrega ao handler depois (replay).
        mensagens, corpo, excedeu = [], b"", False
        while True:
            msg = await receive()
            mensagens.append(msg)
            if msg["type"] != "http.request":
                break
            if not excedeu:
                corpo += msg.get("body", b"")
                if len(corpo) > self.limite:
                    excedeu, corpo = True, b""
            if not msg.get("more_body", False):
                break

        fila = iter(mensagens)

        async def receive_replay():
            try:
                return next(fila)
            except StopIteration:
                return await receive()

        consulta = dict(parse_qsl(scope.get("query_string", b"").decode("utf-8", "replace")))
        resultado = escanear({"query": consulta, "corpo": self._interpretar(corpo, scope)})

        achados = list(resultado.achados)
        if excedeu:  # falha fechada: avisa que o corpo não foi inspecionado
            achados.append(Achado("corpo", "ESTRUTURA", SEVERIDADE["ESTRUTURA"], "valor"))

        state["pii_achados"] = achados
        state["query_sanitizada"] = resultado.sanitizado["query"]
        state["corpo_sanitizado"] = None if excedeu else resultado.sanitizado["corpo"]
        state["varredura_ignorada"] = excedeu

        async def send_com_trace(msg):
            if msg["type"] == "http.response.start":
                msg = {**msg, "headers": [*msg.get("headers", []), (b"x-trace-id", trace_id.encode())]}
            await send(msg)

        await self.app(scope, receive_replay, send_com_trace)

    @staticmethod
    def _interpretar(corpo: bytes, scope):
        if not corpo:
            return None
        tipo = next(
            (v.decode("latin-1").lower() for k, v in scope.get("headers", []) if k == b"content-type"),
            "",
        )
        texto = corpo.decode("utf-8", "replace")
        if "json" in tipo:
            try:
                return json.loads(texto)
            except (ValueError, RecursionError):
                return texto  # JSON inválido ou fundo demais: varre como texto
        if "x-www-form-urlencoded" in tipo:
            return dict(parse_qsl(texto))
        return texto
