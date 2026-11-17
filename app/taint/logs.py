"""Taint Analysis — SINK "log" (Parte 2).

Troca a fábrica de LogRecord do Python: TODO registro de log, de qualquer logger e de
qualquer handler, é inspecionado no momento em que nasce, antes de ser formatado ou
escrito em arquivo/console. Assim `logger.info(cpf)` ou `logger.exception(...)` não
conseguem imprimir PII em texto claro, mesmo em código que esqueceu de proteger.

Na linha de log o PII é mascarado (o log continua útil para depurar) e o evento vai
para a auditoria.
"""
from __future__ import annotations

import logging
import traceback
from contextvars import ContextVar

from app.audit import get_auditoria, severidade_maxima

from .texto import sanitizar_texto

_ocupado: ContextVar[bool] = ContextVar("protecao_logs_ocupada", default=False)
_fabrica_original = None


def instalar_protecao_de_logs() -> None:
    global _fabrica_original
    if _fabrica_original is not None:  # já instalada
        return
    _fabrica_original = logging.getLogRecordFactory()
    original = _fabrica_original

    def fabrica(*args, **kwargs):
        registro = original(*args, **kwargs)
        if _ocupado.get():  # evita recursão (a auditoria também escreve log)
            return registro
        marca = _ocupado.set(True)
        try:
            _sanitizar_registro(registro)
        finally:
            _ocupado.reset(marca)
        return registro

    logging.setLogRecordFactory(fabrica)


def _sanitizar_registro(r: logging.LogRecord) -> None:
    try:
        mensagem = r.getMessage()
    except Exception:  # formato inválido (ex.: %d com Sensitive): não derruba o app
        mensagem = f"{r.msg} {r.args}"
    nova, achados = sanitizar_texto(mensagem)
    if achados:
        r.msg, r.args = nova, ()

    texto_excecao = r.exc_text
    if r.exc_info and not texto_excecao:
        texto_excecao = "".join(traceback.format_exception(*r.exc_info))
    if texto_excecao:  # stack trace também é sink
        seguro, achados_exc = sanitizar_texto(texto_excecao)
        r.exc_text = seguro
        achados = achados + achados_exc

    if achados:
        try:
            get_auditoria().registrar(
                "LOG_SANITIZADO",
                "log",
                "mascarado",
                categorias=[a.categoria for a in achados],
                quantidade=len(achados),
                severidade=severidade_maxima(achados),
            )
        except Exception:
            pass  # auditoria nunca pode derrubar o log
