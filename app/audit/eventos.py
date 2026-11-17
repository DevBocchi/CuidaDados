"""Auditoria (Parte 2): "quem fez o quê, quando e onde", SEM valores originais.

Cada evento vai para duas saídas:
- SQLite (consultável; alimenta o Risco Cidadão na Parte 4);
- uma linha JSON no logger "auditoria" (log estruturado, como no PDF [07]).
Eventos guardam só categoria, quantidade, gravidade e rota — nunca o dado em si.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path

ORDEM_SEVERIDADE = {"baixa": 0, "media": 1, "alta": 2}

# Preenchido pelo middleware a cada requisição: trace_id, rota, método, autenticado.
contexto: ContextVar[dict] = ContextVar("contexto_auditoria", default={})

_log = logging.getLogger("auditoria")
_log.propagate = False
_handlers: list[logging.Handler] = []

_DDL = """
CREATE TABLE IF NOT EXISTS eventos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    trace_id TEXT,
    evento TEXT NOT NULL,
    sink TEXT NOT NULL,
    acao TEXT NOT NULL,
    categorias TEXT NOT NULL,
    quantidade INTEGER NOT NULL,
    severidade TEXT NOT NULL,
    rota TEXT,
    metodo TEXT,
    autenticado INTEGER NOT NULL
)
"""


def severidade_maxima(achados) -> str:
    sevs = [a.severidade for a in achados] or ["baixa"]
    return max(sevs, key=ORDEM_SEVERIDADE.__getitem__)


class Auditoria:
    def __init__(self, caminho: str):
        self.caminho = caminho
        Path(caminho).parent.mkdir(parents=True, exist_ok=True)
        with self._conectar() as con:
            con.execute(_DDL)

    @contextmanager
    def _conectar(self):
        con = sqlite3.connect(self.caminho, timeout=5)
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def registrar(
        self,
        evento: str,
        sink: str,
        acao: str,
        categorias=(),
        quantidade: int = 1,
        severidade: str = "baixa",
        *,
        trace_id: str | None = None,
        rota: str | None = None,
        metodo: str | None = None,
        autenticado: bool | None = None,
    ) -> dict:
        ctx = contexto.get()
        reg = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "trace_id": trace_id or ctx.get("trace_id", "-"),
            "evento": evento,
            "sink": sink,  # entrada | log | resposta | erro
            "acao": acao,  # marcada | mascarado | bloqueado | permitido
            "categorias": sorted(set(categorias)),
            "quantidade": int(quantidade),
            "severidade": severidade,
            "rota": rota or ctx.get("rota", "-"),
            "metodo": metodo or ctx.get("metodo", "-"),
            "autenticado": bool(ctx.get("autenticado", False) if autenticado is None else autenticado),
        }
        with self._conectar() as con:
            con.execute(
                "INSERT INTO eventos (ts, trace_id, evento, sink, acao, categorias, quantidade,"
                " severidade, rota, metodo, autenticado) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    reg["ts"], reg["trace_id"], reg["evento"], reg["sink"], reg["acao"],
                    json.dumps(reg["categorias"]), reg["quantidade"], reg["severidade"],
                    reg["rota"], reg["metodo"], int(reg["autenticado"]),
                ),
            )
        _log.info(json.dumps(reg, ensure_ascii=False))
        return reg

    def listar(self, limite: int = 100) -> list[dict]:
        """Eventos do mais novo para o mais antigo."""
        with self._conectar() as con:
            con.row_factory = sqlite3.Row
            linhas = con.execute("SELECT * FROM eventos ORDER BY id DESC LIMIT ?", (limite,)).fetchall()
        eventos = []
        for linha in linhas:
            e = dict(linha)
            e["categorias"] = json.loads(e["categorias"])
            e["autenticado"] = bool(e["autenticado"])
            eventos.append(e)
        return eventos


_instancia: Auditoria | None = None


def configurar(caminho: str | None = None, saida_console: bool = False, arquivo_log: str | None = None) -> Auditoria:
    """Define onde a auditoria é gravada. Pode ser chamada de novo (ex.: nos testes)."""
    global _instancia
    _instancia = Auditoria(caminho or os.getenv("AUDIT_DB", "data/auditoria.db"))

    for h in _handlers:
        _log.removeHandler(h)
    _handlers.clear()
    _log.setLevel(logging.INFO)
    if saida_console:
        _handlers.append(logging.StreamHandler(sys.stdout))
    if arquivo_log:
        Path(arquivo_log).parent.mkdir(parents=True, exist_ok=True)
        _handlers.append(logging.FileHandler(arquivo_log, encoding="utf-8"))
    for h in _handlers:
        h.setFormatter(logging.Formatter("%(message)s"))
        _log.addHandler(h)
    return _instancia


def get_auditoria() -> Auditoria:
    return _instancia if _instancia is not None else configurar()
