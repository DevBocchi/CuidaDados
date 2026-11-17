"""Tradução de eventos de segurança para linguagem de cidadão (Parte 3).

Fluxo: evento da auditoria -> catálogo (só nome + áreas) -> prompt -> LLM -> validação da
saída -> mensagem. Qualquer falha cai numa mensagem de reserva fixa: a tela do cidadão
nunca fica vazia nem mostra texto não validado.

Segurança (PDF [02] e [07]):
- o LLM nunca vê dados do usuário (rota, trace_id, valores): só texto do catálogo;
- a SAÍDA do LLM é tratada como entrada não confiável: sem HTML/markdown/URL, no máximo
  2 frases e sem PII (reaproveita `sanitizar_texto` da Parte 2);
- só resultados bem-sucedidos do LLM entram no cache; a chave nunca é logada.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from app.taint.texto import sanitizar_texto

from .catalogo import areas_do_evento, mensagem_reserva, normalizar_evento
from .prompt import montar_prompt
from .provedores import ErroLLM, carregar_config, gerar_texto

logger = logging.getLogger("cuidadados.ia")

_MIN, _MAX = 20, 400
_PROIBIDO = re.compile(r"[<>{}`|\[\]]|\*\*|https?://|www\.", re.IGNORECASE)
_FRASES = re.compile(r"(?<=[.!?])\s+")

_cache: dict[tuple, "Traducao"] = {}


@dataclass(frozen=True)
class Traducao:
    mensagem: str
    origem: str  # "llm" | "reserva"
    motivo: str = ""  # por que caiu na reserva
    provedor: str = ""


def limpar_cache() -> None:
    _cache.clear()


def validar_saida(texto: str) -> str | None:
    """Devolve o texto limpo (no máximo 2 frases) ou None se a saída não é aceitável."""
    if not isinstance(texto, str):
        return None
    texto = " ".join(texto.split()).strip().strip("\"'“”")
    if _PROIBIDO.search(texto):
        return None
    texto = " ".join(_FRASES.split(texto)[:2])
    if not (_MIN <= len(texto) <= _MAX):
        return None
    _, achados = sanitizar_texto(texto)
    if achados:
        return None
    return texto


def _reserva(nome: str, areas: tuple[str, ...], motivo: str, provedor: str = "") -> Traducao:
    return Traducao(mensagem_reserva(nome, areas), "reserva", motivo, provedor)


async def traduzir_evento(evento: dict, *, cliente: httpx.AsyncClient | None = None) -> Traducao:
    """`evento` é uma linha da auditoria; só `evento` (nome) e `categorias` são usados."""
    nome = normalizar_evento(str(evento.get("evento", "")))
    areas = areas_do_evento(evento.get("categorias") or [])
    config = carregar_config()
    if not config.pronta:
        return _reserva(nome, areas, "sem_configuracao")

    chave_cache = (nome, areas, config.provedor, config.modelo)
    if chave_cache in _cache:
        return _cache[chave_cache]

    try:
        bruto = await gerar_texto(montar_prompt(nome, areas), config, cliente)
    except ErroLLM as erro:
        logger.warning("LLM indisponível: motivo=%s %s provedor=%s", erro.motivo, erro.detalhe, config.provedor)
        return _reserva(nome, areas, erro.motivo, config.provedor)

    texto = validar_saida(bruto)
    if texto is None:
        logger.warning("Saída do LLM rejeitada pela validação: provedor=%s", config.provedor)
        return _reserva(nome, areas, "saida_rejeitada", config.provedor)

    resultado = Traducao(texto, "llm", "", config.provedor)
    _cache[chave_cache] = resultado
    return resultado
