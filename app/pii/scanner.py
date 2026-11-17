"""Varredura de PII em dados que entram (JSON, query, texto) — Parte 1.

Regra de ouro: os achados NUNCA carregam o valor original, só caminho e categoria.
Isso permite registrar o evento em log sem vazar o dado (Parte 2).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .detectors import (
    CPF_FORMATADO,
    CPF_PURO,
    RG_FORMATADO,
    SEVERIDADE,
    classificar_chave,
    cpf_valido,
)
from .masking import mascarar_cpf, mascarar_generico, redigir


@dataclass(frozen=True)
class Achado:
    caminho: str  # ex.: "corpo.pessoas[1].cpf"
    categoria: str  # CPF, RG, SENHA, SAUDE, ESTRUTURA
    severidade: str  # baixa, media, alta
    origem: str  # "chave" ou "valor"

    def como_dict(self) -> dict:
        return asdict(self)


@dataclass
class Resultado:
    sanitizado: Any
    achados: list[Achado] = field(default_factory=list)

    @property
    def tem_pii(self) -> bool:
        return bool(self.achados)


def escanear(dados: Any, max_profundidade: int = 20) -> Resultado:
    """Devolve uma cópia sanitizada de `dados` e a lista de achados."""
    achados: list[Achado] = []
    sanitizado = _visitar(dados, "", 0, max_profundidade, achados)
    return Resultado(sanitizado, achados)


def _visitar(valor, caminho, prof, max_prof, achados):
    if prof > max_prof:  # falha fechada: estrutura profunda demais não é inspecionada
        achados.append(Achado(caminho or "$", "ESTRUTURA", SEVERIDADE["ESTRUTURA"], "valor"))
        return redigir("ESTRUTURA")

    if isinstance(valor, dict):
        saida = {}
        for chave, v in valor.items():
            sub = f"{caminho}.{chave}" if caminho else str(chave)
            categoria = classificar_chave(str(chave))
            if categoria and v is not None and v != "" and not ja_protegido(v, categoria):
                saida[chave], final = proteger_por_chave(v, categoria)
                achados.append(Achado(sub, final, SEVERIDADE[final], "chave"))
            else:
                saida[chave] = _visitar(v, sub, prof + 1, max_prof, achados)
        return saida

    if isinstance(valor, (list, tuple)):
        return [
            _visitar(v, f"{caminho}[{i}]", prof + 1, max_prof, achados)
            for i, v in enumerate(valor)
        ]

    if isinstance(valor, str):
        return _escanear_texto(valor, caminho or "$", achados)

    return valor


_REDIGIDO = re.compile(r"\[REDACTED:[A-Z]+\]")
_MASCARA_CPF = re.compile(r"\*\*\*\.\d{3}\.\*\*\*-\d{2}|\*\*\*\d{3}\*\*\*\d{2}")
_MASCARA_GENERICA = re.compile(r"[*.\-/\s]*\*[*.\-/\s]*(?:[0-9A-Za-z][*.\-/\s]*){0,2}")


def ja_protegido(valor, categoria) -> bool:
    """True se o valor já saiu de uma máscara nossa (torna a varredura idempotente).

    Só reconhece o formato EXATO das máscaras: senha e saúde aceitam apenas
    [REDACTED:X], para ninguém escapar da proteção colocando um '*' no valor.
    """
    if not isinstance(valor, str):
        return False
    if _REDIGIDO.fullmatch(valor):
        return True
    if categoria in ("SENHA", "SAUDE"):
        return False
    return bool(_MASCARA_CPF.fullmatch(valor) or _MASCARA_GENERICA.fullmatch(valor))


def proteger_por_chave(valor, categoria):
    """Chave sensível: protege o valor inteiro, mesmo que pareça inválido."""
    if categoria in ("SENHA", "SAUDE"):
        return redigir(categoria), categoria

    if isinstance(valor, (str, int)) and not isinstance(valor, bool):
        texto = str(valor)
        if categoria == "DOCUMENTO":
            categoria = "CPF" if len(re.sub(r"\D", "", texto)) == 11 else "RG"
        if categoria == "CPF":
            return mascarar_cpf(texto), "CPF"
        return mascarar_generico(texto), categoria

    # Estrutura ou tipo inesperado sob chave sensível: redige o subárvore inteiro.
    if categoria == "DOCUMENTO":
        categoria = "RG"
    return redigir(categoria), categoria


def _escanear_texto(texto, caminho, achados):
    def trocar_cpf(m):
        achados.append(Achado(caminho, "CPF", SEVERIDADE["CPF"], "valor"))
        return mascarar_cpf(m.group())

    def trocar_cpf_puro(m):
        if not cpf_valido(m.group()):
            return m.group()
        return trocar_cpf(m)

    def trocar_rg(m):
        achados.append(Achado(caminho, "RG", SEVERIDADE["RG"], "valor"))
        return mascarar_generico(m.group())

    texto = CPF_FORMATADO.sub(trocar_cpf, texto)
    texto = CPF_PURO.sub(trocar_cpf_puro, texto)
    return RG_FORMATADO.sub(trocar_rg, texto)
