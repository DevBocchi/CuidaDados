"""Taint Analysis — SOURCE: marca o dado sensível assim que ele entra (Parte 2).

`Sensitive` embrulha o valor. Enquanto embrulhado, qualquer tentativa de imprimir,
formatar ou serializar mostra apenas [REDACTED:CATEGORIA]. Para usar o valor de
verdade (ex.: calcular o hash da senha) é preciso chamar `.revelar()`, uma ação
explícita e fácil de achar numa revisão de código.
"""
from __future__ import annotations

from typing import Any

from app.pii.detectors import classificar_chave
from app.pii.scanner import escanear


class Sensitive:
    __slots__ = ("_valor", "categoria")

    def __init__(self, valor: Any, categoria: str = "SENSIVEL"):
        self._valor = valor
        self.categoria = categoria

    def revelar(self) -> Any:
        """Único jeito de obter o valor original (declassificação explícita)."""
        return self._valor

    def __str__(self) -> str:
        return f"[REDACTED:{self.categoria}]"

    __repr__ = __str__

    def __format__(self, spec: str) -> str:
        return format(str(self), spec)

    def __reduce__(self):  # não deixa serializar (pickle) por acidente
        raise TypeError("Sensitive não pode ser serializado")


def marcar(dados: Any, max_profundidade: int = 20, _prof: int = 0) -> Any:
    """Percorre os dados de entrada e embrulha em Sensitive tudo que for PII."""
    if _prof > max_profundidade:  # falha fechada
        return Sensitive(dados, "ESTRUTURA")

    if isinstance(dados, dict):
        saida = {}
        for chave, valor in dados.items():
            categoria = classificar_chave(str(chave))
            if categoria and valor is not None and valor != "":
                saida[chave] = Sensitive(valor, _resolver(categoria, valor))
            else:
                saida[chave] = marcar(valor, max_profundidade, _prof + 1)
        return saida

    if isinstance(dados, (list, tuple)):
        return [marcar(v, max_profundidade, _prof + 1) for v in dados]

    if isinstance(dados, str):
        achados = escanear(dados).achados
        return Sensitive(dados, achados[0].categoria) if achados else dados

    return dados


def _resolver(categoria: str, valor: Any) -> str:
    if categoria != "DOCUMENTO":
        return categoria
    digitos = "".join(c for c in str(valor) if c.isdigit())
    return "CPF" if len(digitos) == 11 else "RG"
