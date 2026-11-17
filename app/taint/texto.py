"""Sanitização de TEXTO livre: mensagens de log, stack traces, respostas em texto."""
from __future__ import annotations

import re

from app.pii.detectors import SEVERIDADE, classificar_chave
from app.pii.scanner import Achado, escanear, ja_protegido, proteger_por_chave

# Pega "senha=abc", 'cpf: "123..."', '"laudo": "texto"' etc.
_CHAVE_VALOR = re.compile(
    r"""(?P<chave>[A-Za-zÀ-ÿ_][\wÀ-ÿ-]*)(?P<sep>["']?\s*[=:]\s*)"""
    r"""(?P<valor>"[^"]*"|'[^']*'|\[REDACTED:[A-Z]+\]|[^\s,;&}\]]+)"""
)


def sanitizar_texto(texto: str) -> tuple[str, list[Achado]]:
    """Mascara PII em texto livre. Devolve (texto_seguro, achados)."""
    achados: list[Achado] = []
    partes: list[str] = []
    pos = 0
    while True:
        m = _CHAVE_VALOR.search(texto, pos)
        if not m:
            break
        categoria = classificar_chave(m.group("chave"))
        if not categoria:
            # Chave comum ("ok:", "usuario="): NÃO consome o valor, porque ele pode conter
            # outra chave sensível ("login ok: senha=abc"). Segue a busca logo após o separador.
            partes.append(texto[pos:m.end("sep")])
            pos = m.end("sep")
            continue
        valor = m.group("valor")
        aspas = valor[0] if valor[0] in "\"'" else ""
        bruto = valor[1:-1] if aspas else valor
        fecha = ""
        if not aspas and bruto[-1:] in ("\"", "'") and texto[:m.start()].count(bruto[-1]) % 2 == 1:
            # a aspa final fecha uma string que já estava aberta ('"obs": "senha=x"'): preserva
            bruto, fecha = bruto[:-1], bruto[-1]
        partes.append(texto[pos:m.start()])
        if not bruto or ja_protegido(bruto, categoria):
            partes.append(m.group(0))
        else:
            protegido, final = proteger_por_chave(bruto, categoria)
            achados.append(Achado("texto", final, SEVERIDADE[final], "chave"))
            partes.append(f"{m.group('chave')}{m.group('sep')}{aspas}{protegido}{aspas}{fecha}")
        pos = m.end()
    partes.append(texto[pos:])
    texto = "".join(partes)
    resultado = escanear(texto)  # CPF e RG soltos no meio do texto
    return resultado.sanitizado, achados + resultado.achados
