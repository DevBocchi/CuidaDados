"""Mascaramento de PII (Parte 1)."""
import re


def mascarar_cpf(texto: str) -> str:
    """123.456.789-00 -> ***.456.***-00 (formato do exemplo do professor)."""
    d = re.sub(r"\D", "", texto)
    if len(d) != 11:
        return mascarar_generico(texto)
    if "." in texto or "-" in texto:
        return f"***.{d[3:6]}.***-{d[9:]}"
    return f"***{d[3:6]}***{d[9:]}"


def mascarar_generico(texto: str, visiveis: int = 2) -> str:
    """Esconde letras e números, mantém pontuação e os últimos caracteres."""
    total = sum(c.isalnum() for c in texto)
    if total <= 4:
        visiveis = 0
    saida, vistos = [], 0
    for c in texto:
        if c.isalnum():
            vistos += 1
            saida.append(c if vistos > total - visiveis else "*")
        else:
            saida.append(c)
    return "".join(saida)


def redigir(categoria: str) -> str:
    """Substitui o valor inteiro (senha, saúde ou estrutura que não dá para mascarar)."""
    return f"[REDACTED:{categoria}]"
