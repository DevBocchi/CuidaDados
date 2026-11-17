"""Detectores de PII (Parte 1).

Duas formas de detectar, como pede a explicação do professor:
- por NOME DA CHAVE (ex.: "documento", "senha", "laudo"): sempre marca, mesmo que o
  valor pareça inválido (falha fechada: na dúvida, protege);
- por VALOR em texto livre: regex + validação dos dígitos para evitar falso positivo.
"""
import re
import unicodedata

# CPF formatado (000.000.000-00) é marcado sempre; CPF só com dígitos exige validação.
CPF_FORMATADO = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
# CPF só com dígitos: não pode estar colado a letras/dígitos (evita achar "CPF" dentro de ids hex).
CPF_PURO = re.compile(r"(?<![0-9A-Za-z_])\d{11}(?![0-9A-Za-z_])")
RG_FORMATADO = re.compile(r"(?<![\d.])\d{1,2}\.\d{3}\.\d{3}-[\dXx](?!\d)")

# Ordem importa: a primeira categoria que casar com um token da chave vence.
_TOKENS_POR_CATEGORIA = (
    ("SENHA", {"senha", "senhas", "password", "passwd", "pwd"}),
    (
        "SAUDE",
        {
            "laudo", "laudos", "diagnostico", "doenca", "prontuario", "exame",
            "exames", "cid", "receita", "medicamento", "medicamentos", "saude",
        },
    ),
    ("CPF", {"cpf"}),
    ("RG", {"rg", "identidade"}),
    ("DOCUMENTO", {"documento", "documentos", "doc"}),
)

# Gravidade usada no Risco Cidadão (Parte 4).
SEVERIDADE = {
    "SENHA": "alta",
    "SAUDE": "alta",
    "CPF": "media",
    "RG": "media",
    "ESTRUTURA": "media",
}


def cpf_valido(texto: str) -> bool:
    """Valida CPF pelos dois dígitos verificadores."""
    d = re.sub(r"\D", "", texto)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        soma = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        if (soma * 10) % 11 % 10 != int(d[n]):
            return False
    return True


def _tokens_da_chave(chave: str) -> set[str]:
    """'dadosDeSaúde' / 'Dados-de-Saude' -> {'dados', 'de', 'saude'}."""
    sem_acento = "".join(
        c for c in unicodedata.normalize("NFKD", chave) if not unicodedata.combining(c)
    )
    separado = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", sem_acento)
    normal = re.sub(r"[^a-z0-9]+", "_", separado.lower()).strip("_")
    return set(normal.split("_")) if normal else set()


def classificar_chave(chave: str) -> str | None:
    """Devolve a categoria de PII sugerida pelo nome da chave, ou None."""
    tokens = _tokens_da_chave(chave)
    for categoria, nomes in _TOKENS_POR_CATEGORIA:
        if tokens & nomes:
            return categoria
    return None
