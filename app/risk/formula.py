"""Risco Cidadão (Parte 4): um número de 0 a 100 e uma cor, calculados SÓ a partir dos
eventos da auditoria (que nunca contêm valores pessoais).

FÓRMULA (simples de propósito, para o cidadão e a banca entenderem):

    pontos = soma, para cada evento dos últimos JANELA minutos, do peso da sua severidade
    Risco Cidadão = min(100, pontos)

    peso: baixa = 1 | média = 8 | alta = 15
    PII_RECEBIDA pesa 0: receber dado pessoal é o funcionamento normal do app (informativo).

    faixas:  0–9 VERDE (Tranquilo) | 10–29 AMARELO (Atenção) | 30–100 VERMELHO (Crítico)

Por que assim: severidade vem da categoria do dado (senha/saúde = alta; CPF/RG = média),
então vazar senha pesa quase o dobro de vazar CPF. A janela de tempo faz o indicador
"esfriar" quando o problema para de acontecer. Calibração: 1 evento médio fica verde;
2 já é amarelo; 4 é vermelho; 2 eventos de severidade alta (senha/saúde) já são vermelho.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

PESO = {"baixa": 1, "media": 8, "alta": 15}
EVENTOS_INFORMATIVOS = frozenset({"PII_RECEBIDA"})
LIMITE_AMARELO = 10
LIMITE_VERMELHO = 30
JANELA_PADRAO_MIN = 60

NIVEIS = {
    "verde": "Tranquilo",
    "amarelo": "Atenção",
    "vermelho": "Crítico",
}


def nivel_por_pontos(pontos: int) -> str:
    if pontos >= LIMITE_VERMELHO:
        return "vermelho"
    if pontos >= LIMITE_AMARELO:
        return "amarelo"
    return "verde"


def peso_do_evento(evento: dict) -> int:
    if evento.get("evento") in EVENTOS_INFORMATIVOS:
        return 0
    return PESO.get(evento.get("severidade"), 0)


def _dentro_da_janela(evento: dict, inicio: datetime) -> bool:
    try:
        ts = datetime.fromisoformat(evento["ts"])
    except (KeyError, ValueError, TypeError):
        return False  # evento sem data válida não conta (fail-safe contra lixo)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts >= inicio


def calcular_risco(eventos: list[dict], *, janela_min: int = JANELA_PADRAO_MIN,
                   agora: datetime | None = None) -> dict:
    agora = agora or datetime.now(timezone.utc)
    inicio = agora - timedelta(minutes=janela_min)
    na_janela = [e for e in eventos if _dentro_da_janela(e, inicio)]

    pontos_brutos = sum(peso_do_evento(e) for e in na_janela)
    pontos = min(100, pontos_brutos)
    nivel = nivel_por_pontos(pontos)
    return {
        "pontuacao": pontos,
        "nivel": nivel,
        "rotulo": NIVEIS[nivel],
        "janela_minutos": janela_min,
        "eventos_na_janela": len(na_janela),
        "eventos_que_pontuam": sum(1 for e in na_janela if peso_do_evento(e) > 0),
        "por_severidade": dict(Counter(e["severidade"] for e in na_janela if peso_do_evento(e) > 0)),
        "formula": {
            "pesos": PESO,
            "faixas": {"verde": f"0 a {LIMITE_AMARELO - 1}",
                       "amarelo": f"{LIMITE_AMARELO} a {LIMITE_VERMELHO - 1}",
                       "vermelho": f"{LIMITE_VERMELHO} ou mais"},
        },
    }


def agrupar_ocorrencias(eventos: list[dict], *, janela_min: int = JANELA_PADRAO_MIN,
                        agora: datetime | None = None, maximo: int = 6) -> list[dict]:
    """Agrupa por (evento, áreas) para traduzir uma vez cada tipo; mais grave primeiro."""
    from app.ai.catalogo import areas_do_evento, normalizar_evento

    agora = agora or datetime.now(timezone.utc)
    inicio = agora - timedelta(minutes=janela_min)
    grupos: dict[tuple, dict] = {}
    for e in eventos:
        if not _dentro_da_janela(e, inicio) or peso_do_evento(e) == 0:
            continue
        chave = (normalizar_evento(str(e.get("evento", ""))), areas_do_evento(e.get("categorias") or []))
        g = grupos.setdefault(chave, {"evento": chave[0], "categorias": list(chave[1]),
                                      "ocorrencias": 0, "pontos": 0})
        g["ocorrencias"] += 1
        g["pontos"] += peso_do_evento(e)
    return sorted(grupos.values(), key=lambda g: (-g["pontos"], g["evento"]))[:maximo]
