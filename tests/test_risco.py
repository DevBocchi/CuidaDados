"""Testes da Parte 4 — Risco Cidadão e dashboard. Só dados sintéticos."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ai import Traducao
from app.auth import emitir_token
from app.main import app
from app.risk import agrupar_ocorrencias, calcular_risco, nivel_por_pontos

AGORA = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
cliente = TestClient(app, raise_server_exceptions=False)
AUTH = lambda: {"Authorization": f"Bearer {emitir_token('admin')}"}  # noqa: E731


def ev(sev, evento="RESPOSTA_BLOQUEADA", minutos_atras=1, categorias=("CPF",)):
    ts = (AGORA - timedelta(minutes=minutos_atras)).isoformat(timespec="seconds")
    return {"ts": ts, "evento": evento, "severidade": sev, "categorias": list(categorias)}


# --- Fórmula ----------------------------------------------------------------------------

@pytest.mark.parametrize("pontos,nivel", [
    (0, "verde"), (9, "verde"), (10, "amarelo"), (29, "amarelo"), (30, "vermelho"), (100, "vermelho"),
])
def test_faixas(pontos, nivel):
    assert nivel_por_pontos(pontos) == nivel


def test_sem_eventos_e_verde_zero():
    r = calcular_risco([], agora=AGORA)
    assert (r["pontuacao"], r["nivel"], r["rotulo"]) == (0, "verde", "Tranquilo")


def test_pesos_por_severidade_e_calibracao():
    assert calcular_risco([ev("media")], agora=AGORA)["nivel"] == "verde"            # 8
    assert calcular_risco([ev("media")] * 2, agora=AGORA)["nivel"] == "amarelo"      # 16
    assert calcular_risco([ev("media")] * 4, agora=AGORA)["nivel"] == "vermelho"     # 32
    assert calcular_risco([ev("alta")], agora=AGORA)["nivel"] == "amarelo"           # 15
    assert calcular_risco([ev("alta")] * 2, agora=AGORA)["nivel"] == "vermelho"      # 30
    assert calcular_risco([ev("baixa")] * 9, agora=AGORA)["nivel"] == "verde"        # 9


def test_pii_recebida_nao_pontua():
    r = calcular_risco([ev("alta", "PII_RECEBIDA")] * 20, agora=AGORA)
    assert r["pontuacao"] == 0 and r["eventos_na_janela"] == 20 and r["eventos_que_pontuam"] == 0


def test_eventos_fora_da_janela_nao_contam():
    antigos = [ev("alta", minutos_atras=61), ev("alta", minutos_atras=600)]
    assert calcular_risco(antigos, agora=AGORA)["pontuacao"] == 0
    assert calcular_risco(antigos, janela_min=1000, agora=AGORA)["pontuacao"] == 30  # janela configurável


def test_teto_100_e_lixo_ignorado():
    assert calcular_risco([ev("alta")] * 50, agora=AGORA)["pontuacao"] == 100
    lixo = [{"ts": "ontem", "severidade": "alta", "evento": "X"}, {"severidade": "alta"},
            {"ts": None, "severidade": "alta"}, ev("severidade-inventada")]
    assert calcular_risco(lixo, agora=AGORA)["pontuacao"] == 0


def test_agrupar_ocorrencias_ordena_por_pontos_e_ignora_informativos():
    eventos = [ev("media"), ev("media"), ev("alta", "ERRO_INTERNO", categorias=()),
               ev("alta", "PII_RECEBIDA"), ev("media", "EVENTO_FORJADO", categorias=("CPF",))]
    g = agrupar_ocorrencias(eventos, agora=AGORA)
    assert [(x["evento"], x["ocorrencias"], x["pontos"]) for x in g] == [
        ("RESPOSTA_BLOQUEADA", 2, 16), ("ERRO_INTERNO", 1, 15), ("DESCONHECIDO", 1, 8)]


# --- API /risco -------------------------------------------------------------------------

def test_risco_exige_token():
    assert cliente.get("/risco").status_code == 401
    assert cliente.get("/risco", headers={"Authorization": "Bearer lixo"}).status_code == 401


def test_risco_sem_eventos_e_verde():
    r = cliente.get("/risco", headers=AUTH())
    assert r.status_code == 200
    d = r.json()
    assert (d["nivel"], d["pontuacao"], d["explicacoes"]) == ("verde", 0, [])


def test_risco_sobe_com_vazamentos_bloqueados_e_texto_e_seguro():
    for _ in range(2):  # 2 respostas com CPF bloqueadas = 16 pontos = amarelo
        assert cliente.post("/demo/eco-inseguro", json={"documento": "123.456.789-00"}).status_code == 403
    r = cliente.get("/risco", headers=AUTH())
    d = r.json()
    assert (d["nivel"], d["pontuacao"]) == ("amarelo", 16)
    exp = d["explicacoes"][0]
    assert (exp["evento"], exp["ocorrencias"], exp["areas"], exp["origem"]) == (
        "RESPOSTA_BLOQUEADA", 2, ["CPF"], "reserva")
    assert "123.456.789-00" not in r.text and "456" not in r.text


def test_risco_usa_o_tradutor_e_nao_envia_dados_a_ele(monkeypatch):
    vistos = []

    async def falso(grupo):
        vistos.append(grupo)
        return Traducao("Mensagem de teste do tradutor.", "llm", "", "openai")

    monkeypatch.setattr("app.risk.rotas.traduzir_evento", falso)
    cliente.post("/demo/eco-inseguro", json={"documento": "123.456.789-00"})
    d = cliente.get("/risco", headers=AUTH()).json()
    assert d["explicacoes"][0]["mensagem"] == "Mensagem de teste do tradutor."
    assert set(vistos[0]) == {"evento", "categorias", "ocorrencias", "pontos"}  # sem trace_id/rota


# --- Dashboard --------------------------------------------------------------------------

def test_dashboard_servido_com_csp_e_sem_dados():
    r = cliente.get("/dashboard")
    assert r.status_code == 200 and "Risco Cidadão" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert cliente.get("/dashboard/painel.js").status_code == 200
    assert cliente.get("/dashboard/painel.css").status_code == 200


def test_painel_js_nunca_usa_api_que_executa_html():
    js = (Path(__file__).resolve().parent.parent / "dashboard" / "painel.js").read_text(encoding="utf-8")
    for proibido in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert proibido not in js, proibido
    assert "textContent" in js
    html = (Path(__file__).resolve().parent.parent / "dashboard" / "index.html").read_text(encoding="utf-8")
    assert "<script>" not in html and " onclick=" not in html  # sem script inline (CSP)
