"""Testes da Parte 2 — Taint Analysis, auditoria e autenticação. Só dados sintéticos."""
import json
import logging
import pickle

import pytest
from fastapi.testclient import TestClient

from app.audit import Auditoria
from app.auth import emitir_token, validar_token
from app.main import app, criar_app
from app.pii import escanear
from app.taint import Sensitive, marcar, sanitizar_texto

CPF = "529.982.247-25"  # CPF sintético com dígitos verificadores corretos
cliente = TestClient(app, raise_server_exceptions=False)


def _auth(usuario="maria", ttl=900):
    return {"Authorization": f"Bearer {emitir_token(usuario, ttl)}"}


def _eventos(auditoria, evento):
    return [e for e in auditoria.listar() if e["evento"] == evento]


# --- Idempotência do scanner (ajuste da Parte 2) --------------------------------------

def test_escanear_e_idempotente():
    r1 = escanear(
        {"documento": "123.456.789-00", "senha": "abc", "rg": "12.345.678-9",
         "laudo": {"x": 1}, "obs": CPF}
    )
    r2 = escanear(r1.sanitizado)
    assert r2.sanitizado == r1.sanitizado and not r2.achados


def test_asterisco_nao_escapa_da_protecao():
    assert escanear({"senha": "***"}).achados  # senha só aceita [REDACTED:X] como "já protegido"
    r = escanear({"cpf": "*12345678900"})
    assert r.sanitizado["cpf"] == "***456***00" and r.achados


# --- Source: Sensitive e marcar ---------------------------------------------------------

def test_sensitive_nao_vaza_ao_imprimir_formatar_ou_serializar():
    s = Sensitive("abc123", "SENHA")
    assert str(s) == repr(s) == f"{s}" == "%s" % s == "[REDACTED:SENHA]"
    assert s.revelar() == "abc123"
    with pytest.raises(TypeError):
        json.dumps({"x": s})
    with pytest.raises(TypeError):
        pickle.dumps(s)


def test_marcar_embrulha_chaves_sensiveis_e_cpf_em_texto():
    m = marcar({
        "nome": "Ana", "senha": "abc", "documento": "123.456.789-00",
        "obs": f"cpf {CPF}", "itens": [{"laudo": {"cid": "X"}}],
    })
    assert m["nome"] == "Ana"
    assert (m["senha"].categoria, m["documento"].categoria) == ("SENHA", "CPF")
    assert m["obs"].categoria == "CPF"
    assert m["itens"][0]["laudo"].categoria == "SAUDE"
    texto = str(m)
    for cru in ("abc", "123.456.789-00", CPF):
        assert cru not in texto


# --- Texto livre ------------------------------------------------------------------------

def test_sanitizar_texto_chave_valor_e_valor_solto():
    texto = f'login ok senha=abc123 {{"cpf": "{CPF}"}} paciente {CPF}'
    seguro, achados = sanitizar_texto(texto)
    assert seguro == (
        'login ok senha=[REDACTED:SENHA] {"cpf": "***.982.***-25"} paciente ***.982.***-25'
    )
    assert len(achados) == 3
    assert sanitizar_texto(seguro) == (seguro, [])  # idempotente


# --- Sink: logs -------------------------------------------------------------------------

def test_log_com_cpf_solto_e_mascarado_e_auditado(caplog, auditoria):
    caplog.set_level(logging.INFO)
    logging.getLogger("teste").info("cliente com cpf %s entrou", CPF)
    assert CPF not in caplog.text and "***.982.***-25" in caplog.text
    ev = _eventos(auditoria, "LOG_SANITIZADO")[0]
    assert (ev["sink"], ev["acao"], ev["categorias"]) == ("log", "mascarado", ["CPF"])


def test_log_de_senha_em_fstring_e_mascarado(caplog):
    caplog.set_level(logging.INFO)
    senha = "SuperSecreta!"
    logging.getLogger("teste").info(f"login senha={senha}")
    assert senha not in caplog.text and "[REDACTED:SENHA]" in caplog.text


def test_log_de_variavel_sensitive_nao_imprime_valor(caplog):
    caplog.set_level(logging.INFO)
    logging.getLogger("teste").info("dados_de_saude: %s", Sensitive("diabetes tipo 2", "SAUDE"))
    assert "diabetes" not in caplog.text and "[REDACTED:SAUDE]" in caplog.text


def test_stack_trace_no_log_e_sanitizado(caplog):
    caplog.set_level(logging.INFO)
    try:
        raise ValueError(f"falha com cpf {CPF}")
    except ValueError:
        logging.getLogger("teste").exception("erro ao processar")
    assert CPF not in caplog.text and "***.982.***-25" in caplog.text


# --- Sink: resposta HTTP ----------------------------------------------------------------

def test_resposta_com_pii_para_nao_autenticado_e_bloqueada(auditoria):
    resp = cliente.post("/demo/eco-inseguro", json={"documento": "123.456.789-00"})
    assert resp.status_code == 403
    assert "123.456.789-00" not in resp.text and "456" not in resp.json()["erro"]
    bloqueio = _eventos(auditoria, "RESPOSTA_BLOQUEADA")[0]
    assert (bloqueio["sink"], bloqueio["acao"], bloqueio["categorias"]) == ("resposta", "bloqueado", ["CPF"])
    assert bloqueio["autenticado"] is False and bloqueio["rota"] == "/demo/eco-inseguro"
    assert _eventos(auditoria, "PII_RECEBIDA")[0]["sink"] == "entrada"  # source também auditado


def test_resposta_sem_pii_passa_para_todos():
    resp = cliente.post("/demo/eco-inseguro", json={"nome": "Ana"})
    assert resp.status_code == 200 and resp.json() == {"nome": "Ana"}


def test_autenticado_recebe_pii_e_fica_auditado(auditoria):
    corpo = {"obs": f"cpf {CPF}"}
    resp = cliente.post("/demo/eco-inseguro", json=corpo, headers=_auth())
    assert resp.status_code == 200 and resp.json() == corpo
    ev = _eventos(auditoria, "PII_EM_RESPOSTA_AUTENTICADA")[0]
    assert (ev["acao"], ev["severidade"], ev["autenticado"]) == ("permitido", "baixa", True)


def test_senha_nunca_sai_nem_para_autenticado(auditoria):
    resp = cliente.post("/demo/eco-inseguro", json={"senha": "abc123"}, headers=_auth())
    assert resp.status_code == 403 and "abc123" not in resp.text
    assert _eventos(auditoria, "RESPOSTA_BLOQUEADA")[0]["severidade"] == "alta"


def test_token_invalido_ou_expirado_conta_como_nao_autenticado():
    corpo = {"obs": f"cpf {CPF}"}
    assert cliente.post("/demo/eco-inseguro", json=corpo, headers=_auth(ttl=-1)).status_code == 403
    ruim = {"Authorization": "Bearer lixo.lixo"}
    assert cliente.post("/demo/eco-inseguro", json=corpo, headers=ruim).status_code == 403


def test_resposta_ja_sanitizada_do_demo_pii_nao_e_bloqueada():
    resp = cliente.post("/demo/pii", json={"documento": "123.456.789-00", "senha": "abc"})
    assert resp.status_code == 200
    assert resp.json()["corpo_sanitizado"]["documento"] == "***.456.***-00"


# --- Sink: erros ------------------------------------------------------------------------

def test_422_nao_reflete_o_corpo_enviado(auditoria):
    resp = cliente.post("/demo/cadastro", json={"nome": "Ana", "senha": "abc123", "cpf": CPF})
    assert resp.status_code == 422
    assert "abc123" not in resp.text and CPF not in resp.text
    assert resp.json()["campos"][0]["campo"] == "body.idade"
    ev = _eventos(auditoria, "ENTRADA_REFLETIDA_BLOQUEADA")[0]
    assert set(ev["categorias"]) == {"CPF", "SENHA"}


def test_500_devolve_mensagem_generica_e_sanitiza_o_log(auditoria):
    resp = cliente.get("/demo/erro")
    assert resp.status_code == 500
    assert CPF not in resp.text and "RuntimeError" not in resp.text and "Traceback" not in resp.text
    assert resp.json()["trace_id"] != "-"
    trace = resp.json()["trace_id"]
    assert _eventos(auditoria, "ERRO_INTERNO")[0]["trace_id"] == trace
    # o CPF da mensagem de erro foi mascarado no log, e o evento aponta para a mesma requisição
    assert _eventos(auditoria, "LOG_SANITIZADO")[0]["trace_id"] == trace


# --- Source -> sink na prática ----------------------------------------------------------

def test_corpo_marcado_logado_nao_vaza(caplog):
    caplog.set_level(logging.INFO)
    resp = cliente.post("/demo/fonte", json={"senha": "abc123", "documento": "123.456.789-00"})
    assert resp.status_code == 200
    assert "abc123" not in caplog.text and "123.456.789-00" not in caplog.text
    assert "[REDACTED:SENHA]" in caplog.text and "[REDACTED:CPF]" in caplog.text


# --- Demo desligada por padrão ----------------------------------------------------------

def test_rotas_demo_so_existem_com_modo_demo():
    assert TestClient(criar_app(False)).post("/demo/pii", json={}).status_code == 404
    assert TestClient(criar_app(True)).post("/demo/pii", json={}).status_code == 200


# --- Auditoria e autenticação -----------------------------------------------------------

def test_auditoria_grava_e_lista_sem_valores(tmp_path):
    aud = Auditoria(str(tmp_path / "x.db"))
    aud.registrar("TESTE", "log", "mascarado", categorias=["CPF", "CPF", "RG"], quantidade=2,
                  severidade="media", trace_id="t1", rota="/r", metodo="GET", autenticado=True)
    ev = aud.listar()[0]
    assert ev["categorias"] == ["CPF", "RG"] and ev["autenticado"] is True
    assert set(ev) == {"id", "ts", "trace_id", "evento", "sink", "acao", "categorias",
                       "quantidade", "severidade", "rota", "metodo", "autenticado"}


def test_token_valido_adulterado_expirado_e_outro_segredo(monkeypatch):
    token = emitir_token("maria")
    assert validar_token(token) == "maria"
    payload, assinatura = token.split(".")
    assert validar_token(f"{payload}x.{assinatura}") is None
    assert validar_token(emitir_token("maria", ttl_segundos=-1)) is None
    monkeypatch.setenv("APP_SECRET", "outro-segredo")
    assert validar_token(token) is None


# --- Regressão: achado pelo demo_taint (Parte 5) -----------------------------------------

def test_chave_comum_antes_da_senha_nao_esconde_a_senha():
    # "ok:" era lida como chave e engolia "senha=..." como se fosse o valor dela
    seguro, achados = sanitizar_texto("login ok: senha=Senha#2026 documento=123.456.789-00")
    assert seguro == "login ok: senha=[REDACTED:SENHA] documento=***.456.***-00"
    assert len(achados) == 2
    assert sanitizar_texto(seguro) == (seguro, [])


@pytest.mark.parametrize("texto,esperado", [
    ("usuario: maria senha: Abc#123", "usuario: maria senha: [REDACTED:SENHA]"),
    ('{"obs": "senha=Abc#123"}', '{"obs": "senha=[REDACTED:SENHA]"}'),
    ("a=b c=d senha=x!y", "a=b c=d senha=[REDACTED:SENHA]"),
    ("status: senha=Abc#123, cpf: 529.982.247-25", "status: senha=[REDACTED:SENHA], cpf: ***.982.***-25"),
])
def test_senha_depois_de_chaves_comuns(texto, esperado):
    assert sanitizar_texto(texto)[0] == esperado
