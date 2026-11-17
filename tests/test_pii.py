"""Testes da Parte 1 — Parsing de PII. Só dados sintéticos."""
from fastapi import Body, FastAPI
from fastapi.testclient import TestClient

from app.main import app
from app.pii import PIIMiddleware, escanear
from app.pii.detectors import classificar_chave, cpf_valido
from app.pii.masking import mascarar_cpf

CPF_VALIDO = "529.982.247-25"  # CPF de exemplo com dígitos verificadores corretos


# --- Detectores ---------------------------------------------------------------------

def test_cpf_valido_e_invalidos():
    assert cpf_valido(CPF_VALIDO)
    assert cpf_valido("52998224725")
    assert not cpf_valido("123.456.789-00")  # exemplo do professor: dígitos inválidos
    assert not cpf_valido("111.111.111-11")  # todos iguais
    assert not cpf_valido("12345678901")


def test_classificar_chave_normaliza_acento_e_camelcase():
    assert classificar_chave("senha") == "SENHA"
    assert classificar_chave("novaSenha") == "SENHA"
    assert classificar_chave("Diagnóstico") == "SAUDE"
    assert classificar_chave("dados_de_saude") == "SAUDE"
    assert classificar_chave("documento") == "DOCUMENTO"
    assert classificar_chave("nome") is None
    assert classificar_chave("passagem") is None  # não confunde com "pass"


# --- Mascaramento ---------------------------------------------------------------------

def test_mascara_cpf_no_formato_do_professor():
    assert mascarar_cpf("123.456.789-00") == "***.456.***-00"
    assert mascarar_cpf("12345678900") == "***456***00"


# --- Scanner ---------------------------------------------------------------------------

def test_exemplo_do_professor_documento_e_tagueado_e_mascarado():
    r = escanear({"documento": "123.456.789-00"})  # inválido, mas a chave manda
    assert r.sanitizado == {"documento": "***.456.***-00"}
    assert [(a.caminho, a.categoria, a.origem) for a in r.achados] == [
        ("documento", "CPF", "chave")
    ]


def test_senha_e_saude_sao_redigidas_por_inteiro():
    r = escanear({"senha": "abc123", "laudo": {"cid": "X", "texto": "dado clínico"}})
    assert r.sanitizado == {"senha": "[REDACTED:SENHA]", "laudo": "[REDACTED:SAUDE]"}
    assert {a.severidade for a in r.achados} == {"alta"}


def test_rg_por_chave_mantem_so_o_final():
    r = escanear({"rg": "12.345.678-9"})
    assert r.sanitizado["rg"] == "**.***.**8-9"
    assert r.achados[0].categoria == "RG"


def test_texto_livre_cpf_valido_e_mascarado_invalido_nao():
    r = escanear({"obs": f"paciente cpf {CPF_VALIDO} e protocolo 12345678901"})
    assert "***.982.***-25" in r.sanitizado["obs"]
    assert "12345678901" in r.sanitizado["obs"]  # 11 dígitos sem DV válido: não é CPF
    assert len(r.achados) == 1 and r.achados[0].origem == "valor"


def test_caminho_em_listas_aninhadas():
    r = escanear({"pessoas": [{"nome": "Ana"}, {"cpf": CPF_VALIDO}]})
    assert r.achados[0].caminho == "pessoas[1].cpf"
    assert r.sanitizado["pessoas"][0] == {"nome": "Ana"}


def test_campos_vazios_nao_geram_achado():
    r = escanear({"senha": "", "cpf": None})
    assert not r.tem_pii


def test_estrutura_muito_funda_e_redigida():
    fundo = {"a": {"b": {"c": "x"}}}
    r = escanear(fundo, max_profundidade=1)
    assert r.achados[0].categoria == "ESTRUTURA"


def test_achados_nunca_carregam_valor_original():
    r = escanear({"documento": "123.456.789-00", "senha": "SuperSecreta!", "obs": CPF_VALIDO})
    texto = repr(r.achados)
    for original in ("123.456.789-00", "SuperSecreta!", CPF_VALIDO):
        assert original not in texto


# --- Middleware ------------------------------------------------------------------------

def test_middleware_sanitiza_corpo_e_query_e_poe_trace_id():
    client = TestClient(app)
    resp = client.post(
        f"/demo/pii?cpf={CPF_VALIDO}",
        json={"documento": "123.456.789-00", "senha": "abc", "nome": "Maria"},
    )
    corpo = resp.json()
    assert corpo["corpo_sanitizado"] == {
        "documento": "***.456.***-00",
        "senha": "[REDACTED:SENHA]",
        "nome": "Maria",
    }
    assert corpo["query_sanitizada"] == {"cpf": "***.982.***-25"}
    assert {a["caminho"] for a in corpo["achados"]} == {"corpo.documento", "corpo.senha", "query.cpf"}
    assert resp.headers["x-trace-id"] == corpo["trace_id"]
    assert CPF_VALIDO not in resp.text and "abc" not in resp.text


def test_handler_continua_recebendo_o_corpo_original():
    outro = FastAPI()
    outro.add_middleware(PIIMiddleware)

    @outro.post("/eco")
    async def eco(payload: dict = Body(...)):
        return {"tamanho_senha": len(payload["senha"])}  # só o tamanho, não o valor

    resp = TestClient(outro).post("/eco", json={"senha": "abcdef"})
    assert resp.json() == {"tamanho_senha": 6}


def _app_que_expoe_o_estado(**opcoes):
    """App de teste cuja rota não lê o corpo: só devolve o que o middleware calculou."""
    from fastapi import Request

    teste = FastAPI()
    teste.add_middleware(PIIMiddleware, **opcoes)

    @teste.post("/estado")
    async def estado(request: Request):
        return {
            "achados": [a.como_dict() for a in request.state.pii_achados],
            "corpo_sanitizado": request.state.corpo_sanitizado,
            "ignorada": request.state.varredura_ignorada,
        }

    return TestClient(teste)


def test_json_invalido_e_varrido_como_texto():
    resp = _app_que_expoe_o_estado().post(
        "/estado", content=f"nao e json {CPF_VALIDO}", headers={"content-type": "application/json"}
    )
    dados = resp.json()
    assert dados["corpo_sanitizado"] == "nao e json ***.982.***-25"
    assert dados["achados"][0]["categoria"] == "CPF"
    assert CPF_VALIDO not in resp.text


def test_corpo_acima_do_limite_gera_achado_de_estrutura():
    resp = _app_que_expoe_o_estado(limite_bytes=10).post("/estado", json={"senha": "a" * 100})
    dados = resp.json()
    assert dados["ignorada"] is True
    assert dados["corpo_sanitizado"] is None  # falha fechada: nada do corpo é exposto
    assert dados["achados"][0]["categoria"] == "ESTRUTURA"
