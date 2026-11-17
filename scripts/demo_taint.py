"""Evidência das Partes 1 e 2: o MESMO código, ANTES e DEPOIS da proteção.

Uso:  python scripts/demo_taint.py          (não precisa de servidor nem de .env)
Só dados sintéticos. Os valores "crus" aparecem de propósito na seção ANTES, para provar
o problema; na seção DEPOIS eles não podem aparecer em lugar nenhum.
"""
import io
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ["MODO_DEMO"] = "1"
os.environ.setdefault("APP_SECRET", "segredo-de-demonstracao-longo-123")
os.environ["AUDIT_DB"] = str(Path(tempfile.mkdtemp()) / "demo_auditoria.db")

CPF = "529.982.247-25"          # CPF sintético (dígitos verificadores válidos)
SENHA = "SenhaDeTeste#2026"      # senha sintética
DOC = "123.456.789-00"           # exemplo do professor
CRUS = (CPF, SENHA, DOC)

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="LOG> %(levelname)s %(name)s: %(message)s")
for _n in ("httpx", "httpx2"):
    logging.getLogger(_n).setLevel(logging.WARNING)


def titulo(t):
    print(f"\n{'=' * 74}\n{t}\n{'=' * 74}")


def captura(nome):
    """Logger com buffer próprio, para mostrar exatamente o que seria gravado."""
    buf = io.StringIO()
    lg = logging.getLogger(nome)
    lg.handlers = [logging.StreamHandler(buf)]
    lg.handlers[0].setFormatter(logging.Formatter("  gravado no log -> %(message)s"))
    lg.propagate = False
    lg.setLevel(logging.INFO)
    return lg, buf


def codigo_do_desenvolvedor(lg):
    """O código descuidado de sempre. Não muda entre ANTES e DEPOIS."""
    lg.info(f"login ok: senha={SENHA} documento={DOC}")
    lg.info("paciente com cpf %s foi atendido", CPF)
    try:
        raise ValueError(f"falha ao validar cpf {CPF}")
    except ValueError:
        lg.exception("erro ao processar")


# --- 1) LOGS: antes (nada instalado ainda) -------------------------------------------------
titulo("1A) LOG — ANTES: sem proteção (o que o código descuidado grava)")
lg, buf = captura("demo.antes")
codigo_do_desenvolvedor(lg)
print(buf.getvalue().rstrip())
vazou_antes = sum(v in buf.getvalue() for v in CRUS)
print(f"-> valores pessoais crus no log: {vazou_antes} de {len(CRUS)}  (VAZAMENTO)")

# Importar o app instala a proteção de logs (Taint Analysis: sink "log").
import httpx  # noqa: E402,F401
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from app.audit import get_auditoria  # noqa: E402
from app.auth import emitir_token  # noqa: E402
from app.main import app as app_protegido  # noqa: E402
from app.taint import marcar  # noqa: E402

titulo("1B) LOG — DEPOIS: o MESMO código, com a proteção do módulo")
lg, buf = captura("demo.depois")
codigo_do_desenvolvedor(lg)
print(buf.getvalue().rstrip())
vazou_depois = sum(v in buf.getvalue() for v in CRUS)
print(f"-> valores pessoais crus no log: {vazou_depois} de {len(CRUS)}")

titulo("1C) LOG — variável marcada como sensível (Source) não imprime o valor")
lg, buf = captura("demo.fonte")
lg.info("corpo recebido: %s", marcar({"nome": "Ana", "senha": SENHA, "documento": DOC}))
print(buf.getvalue().rstrip())
vazou_marcado = sum(v in buf.getvalue() for v in CRUS)
print(f"-> valores pessoais crus no log: {vazou_marcado} de {len(CRUS)}")


# --- 2) HTTP: app ingênuo x app protegido ---------------------------------------------------
class Cadastro(BaseModel):
    nome: str
    idade: int


ingenuo = FastAPI()


@ingenuo.post("/eco")
async def eco_ingenuo(payload: dict):
    return payload


@ingenuo.post("/cadastro")
async def cadastro_ingenuo(dados: Cadastro):
    return {"ok": True}


antes = TestClient(ingenuo, raise_server_exceptions=False)
depois = TestClient(app_protegido, raise_server_exceptions=False)
corpo_cpf = {"documento": DOC}
corpo_invalido = {"nome": "Ana", "senha": SENHA, "cpf": CPF}


def mostrar(rotulo, resp):
    print(f"{rotulo}\n  HTTP {resp.status_code}  corpo: {resp.text[:230]}")
    return resp.text


titulo("2A) RESPOSTA HTTP — usuário NÃO autenticado pede eco de um CPF")
t1 = mostrar("ANTES (app sem proteção):", antes.post("/eco", json=corpo_cpf))
t2 = mostrar("DEPOIS (app com TaintMiddleware):", depois.post("/demo/eco-inseguro", json=corpo_cpf))
print(f"-> CPF cru na resposta: antes={DOC in t1}  depois={DOC in t2}")

titulo("2B) ERRO 422 — o corpo inválido NÃO pode voltar refletido")
t3 = mostrar("ANTES (FastAPI padrão devolve `input` com o que foi enviado):", antes.post("/cadastro", json=corpo_invalido))
t4 = mostrar("DEPOIS (handler próprio: só campo e motivo):", depois.post("/demo/cadastro", json=corpo_invalido))
print(f"-> senha refletida: antes={SENHA in t3}  depois={SENHA in t4}")

titulo("2C) ERRO 500 — mensagem genérica; detalhe só no log (sanitizado)")
t5 = mostrar("DEPOIS:", depois.get("/demo/erro"))
print(f"-> CPF ou 'Traceback' na resposta: {CPF in t5 or 'Traceback' in t5}")

titulo("2D) Usuário AUTENTICADO: CPF passa (auditado), senha NUNCA sai")
auth = {"Authorization": f"Bearer {emitir_token('demo')}"}
mostrar("CPF no corpo, com token:", depois.post("/demo/eco-inseguro", json={"obs": f"cpf {CPF}"}, headers=auth))
t6 = mostrar("senha no corpo, com token:", depois.post("/demo/eco-inseguro", json={"senha": SENHA}, headers=auth))
print(f"-> senha na resposta: {SENHA in t6}")

# --- 3) AUDITORIA: o que ficou registrado (sem valores) -------------------------------------
titulo("3) AUDITORIA — eventos registrados (só tipo, categoria e gravidade; nunca o valor)")
eventos = get_auditoria().listar(100)[::-1]
for e in eventos:
    print(f"  {e['evento']:<30} sink={e['sink']:<8} acao={e['acao']:<10} cat={','.join(e['categorias']) or '-':<10} "
          f"sev={e['severidade']:<5} auth={'sim' if e['autenticado'] else 'não'}")
bruto = json.dumps(eventos, ensure_ascii=False)
na_auditoria = sum(v in bruto for v in CRUS)
print(f"-> {len(eventos)} eventos; valores pessoais crus na auditoria: {na_auditoria} de {len(CRUS)}")

titulo("RESUMO")
ok = (vazou_antes == len(CRUS) and vazou_depois == 0 and vazou_marcado == 0
      and DOC in t1 and DOC not in t2 and SENHA in t3 and SENHA not in t4
      and CPF not in t5 and SENHA not in t6 and na_auditoria == 0)
print("ANTES: vazava em log, resposta e erro 422. DEPOIS: nenhum valor cru sai.")
print("RESULTADO:", "APROVADO" if ok else "REPROVADO")
sys.exit(0 if ok else 1)
