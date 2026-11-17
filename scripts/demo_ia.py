"""Evidência da Parte 3: prompt, mensagens de reserva e defesa contra saída maliciosa do LLM.

Uso: python scripts/demo_ia.py
Se LLM_PROVIDER/LLM_API_KEY/LLM_MODEL estiverem configurados, a seção 3 faz uma chamada real.
"""
import asyncio
import os
import sys
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from app.ai import limpar_cache, montar_prompt, traduzir_evento  # noqa: E402
from app.ai.catalogo import EVENTOS  # noqa: E402
from app.ai.provedores import carregar_config  # noqa: E402


VARS_LLM = ("LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL")


@contextmanager
def ambiente_llm(**novos):
    """Troca as variáveis LLM_* só dentro do bloco e RESTAURA a configuração real depois."""
    antes = {v: os.environ.get(v) for v in VARS_LLM}
    for v in VARS_LLM:
        os.environ.pop(v, None)
    os.environ.update(novos)
    try:
        yield
    finally:
        for v, valor in antes.items():
            os.environ.pop(v, None)
            if valor is not None:
                os.environ[v] = valor


def titulo(t):
    print(f"\n{'=' * 70}\n{t}\n{'=' * 70}")


async def main():
    titulo("1) Prompt enviado ao LLM (só catálogo: nenhum dado do usuário)")
    print(montar_prompt("RESPOSTA_BLOQUEADA", ("SENHA", "CPF")))

    titulo("2) Mensagens de reserva (sem LLM): evento técnico -> cidadão")
    with ambiente_llm():  # garante que a seção 2 não chama nenhum LLM real
        for nome in EVENTOS:
            t = await traduzir_evento({"evento": nome, "categorias": ["CPF", "SAUDE"]})
            print(f"[{nome}] ({t.origem}/{t.motivo or '-'})\n  {t.mensagem}\n")

    titulo("3) Saída maliciosa de um LLM SIMULADO (MockTransport) é rejeitada")
    ruins = [
        "Seu CPF 529.982.247-25 foi exposto, mas protegemos tudo isso aqui.",
        "Clique em https://site-falso.example para confirmar seus dados agora.",
        "<script>alert(1)</script> O sistema protegeu seus dados.",
    ]
    with ambiente_llm(LLM_PROVIDER="openai", LLM_API_KEY="chave-de-demonstracao", LLM_MODEL="modelo-simulado"):
        for ruim in ruins:
            limpar_cache()
            transporte = httpx.MockTransport(
                lambda req, r=ruim: httpx.Response(200, json={"choices": [{"message": {"content": r}}]})
            )
            async with httpx.AsyncClient(transport=transporte) as c:
                t = await traduzir_evento({"evento": "ERRO_INTERNO", "categorias": []}, cliente=c)
            print(f"LLM disse : {ruim}\nTela mostra: {t.mensagem}\n  -> origem={t.origem} motivo={t.motivo}\n")

    titulo("4) Chamada real (opcional)")
    limpar_cache()
    if not carregar_config().pronta:
        print("LLM_PROVIDER/LLM_API_KEY/LLM_MODEL não configurados: seção ignorada.")
    else:
        cfg = carregar_config()
        print(f"provedor={cfg.provedor} modelo={cfg.modelo}  (a chave nunca é exibida)")
        t = await traduzir_evento({"evento": "RESPOSTA_BLOQUEADA", "categorias": ["CPF"]})
        print(f"origem={t.origem} motivo={t.motivo or '-'}\n{t.mensagem}")
        if t.origem != "llm":
            print("Se o motivo for erro_http, veja acima a linha 'LLM indisponível: ... HTTP <código>'.")


asyncio.run(main())
