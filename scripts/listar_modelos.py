"""Lista os modelos que a SUA chave pode usar, para você copiar o nome exato em LLM_MODEL.

Uso:  python scripts/listar_modelos.py
Lê LLM_PROVIDER e LLM_API_KEY do .env. Imprime só nomes de modelos, nunca a chave.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from app.ai.provedores import carregar_config  # noqa: E402


def listar(config, cliente):
    if config.provedor == "gemini":
        r = cliente.get("https://generativelanguage.googleapis.com/v1beta/models",
                        params={"pageSize": 200}, headers={"x-goog-api-key": config.chave})
        r.raise_for_status()
        return sorted(
            m["name"].removeprefix("models/")
            for m in r.json().get("models", [])
            if "generateContent" in m.get("supportedGenerationMethods", [])
        )
    r = cliente.get("https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {config.chave}"})
    r.raise_for_status()
    return sorted(m["id"] for m in r.json().get("data", []))


def main():
    config = carregar_config()
    if config.provedor not in ("gemini", "openai") or not config.chave:
        sys.exit("Preencha LLM_PROVIDER (gemini ou openai) e LLM_API_KEY no .env.")
    try:
        with httpx.Client(timeout=15) as cliente:
            nomes = listar(config, cliente)
    except httpx.HTTPStatusError as erro:
        sys.exit(f"A API respondeu HTTP {erro.response.status_code}. Confira se a chave está correta e ativa.")
    except httpx.HTTPError:
        sys.exit("Não foi possível falar com a API (rede ou timeout).")
    print(f"{len(nomes)} modelos disponíveis para {config.provedor}. Copie UM nome para LLM_MODEL:\n")
    print("\n".join(nomes))


if __name__ == "__main__":
    main()
