"""CuidaDados. Carrega o .env (se existir) antes de qualquer módulo ler variáveis de ambiente.

Variáveis já definidas no ambiente têm prioridade sobre o .env (override=False)."""
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv ausente: usa só as variáveis do ambiente
    pass
