"""Configuração dos testes: define o ambiente ANTES de importar app.main."""
import os
import tempfile

os.environ.setdefault("MODO_DEMO", "1")
os.environ.setdefault("APP_SECRET", "segredo-somente-de-teste")
os.environ.setdefault("AUDIT_DB", os.path.join(tempfile.mkdtemp(), "auditoria.db"))

import pytest  # noqa: E402

from app.audit import configurar  # noqa: E402


@pytest.fixture(autouse=True)
def auditoria(tmp_path):
    """Cada teste usa um banco de auditoria novo e vazio."""
    return configurar(str(tmp_path / "auditoria.db"), saida_console=False)
