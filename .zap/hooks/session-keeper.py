"""
Hook para renovar automaticamente sessão JWT no ZAP
Mantém o token atualizado nos headers durante o scan.
"""

import os
import time
import json
from zapv2 import ZAPv2

# URL de login acessível a partir do container do ZAP
# Com --network="host" e target http://localhost:3002,
# 127.0.0.1:3002 é equivalente dentro do container.
LOGIN_URL = "http://127.0.0.1:3002/rest/user/login"


def authenticate():
    """Realiza login e retorna o token JWT atualizado"""
    import requests  # usando requests para simplificar a chamada HTTP

    email = os.getenv("ZAP_USERNAME")
    password = os.getenv("ZAP_PASSWORD")

    if not email or not password:
        print("[HOOK] ERRO: ZAP_USERNAME ou ZAP_PASSWORD não definidos no ambiente.")
        return None

    payload = {
        "email": email,
        "password": password,
    }

    try:
        print(f"[HOOK] Efetuando login em {LOGIN_URL} com usuário {email}...")
        response = requests.post(LOGIN_URL, json=payload)
        print(f"[HOOK] Login status: {response.status_code}")
        print(f"[HOOK] Resposta: {response.text}")

        if response.status_code == 200:
            data = response.json()
            # Ajuste conforme o formato real do JSON de resposta da sua API
            auth = data.get("authentication", {})
            token = auth.get("token")
            if token:
                return token

        print("[HOOK] ERRO: resposta de login não contém token esperado.")
    except Exception as e:
        print(f"[HOOK] ERRO ao autenticar: {e}")

    return None


def zap_session_hook(zap=None, target=None, progress=None):
    """
    Função chamada automaticamente pelo ZAP durante o scan.
    Atualiza o header Authorization com um token JWT válido.
    """
    print("[HOOK] Renovando token JWT para o ZAP...")

    token = authenticate()
    if not token:
        print("[HOOK] ERRO: Não foi possível renovar o token!")
        return

    print("[HOOK] Token atualizado com sucesso!")

    # Exemplo de header que será aplicado às requisições
    header = f"Authorization: Bearer {token}"

    # Contexto padrão (0) – ajuste se você tiver mais de um contexto
    context_id = 0

    # Garante que o contexto está in-scope
    try:
        zap.context.set_context_in_scope(context_id, True)
    except Exception as e:
        print(f"[HOOK] Aviso ao marcar contexto como in-scope: {e}")

    # Dependendo da versão da API, os métodos abaixo podem variar.
    # Este é um exemplo genérico de remoção e adição de headers.
    try:
        zap.context.remove_context_data("httpHeaders", context_id)
    except Exception as e:
        print(f"[HOOK] Aviso ao remover headers antigos: {e}")

    try:
        zap.context.add_context_data("httpHeaders", context_id, header)
        print(f"[HOOK] Header atualizado no contexto {context_id}: {header}")
    except Exception as e:
        print(f"[HOOK] ERRO ao adicionar novo header: {e}")

    # Pequeno delay para evitar flood
    time.sleep(1)