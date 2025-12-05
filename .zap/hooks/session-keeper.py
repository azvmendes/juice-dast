"""
Hook para renovar automaticamente sessão JWT no ZAP
Mantém o token atualizado nos headers durante o scan.
"""

import time
import json
from zapv2 import ZAPv2

# A URL de login deve ser a mesma usada para autenticação
LOGIN_URL = "http://127.0.0.1:3002/rest/user/login"

def authenticate():
    """Realiza login e retorna o token JWT atualizado"""
    import requests
    payload = {
        "email": "${ZAP_USERNAME}",
        "password": "${ZAP_PASSWORD}"
    }
    response = requests.post(LOGIN_URL, json=payload)
    if response.status_code == 200 and "authentication" in response.text.lower():
        return response.json().get("authentication", {}).get("token")
    return None


def zap_session_hook(zap=None, target=None, progress=None):
    """Executado automaticamente durante o scan"""
    print("[HOOK] Renovando token JWT para o ZAP...")

    token = authenticate()
    if token:
        print("[HOOK] Token atualizado com sucesso!")
        header = f"Authorization: Bearer {token}"

        # Atualizar o header no contexto
        context_id = 0
        zap.context.set_context_in_scope(context_id, True)
        zap.context.set_tech(context_id, "Language.JavaScript")

        # Remove old header
        zap.context.remove_context_data("httpHeaders", context_id)

        # Add new header
        zap.context.add_context_data("httpHeaders", context_id, header)

        time.sleep(1)
    else:
        print("[HOOK] ERRO: Não foi possível renovar o token!")


