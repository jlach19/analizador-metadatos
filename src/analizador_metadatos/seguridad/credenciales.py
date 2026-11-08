import getpass
import os
import sys
from types import ModuleType


SERVICE_NAME = "analizador-metadatos"
ACCOUNT_NAME = "virustotal-api-key"


class ErrorCredenciales(RuntimeError):
    pass


def _keyring_seguro() -> ModuleType:
    try:
        import keyring
    except ImportError as error:
        raise ErrorCredenciales(
            "Falta el paquete para guardar la clave en el llavero seguro. "
            "Instálalo con `python -m pip install -r requirements.txt`."
        ) from error

    backend = keyring.get_keyring()
    nombre_backend = (
        f"{backend.__class__.__module__}.{backend.__class__.__name__}".lower()
    )
    if backend.priority <= 0 or any(
        marcador in nombre_backend
        for marcador in ("plaintext", "null", "fail")
    ):
        raise ErrorCredenciales(
            "No se encontró un llavero seguro del sistema operativo. "
            "Configura GNOME Keyring/KWallet en Linux, o el llavero de macOS "
            "o Windows. La clave no se guardará en texto plano."
        )
    return keyring


def obtener_api_key() -> tuple[str, bool]:
    api_key_entorno = os.environ.get("VT_API_KEY", "").strip()
    if api_key_entorno:
        return api_key_entorno, False

    keyring = _keyring_seguro()
    try:
        api_key_guardada = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
    except keyring.errors.KeyringError as error:
        raise ErrorCredenciales(
            "No se pudo leer la clave del llavero seguro del sistema."
        ) from error
    if api_key_guardada:
        return api_key_guardada, False

    if not sys.stdin.isatty():
        raise ErrorCredenciales(
            "No hay una clave guardada y se necesita una terminal interactiva "
            "para introducirla de forma oculta."
        )
    try:
        api_key_nueva = getpass.getpass(
            "Introduce tu clave API de VirusTotal (no se mostrará): "
        ).strip()
    except (EOFError, KeyboardInterrupt) as error:
        raise ErrorCredenciales("Se canceló la introducción de la clave.") from error
    if not api_key_nueva:
        raise ErrorCredenciales("La clave API no puede estar vacía.")
    return api_key_nueva, True


def guardar_api_key(api_key: str) -> None:
    keyring = _keyring_seguro()
    try:
        keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, api_key)
    except keyring.errors.KeyringError as error:
        raise ErrorCredenciales(
            "No se pudo guardar la clave en el llavero seguro del sistema."
        ) from error
