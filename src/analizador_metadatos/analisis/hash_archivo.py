import hashlib
from pathlib import Path


def calcular_sha256(archivo: str | Path) -> str:
    sha256 = hashlib.sha256()
    with Path(archivo).open("rb") as contenido:
        for bloque in iter(lambda: contenido.read(1024 * 1024), b""):
            sha256.update(bloque)
    return sha256.hexdigest()
