import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EXECUTABLE = ROOT / "build" / (
    "header_analyzer.exe" if sys.platform == "win32" else "header_analyzer"
)


@dataclass(frozen=True)
class ResultadoCabecera:
    formato: str
    tamano_bytes: int
    desplazamiento_firma: int | None
    cabecera_hex: str
    cabecera_valida: bool
    comprobaciones: dict[str, bool]
    anomalias: list[str]


def analizar_archivo(ruta: str | Path) -> ResultadoCabecera:
    archivo = Path(ruta).expanduser()
    if not archivo.is_file():
        raise FileNotFoundError("La ruta no existe o no corresponde a un archivo.")
    if not EXECUTABLE.is_file():
        raise RuntimeError(
            "No se encontró el analizador C. Compílalo primero con `python build.py`."
        )

    resultado = subprocess.run(
        [str(EXECUTABLE), str(archivo)],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if resultado.returncode != 0:
        detalle = resultado.stderr.strip() or (
            f"El analizador C terminó con código {resultado.returncode}."
        )
        raise RuntimeError(detalle)

    try:
        datos = json.loads(resultado.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("El analizador C devolvió una respuesta inválida.") from error

    if (
        not isinstance(datos, dict)
        or not isinstance(datos.get("format"), str)
        or type(datos.get("file_size")) is not int
        or "signature_offset" not in datos
        or (
            datos.get("signature_offset") is not None
            and type(datos.get("signature_offset")) is not int
        )
        or not isinstance(datos.get("header_hex"), str)
        or type(datos.get("header_valid")) is not bool
        or not isinstance(datos.get("checks"), dict)
        or not all(
            isinstance(nombre, str) and type(valor) is bool
            for nombre, valor in datos["checks"].items()
        )
        or not isinstance(datos.get("anomalies"), list)
        or not all(isinstance(anomalia, str) for anomalia in datos["anomalies"])
    ):
        raise RuntimeError("El analizador C devolvió datos incompletos o inválidos.")

    return ResultadoCabecera(
        formato=datos["format"],
        tamano_bytes=datos["file_size"],
        desplazamiento_firma=datos["signature_offset"],
        cabecera_hex=datos["header_hex"],
        cabecera_valida=datos["header_valid"],
        comprobaciones=datos["checks"],
        anomalias=datos["anomalies"],
    )
