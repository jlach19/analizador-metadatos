import http.client
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen


API_BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT_SECONDS = 30
UPLOAD_TIMEOUT_SECONDS = 120
POLL_INTERVAL_SECONDS = 5
POLL_TIMEOUT_SECONDS = 300
INLINE_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_UPLOAD_SIZE = 650 * 1024 * 1024

STAT_NAMES = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "timeout",
    "confirmed-timeout",
    "failure",
    "type-unsupported",
)


class VirusTotalError(RuntimeError):
    pass


class VirusTotalNotFound(VirusTotalError):
    pass


@dataclass(frozen=True)
class ReporteVirusTotal:
    fecha_ultimo_analisis: int | None
    estadisticas: dict[str, int]
    reputacion: int
    tipo_archivo: str | None
    archivo_subido: bool = False

    @property
    def es_malicioso(self) -> bool:
        return self.estadisticas["malicious"] > 0

    @property
    def motores_positivos(self) -> int:
        return self.estadisticas["malicious"]


def _mensaje_http(codigo: int) -> str:
    if codigo in (401, 403):
        return "VirusTotal rechazó la clave de API (401/403)."
    if codigo == 404:
        return "VirusTotal no encontró el recurso solicitado (404)."
    if codigo == 413:
        return "VirusTotal rechazó el archivo por exceder el límite de tamaño."
    if codigo == 429:
        return "VirusTotal limitó las consultas (429). Revisa la cuota de la cuenta."
    return f"VirusTotal devolvió un error HTTP {codigo}."


def _request_json(
    url: str,
    api_key: str,
    method: str = "GET",
    data: bytes | None = None,
    content_type: str = "application/json",
) -> dict:
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = content_type
    solicitud = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(solicitud, timeout=TIMEOUT_SECONDS) as respuesta:
            datos = json.loads(respuesta.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 404:
            raise VirusTotalNotFound(_mensaje_http(error.code)) from error
        raise VirusTotalError(_mensaje_http(error.code)) from error
    except TimeoutError as error:
        raise VirusTotalError(
            "La consulta a VirusTotal superó el tiempo de espera."
        ) from error
    except URLError as error:
        raise VirusTotalError(
            f"No se pudo conectar con VirusTotal: {error}"
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VirusTotalError("VirusTotal devolvió una respuesta JSON inválida.") from error
    if not isinstance(datos, dict):
        raise VirusTotalError("VirusTotal devolvió una respuesta inválida.")
    return datos


def _estadisticas(datos: dict) -> dict[str, int]:
    try:
        atributos = datos["data"]["attributes"]
        estadisticas_raw = atributos.get(
            "last_analysis_stats", atributos.get("stats")
        )
        if not isinstance(estadisticas_raw, dict):
            raise TypeError("Faltan las estadísticas de los motores.")
        resultado = {
            nombre: estadisticas_raw.get(nombre, 0) for nombre in STAT_NAMES
        }
        if not all(
            type(valor) is int and valor >= 0 for valor in resultado.values()
        ):
            raise TypeError("Las estadísticas de motores no son enteros válidos.")
        return resultado
    except (KeyError, TypeError, AttributeError) as error:
        raise VirusTotalError(
            "La respuesta de VirusTotal no contiene estadísticas válidas."
        ) from error


def _crear_reporte(
    datos: dict, archivo_subido: bool = False
) -> ReporteVirusTotal:
    try:
        atributos = datos["data"]["attributes"]
        estadisticas = _estadisticas(datos)
        fecha = atributos.get("last_analysis_date", atributos.get("date"))
        reputacion = atributos.get("reputation", 0)
        meta = datos["data"].get("meta", {})
        file_info = meta.get("file_info", {}) if isinstance(meta, dict) else {}
        tipo_archivo = atributos.get(
            "type_description", file_info.get("type_description")
        )
        if fecha is not None and type(fecha) is not int:
            fecha = None
        if type(reputacion) is not int:
            raise TypeError("La reputación no es válida.")
        if tipo_archivo is not None and not isinstance(tipo_archivo, str):
            tipo_archivo = None
    except (KeyError, TypeError, AttributeError) as error:
        raise VirusTotalError(
            "La respuesta de VirusTotal no contiene un reporte de archivo válido."
        ) from error
    return ReporteVirusTotal(
        fecha_ultimo_analisis=fecha,
        estadisticas=estadisticas,
        reputacion=reputacion,
        tipo_archivo=tipo_archivo,
        archivo_subido=archivo_subido,
    )


def consultar_hash(hash_sha256: str, api_key: str) -> dict | None:
    if len(hash_sha256) != 64 or any(
        caracter not in "0123456789abcdefABCDEF" for caracter in hash_sha256
    ):
        raise ValueError(
            "El hash SHA-256 debe contener exactamente 64 caracteres hexadecimales."
        )
    try:
        return _request_json(
            f"{API_BASE_URL}/files/{hash_sha256.lower()}", api_key
        )
    except VirusTotalNotFound:
        return None


def _url_carga(api_key: str) -> str:
    datos = _request_json(f"{API_BASE_URL}/files/upload_url", api_key)
    try:
        url = datos["data"]
        partes = urlsplit(url)
        if not isinstance(url, str) or not partes.hostname:
            raise ValueError("URL de carga no válida.")
        if partes.scheme == "http" and (
            partes.hostname == "virustotal.com"
            or partes.hostname.endswith(".virustotal.com")
        ):
            url = urlunsplit(
                ("https", partes.netloc, partes.path, partes.query, partes.fragment)
            )
        elif partes.scheme != "https":
            raise ValueError("La carga debe usar HTTPS.")
    except (KeyError, TypeError, ValueError) as error:
        raise VirusTotalError(
            "VirusTotal no devolvió una URL de carga válida."
        ) from error
    return url


def _subir_archivo(
    archivo: Path, api_key: str, url: str
) -> dict:
    tamano = archivo.stat().st_size
    if tamano > MAX_UPLOAD_SIZE:
        raise VirusTotalError(
            "El archivo supera el límite de carga de VirusTotal de 650 MB."
        )

    partes = urlsplit(url)
    if partes.scheme != "https" or not partes.hostname:
        raise VirusTotalError("La URL de carga segura de VirusTotal no es válida.")

    limite = partes.path or "/"
    if partes.query:
        limite = f"{limite}?{partes.query}"
    boundary = f"----analizador-metadatos-{uuid.uuid4().hex}"
    nombre = archivo.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
    prefijo = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{nombre}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    sufijo = f"\r\n--{boundary}--\r\n".encode("ascii")
    largo = len(prefijo) + tamano + len(sufijo)
    conexion = http.client.HTTPSConnection(
        partes.hostname,
        partes.port or 443,
        timeout=UPLOAD_TIMEOUT_SECONDS,
    )
    try:
        conexion.putrequest("POST", limite)
        if (
            partes.hostname == "virustotal.com"
            or partes.hostname.endswith(".virustotal.com")
        ):
            conexion.putheader("x-apikey", api_key)
        conexion.putheader("Accept", "application/json")
        conexion.putheader(
            "Content-Type", f"multipart/form-data; boundary={boundary}"
        )
        conexion.putheader("Content-Length", str(largo))
        conexion.endheaders()
        conexion.send(prefijo)
        with archivo.open("rb") as contenido:
            for bloque in iter(lambda: contenido.read(1024 * 1024), b""):
                conexion.send(bloque)
        conexion.send(sufijo)
        respuesta = conexion.getresponse()
        cuerpo = respuesta.read()
        if not 200 <= respuesta.status < 300:
            raise VirusTotalError(_mensaje_http(respuesta.status))
        try:
            datos = json.loads(cuerpo.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VirusTotalError(
                "VirusTotal devolvió una respuesta JSON inválida al subir el archivo."
            ) from error
        if not isinstance(datos, dict):
            raise VirusTotalError("VirusTotal devolvió una respuesta de carga inválida.")
        return datos
    except (OSError, http.client.HTTPException) as error:
        raise VirusTotalError(
            f"No se pudo subir el archivo a VirusTotal: {error}"
        ) from error
    finally:
        conexion.close()


def _esperar_analisis(analysis_id: str, api_key: str) -> dict:
    url = f"{API_BASE_URL}/analyses/{quote(analysis_id, safe='')}"
    limite = time.monotonic() + POLL_TIMEOUT_SECONDS
    while True:
        datos = _request_json(url, api_key)
        try:
            atributos = datos["data"]["attributes"]
            estado = atributos["status"]
        except (KeyError, TypeError) as error:
            raise VirusTotalError(
                "VirusTotal devolvió un estado de análisis inválido."
            ) from error
        if estado == "completed":
            return datos
        if estado not in ("queued", "in-progress"):
            raise VirusTotalError(
                f"El análisis en VirusTotal terminó con estado '{estado}'."
            )
        if time.monotonic() >= limite:
            raise VirusTotalError(
                "VirusTotal no terminó el análisis dentro del tiempo esperado."
            )
        time.sleep(min(POLL_INTERVAL_SECONDS, max(0, limite - time.monotonic())))


def obtener_reporte(
    hash_sha256: str, archivo: str | Path, api_key: str
) -> ReporteVirusTotal:
    if not api_key.strip():
        raise VirusTotalError(
            "La conexión a VirusTotal es obligatoria. Configura la variable "
            "de entorno VT_API_KEY."
        )
    reporte_existente = consultar_hash(hash_sha256, api_key.strip())
    if reporte_existente is not None:
        return _crear_reporte(reporte_existente)

    ruta_archivo = Path(archivo)
    if ruta_archivo.stat().st_size > INLINE_UPLOAD_LIMIT:
        url_carga = _url_carga(api_key.strip())
    else:
        url_carga = f"{API_BASE_URL}/files"
    respuesta_carga = _subir_archivo(ruta_archivo, api_key.strip(), url_carga)
    try:
        analysis_id = respuesta_carga["data"]["id"]
        if not isinstance(analysis_id, str) or not analysis_id:
            raise ValueError("Identificador de análisis inválido.")
    except (KeyError, TypeError, ValueError) as error:
        raise VirusTotalError(
            "VirusTotal no devolvió el identificador del análisis subido."
        ) from error
    datos_analisis = _esperar_analisis(analysis_id, api_key.strip())
    return _crear_reporte(datos_analisis, archivo_subido=True)
