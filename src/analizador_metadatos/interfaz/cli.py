import shutil
import sqlite3
import subprocess
import sys
import tkinter as tk
from datetime import datetime
from os import environ
from pathlib import Path
from tkinter import filedialog

from analizador_metadatos.analisis.analizador_c import analizar_archivo
from analizador_metadatos.analisis.analizador_c import ResultadoCabecera
from analizador_metadatos.analisis.hash_archivo import calcular_sha256
from analizador_metadatos.persistencia.sqlite import (
    DATABASE_PATH,
    inicializar_db,
    registrar_analisis,
    registrar_reporte_virustotal,
)
from analizador_metadatos.integraciones.virustotal import (
    ReporteVirusTotal,
    VirusTotalError,
    obtener_reporte,
)
from analizador_metadatos.seguridad.credenciales import (
    ErrorCredenciales,
    guardar_api_key,
    obtener_api_key,
)


def formato_tamano(tamano_bytes: int) -> str:
    unidades = ("bytes", "KiB", "MiB", "GiB")
    tamano = float(tamano_bytes)
    unidad = unidades[0]
    for unidad_siguiente in unidades[1:]:
        if tamano < 1024:
            break
        tamano /= 1024
        unidad = unidad_siguiente
    if unidad == "bytes":
        return f"{tamano_bytes:,} {unidad}"
    return f"{tamano_bytes:,} bytes ({tamano:.1f} {unidad})"


def imprimir_resumen_analisis(
    archivo: Path,
    resultado: ResultadoCabecera,
    hash_sha256: str,
    reporte: ReporteVirusTotal,
    estado_sqlite: str,
) -> None:
    nombre_formato = (
        f"{archivo.name} ({resultado.formato}, "
        f"{formato_tamano(resultado.tamano_bytes)})"
    )
    print("\n=== Resumen del análisis ===")
    print(f"Archivo: {nombre_formato}")
    print(f"SHA-256: {hash_sha256}")

    if resultado.formato == "TXT":
        print(
            "Estructura: no aplica para TXT; el contenido no se analiza localmente."
        )
    elif resultado.cabecera_valida and not resultado.anomalias:
        print("Estructura: válida; sin anomalías detectadas.")
    else:
        print("Estructura: requiere revisión.")
        if resultado.anomalias:
            print("Anomalías:")
            for anomalia in resultado.anomalias:
                print(f"  - {anomalia.replace('_', ' ')}")
        if (
            resultado.desplazamiento_firma is not None
            and resultado.desplazamiento_firma != 0
        ):
            print(
                "Desplazamiento de la firma: "
                f"{resultado.desplazamiento_firma} bytes"
            )

    estadisticas = reporte.estadisticas
    motores_analizados = sum(estadisticas.values())
    detecciones = estadisticas["malicious"] + estadisticas["suspicious"]
    if motores_analizados:
        print(
            "VirusTotal: "
            f"{detecciones}/{motores_analizados} detecciones "
            f"({estadisticas['malicious']} maliciosas, "
            f"{estadisticas['suspicious']} sospechosas)"
        )
        if estadisticas["malicious"]:
            unidad_motor = (
                "motor" if estadisticas["malicious"] == 1 else "motores"
            )
            print(
                "Veredicto de VirusTotal: detecciones maliciosas "
                f"({estadisticas['malicious']} {unidad_motor})."
            )
        else:
            print(
                "Veredicto de VirusTotal: sin detecciones maliciosas en este "
                "reporte; esto no garantiza que el archivo sea seguro."
            )
        print(
            "La ausencia de detecciones no garantiza que el archivo sea seguro; "
            "el resultado depende de los motores consultados."
        )
    else:
        print("VirusTotal: no hay estadísticas de motores disponibles.")

    if reporte.fecha_ultimo_analisis is not None:
        fecha = datetime.fromtimestamp(
            reporte.fecha_ultimo_analisis
        ).astimezone()
        print(f"Último análisis VT: {fecha.isoformat(timespec='minutes')}")
    origen = (
        "archivo subido a VirusTotal"
        if reporte.archivo_subido
        else "reporte existente por SHA-256"
    )
    print(f"Reporte obtenido mediante: {origen}.")
    print(estado_sqlite)


def validar_archivo(ruta: str | Path) -> Path:
    if not str(ruta).strip():
        raise ValueError("La ruta no puede estar vacía.")

    archivo = Path(ruta).expanduser()
    if not archivo.is_file():
        raise FileNotFoundError("La ruta no existe o no corresponde a un archivo.")
    return archivo


def seleccionar_archivo() -> Path | None:
    if sys.platform.startswith("linux"):
        zenity = shutil.which("zenity")
        if zenity is not None:
            resultado = subprocess.run(
                [
                    zenity,
                    "--file-selection",
                    "--title=Selecciona un archivo para analizar",
                    "--width=1100",
                    "--height=700",
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            if resultado.returncode == 1:
                return None
            if resultado.returncode != 0:
                detalle = resultado.stderr.strip() or (
                    "Zenity no pudo abrir el selector de archivos."
                )
                raise RuntimeError(detalle)
            return validar_archivo(resultado.stdout.rstrip("\n"))

    ventana = None
    try:
        ventana = tk.Tk()
        ventana.withdraw()
        ruta = filedialog.askopenfilename(
            title="Selecciona un archivo para analizar"
        )
    except tk.TclError as error:
        mensaje = f"No se pudo abrir el selector de archivos: {error}"
        raise RuntimeError(mensaje) from error
    finally:
        if ventana is not None:
            ventana.destroy()

    if not ruta:
        return None
    return validar_archivo(ruta)


def solicitar_datos_usuario() -> tuple[str, str]:
    while True:
        nombre = " ".join(input("Nombre del usuario: ").split())
        if nombre:
            nombre = " ".join(palabra.capitalize() for palabra in nombre.split())
            break
        print("El nombre no puede estar vacío.")

    while True:
        print("\nSelecciona tu rol:")
        print("1. Administrador")
        print("2. Analista")
        rol_elegido = input("Elige 1 o 2: ").strip()
        if rol_elegido == "1":
            return nombre, "Administrador"
        if rol_elegido == "2":
            return nombre, "Analista"
        print("Opción no válida. Elige 1 o 2.")


def ejecutar() -> None:
    print("=== Lector y Analizador de Metadatos ===")
    try:
        nombre_usuario, rol_usuario = solicitar_datos_usuario()
    except EOFError:
        print("\nNo se recibieron los datos del usuario. Saliendo.")
        return

    while True:
        print("\n1. Seleccionar archivo")
        print("2. Salir")

        try:
            opcion = input("Elige una opción: ").strip()
        except EOFError:
            print("\nFin de la entrada. Saliendo.")
            return

        if opcion == "1":
            try:
                archivo = seleccionar_archivo()
                if archivo is None:
                    print("Selección cancelada.")
                    continue
                print(
                    "Privacidad: si no hay reporte, el archivo se subirá a "
                    "VirusTotal y podría compartirse públicamente."
                )
                api_key, clave_nueva = obtener_api_key()
            except ErrorCredenciales as error:
                print(f"No se puede iniciar el análisis: {error}")
                continue
            except (OSError, RuntimeError, ValueError) as error:
                print(f"No se pudo seleccionar el archivo: {error}")
                continue

            try:
                resultado = analizar_archivo(archivo)
                hash_sha256 = calcular_sha256(archivo)
            except (OSError, RuntimeError, ValueError) as error:
                print(f"No se pudo analizar el archivo: {error}")
                continue

            print("\nConsultando el reporte de VirusTotal...")
            try:
                reporte = obtener_reporte(hash_sha256, archivo, api_key)
            except (OSError, VirusTotalError, ValueError) as error:
                print(f"Análisis no completado: {error}")
                continue

            if clave_nueva:
                try:
                    guardar_api_key(api_key)
                except ErrorCredenciales as error:
                    print(
                        f"Reporte obtenido, pero no se pudo guardar la clave: {error}"
                    )
                else:
                    print("Clave API guardada en el llavero seguro del sistema.")

            ruta_db = environ.get("DB_METADATOS_PATH")
            if ruta_db:
                ruta_db = Path(ruta_db).expanduser()
            else:
                ruta_db = DATABASE_PATH

            ids_db = None
            id_reporte = None
            try:
                inicializar_db(ruta_db)
                ids_db = registrar_analisis(
                    nombre_usuario=nombre_usuario,
                    rol_usuario=rol_usuario,
                    nombre_archivo=archivo.name,
                    extension=archivo.suffix.lower() or "(sin extensión)",
                    tamano_bytes=resultado.tamano_bytes,
                    hash_sha256=hash_sha256,
                    integridad_estructural=resultado.cabecera_valida,
                    cabecera_hex=resultado.cabecera_hex,
                    fecha_hora=datetime.now().astimezone().isoformat(
                        timespec="seconds"
                    ),
                    ruta_db=ruta_db,
                )
            except sqlite3.Error as error:
                print(f"No se pudo guardar el análisis en SQLite: {error}")

            if ids_db is not None:
                try:
                    id_reporte = registrar_reporte_virustotal(
                        id_archivo=ids_db[1],
                        es_malicioso=reporte.es_malicioso,
                        motores_positivos=reporte.motores_positivos,
                        ruta_db=ruta_db,
                    )
                except sqlite3.Error as error:
                    print(f"No se pudo guardar el reporte en SQLite: {error}")

            if ids_db is None:
                estado_sqlite = "SQLite: no se pudieron guardar archivo y análisis."
            elif id_reporte is None:
                estado_sqlite = "SQLite: archivo y análisis guardados; reporte pendiente."
            else:
                estado_sqlite = "SQLite: archivo, análisis y reporte guardados."
            imprimir_resumen_analisis(
                archivo, resultado, hash_sha256, reporte, estado_sqlite
            )
        elif opcion == "2":
            print("Hasta luego.")
            return
        else:
            print("Opción no válida. Elige 1 o 2.")
