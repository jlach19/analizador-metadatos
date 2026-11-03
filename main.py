from pathlib import Path

import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog

from analizador_c import analizar_archivo


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


def ejecutar() -> None:
    print("=== Lector y Analizador de Metadatos ===")

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
                resultado = analizar_archivo(archivo)
            except (OSError, RuntimeError, ValueError) as error:
                print(f"No se pudo analizar el archivo: {error}")
                continue

            print("\nResultado del análisis local:")
            print(f"  Nombre: {archivo.name}")
            print(f"  Formato: {resultado.formato}")
            print(f"  Tamaño: {resultado.tamano_bytes} bytes")
            if resultado.desplazamiento_firma is not None:
                print(
                    "  Desplazamiento de la firma: "
                    f"{resultado.desplazamiento_firma} bytes"
                )
            print(f"  Cabecera hexadecimal: {resultado.cabecera_hex}")
            estado = "válida" if resultado.cabecera_valida else "anómala"
            print(f"  Cabecera: {estado}")
            print("  Comprobaciones:")
            for nombre, valida in resultado.comprobaciones.items():
                estado_comprobacion = "correcta" if valida else "fallida"
                print(f"    - {nombre.replace('_', ' ')}: {estado_comprobacion}")
            if resultado.anomalias:
                print("  Anomalías detectadas:")
                for anomalia in resultado.anomalias:
                    print(f"    - {anomalia.replace('_', ' ')}")
            else:
                print("  Anomalías detectadas: ninguna en las comprobaciones realizadas.")
            print("  El archivo no se ejecutó ni se envió a VirusTotal.")
        elif opcion == "2":
            print("Hasta luego.")
            return
        else:
            print("Opción no válida. Elige 1 o 2.")


if __name__ == "__main__":
    ejecutar()
