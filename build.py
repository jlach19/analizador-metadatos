import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "c" / "header_analyzer.c"
BUILD_DIR = ROOT / "build"
IS_WINDOWS = sys.platform == "win32"
EXECUTABLE = BUILD_DIR / ("header_analyzer.exe" if IS_WINDOWS else "header_analyzer")


def compilar() -> Path:
    BUILD_DIR.mkdir(exist_ok=True)

    if EXECUTABLE.exists() and EXECUTABLE.stat().st_mtime >= SOURCE.stat().st_mtime:
        print(f"El analizador C ya está actualizado: {EXECUTABLE}")
        return EXECUTABLE

    if IS_WINDOWS and shutil.which("cl"):
        compiler = shutil.which("cl")
        command = [
            compiler,
            "/nologo",
            "/std:c11",
            "/W4",
            "/O2",
            f"/Fe:{EXECUTABLE.name}",
            str(SOURCE),
        ]
    else:
        compiler = (
            shutil.which("gcc")
            or shutil.which("clang")
            or shutil.which("cc")
        )
        if compiler is None:
            raise RuntimeError(
                "No se encontró un compilador C. Instala GCC o Clang "
                "(o abre la terminal de herramientas de Visual Studio en Windows)."
            )
        command = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(SOURCE),
            "-o",
            EXECUTABLE.name,
        ]

    print(f"Compilando analizador C con {Path(compiler).name}...")
    subprocess.run(command, cwd=BUILD_DIR, check=True)
    if not EXECUTABLE.is_file():
        raise RuntimeError("La compilación terminó sin crear el ejecutable esperado.")

    print(f"Analizador C listo: {EXECUTABLE}")
    return EXECUTABLE


if __name__ == "__main__":
    try:
        compilar()
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"No se pudo compilar el analizador C: {error}", file=sys.stderr)
        raise SystemExit(1) from error
