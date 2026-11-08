import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from analizador_metadatos.interfaz.cli import ejecutar


if __name__ == "__main__":
    ejecutar()
