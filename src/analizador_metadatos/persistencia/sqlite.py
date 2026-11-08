import sqlite3
from contextlib import closing
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[3] / "database_metadatos"

SCHEMA = """
CREATE TABLE IF NOT EXISTS USUARIO (
    id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    rol TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ARCHIVO (
    id_archivo INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    extension TEXT NOT NULL,
    tamano_bytes INTEGER NOT NULL,
    hash_sha256 TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS ANALISIS (
    id_analisis INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha_hora TEXT NOT NULL,
    integridad_estructural INTEGER NOT NULL,
    cabecera_hex_extraida TEXT NOT NULL,
    id_usuario INTEGER NOT NULL,
    id_archivo INTEGER NOT NULL,
    FOREIGN KEY (id_usuario) REFERENCES USUARIO(id_usuario) ON DELETE CASCADE,
    FOREIGN KEY (id_archivo) REFERENCES ARCHIVO(id_archivo) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS REPORTE_VIRUSTOTAL (
    id_reporte INTEGER PRIMARY KEY AUTOINCREMENT,
    es_malicioso INTEGER NOT NULL,
    motores_positivos INTEGER NOT NULL,
    id_archivo INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (id_archivo) REFERENCES ARCHIVO(id_archivo) ON DELETE CASCADE
);
"""


def _normalizar_nombre(nombre: str) -> str:
    return " ".join(palabra.capitalize() for palabra in nombre.split())


def inicializar_db(ruta_db: str | Path = DATABASE_PATH) -> None:
    with closing(sqlite3.connect(ruta_db)) as conexion:
        conexion.execute("PRAGMA foreign_keys = ON")
        conexion.executescript(SCHEMA)


def registrar_analisis(
    nombre_usuario: str,
    rol_usuario: str,
    nombre_archivo: str,
    extension: str,
    tamano_bytes: int,
    hash_sha256: str,
    integridad_estructural: bool,
    cabecera_hex: str,
    fecha_hora: str,
    ruta_db: str | Path = DATABASE_PATH,
) -> tuple[int, int, int]:
    nombre_usuario = _normalizar_nombre(nombre_usuario)
    nombre_normalizado = nombre_usuario.casefold()
    with closing(sqlite3.connect(ruta_db)) as conexion:
        conexion.execute("PRAGMA foreign_keys = ON")
        with conexion:
            usuarios = conexion.execute(
                "SELECT id_usuario, nombre FROM USUARIO WHERE rol = ?",
                (rol_usuario,),
            ).fetchall()
            usuario_existente = next(
                (
                    (id_usuario, nombre)
                    for id_usuario, nombre in usuarios
                    if _normalizar_nombre(nombre).casefold() == nombre_normalizado
                ),
                None,
            )
            if usuario_existente is None:
                cursor = conexion.execute(
                    "INSERT INTO USUARIO (nombre, rol) VALUES (?, ?)",
                    (nombre_usuario, rol_usuario),
                )
                id_usuario = cursor.lastrowid
            else:
                id_usuario, nombre_guardado = usuario_existente
                if nombre_guardado != nombre_usuario:
                    conexion.execute(
                        "UPDATE USUARIO SET nombre = ? WHERE id_usuario = ?",
                        (nombre_usuario, id_usuario),
                    )

            conexion.execute(
                """
                INSERT INTO ARCHIVO (nombre, extension, tamano_bytes, hash_sha256)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hash_sha256) DO UPDATE SET
                    nombre = excluded.nombre,
                    extension = excluded.extension,
                    tamano_bytes = excluded.tamano_bytes
                """,
                (nombre_archivo, extension, tamano_bytes, hash_sha256),
            )
            archivo = conexion.execute(
                "SELECT id_archivo FROM ARCHIVO WHERE hash_sha256 = ?",
                (hash_sha256,),
            ).fetchone()
            if archivo is None:
                raise sqlite3.IntegrityError("No se pudo recuperar el archivo guardado.")
            id_archivo = archivo[0]

            cursor = conexion.execute(
                """
                INSERT INTO ANALISIS (
                    fecha_hora, integridad_estructural, cabecera_hex_extraida,
                    id_usuario, id_archivo
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    fecha_hora,
                    int(integridad_estructural),
                    cabecera_hex,
                    id_usuario,
                    id_archivo,
                ),
            )
            return id_usuario, id_archivo, cursor.lastrowid


def registrar_reporte_virustotal(
    id_archivo: int,
    es_malicioso: bool,
    motores_positivos: int,
    ruta_db: str | Path = DATABASE_PATH,
) -> int:
    with closing(sqlite3.connect(ruta_db)) as conexion:
        conexion.execute("PRAGMA foreign_keys = ON")
        with conexion:
            conexion.execute(
                """
                INSERT INTO REPORTE_VIRUSTOTAL (
                    id_archivo, es_malicioso, motores_positivos
                ) VALUES (?, ?, ?)
                ON CONFLICT(id_archivo) DO UPDATE SET
                    es_malicioso = excluded.es_malicioso,
                    motores_positivos = excluded.motores_positivos
                """,
                (id_archivo, int(es_malicioso), motores_positivos),
            )
            reporte = conexion.execute(
                "SELECT id_reporte FROM REPORTE_VIRUSTOTAL WHERE id_archivo = ?",
                (id_archivo,),
            ).fetchone()
            if reporte is None:
                raise sqlite3.IntegrityError(
                    "No se pudo recuperar el reporte de VirusTotal guardado."
                )
            return reporte[0]
