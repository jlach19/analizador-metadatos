# Lector y Analizador de Metadatos de Archivos para Forense Digital

> PROYECTO DEL MODULO 4 DE LA MATERIA DE PROGRAMACIÓN DE LA UNIVERSIDAD NACIONAL DE LAS CIENCIAS DR. HUMBERTO FERNÁNDEZ MORÁN
>  
## Requisitos previos

Se necesita tener instalado el sistema de control de versiones de GIT, para eso entra a su [página
oficial](https://git-scm.com/) y sigue los pasos para la instalación.

Posteriormente, clona este repositorio con el siguiente comando

```bash
git clone https://github.com/jlach19/analizador-metadatos.git
```

Se requiere

* Python 3.10 o posterior
* Libreria Tkinter de Python
* GNU Make
* Compilador C11.
* Un llavero seguro del sistema operativo y la dependencia `keyring` de Python.

Este proyecto corre en Sistemas Operativos Linux, Windows y MacOS. Por lo tanto,
el usuario debe asegurarse de instalar los requerimientos mencionados previamente segun
el sistema operativo de su máquina.

A continuación, se presentan las instrucciones segun cada sistema operativo

### Linux (Debian o Ubuntu)

Abre la terminal y ejecuta

```bash
sudo apt update
sudo apt install python3 python3-tk make build-essential
```

`build-essential` incluye GCC y las cabeceras estándar necesarias para compilar
C.

Si quieres el selector GTK grande, instala la **zenity** en Debian o
Ubuntu con `sudo apt install zenity`.

### Windows

1. Instala Python 3.10 o posterior desde
   [python.org](https://www.python.org/downloads/windows/). Deja habilitados
   Tcl/Tk y el lanzador `py` durante la instalación.
2. Instala Chocolatey siguiendo su
   [guía oficial](https://chocolatey.org/install). Es una instalación de una
   sola vez y requiere PowerShell como administrador.
3. Asegurate de tener instalado Chocolate en tu sistema, si no lo tienes
   instalado sigue las instrucciones de su [guía oficial](https://chocolatey.org/install).
   Luego, en PowerShell como administrador, instala las herramientas de compilación:

   ```powershell
   choco install make mingw -y
   ```

   Esto instala GNU Make y GCC/MinGW. No hace falta instalar MSYS2 ni Visual
   Studio para esta configuración.
4. Cierra y vuelve a abrir PowerShell para que se actualice el `PATH`. Entra a
   la carpeta del proyecto y ejecuta:

   ```powershell
   make
   ```

Si quieres comprobar la instalación antes de ejecutar, estos comandos deben
mostrar versiones:

```powershell
py -3 --version
make --version
gcc --version
```

### macOS

1. Instala Python 3.10 o posterior desde
   [python.org](https://www.python.org/downloads/macos/) y verifica que incluya
   Tcl/Tk.
2. Instala las herramientas de línea de comandos de Apple, que incluyen Clang y
   las cabeceras estándar de C:

   ```bash
   xcode-select --install
   ```

3. Instala [Homebrew](https://brew.sh/) si todavía no lo tienes y luego instala
   GNU Make:

   ```bash
   brew install make
   ```

   macOS ya incluye BSD Make como `make`; Homebrew instala GNU Make como
   `gmake`, que es el comando que debe usarse con este proyecto.

## Compilar y ejecutar

Instala las dependencias de Python una sola vez, usando el mismo Python con el
que ejecutas el proyecto:

```bash
# Linux o macOS
python3 -m pip install -r requirements.txt
make
```

```powershell
# Windows PowerShell
py -3 -m pip install -r requirements.txt
make
```

Desde la carpeta del proyecto, ejecuta el comando correspondiente.

```bash
# Linux y Windows
make

# macOS
gmake
```

## Cómo funciona

1. Selecciona archivo. Se abrirá el selector gráfico para
   navegar por tus directorios. 
2. Python invoca el analizador C con la ruta seleccionada. C abre el archivo
   solo para lectura y extrae sus bytes de cabecera.
3. El programa comprueba:
   - **PDF:** firma `%PDF-`, versión y presencia de `%%EOF` cerca del final.
   - **PNG:** firma, chunk `IHDR`, dimensiones y CRC de `IHDR`.
   - **EXE/PE:** firma DOS `MZ`, desplazamiento PE y firma `PE`.
   - **TXT:** se admite para calcular el hash y consultar VirusTotal; el
     contenido no se analiza localmente.
4. Python calcula el SHA-256 y extrae el formato, la extensión, el tamaño, la
   cabecera hexadecimal, las comprobaciones y las anomalías.
5. La conexión con VirusTotal y `VT_API_KEY` son obligatorias. El programa
   consulta el reporte por SHA-256; si no existe, sube el archivo, espera a que
   VirusTotal termine el análisis y guarda/actualiza su dictamen en
   `REPORTE_VIRUSTOTAL`. Si falta la clave, falla la conexión o VirusTotal no
   termina el análisis, no se registra ni se presenta el análisis como
   completado. Archivos de más de 32 MB usan el endpoint de carga grande; el
   límite de carga de VirusTotal es 650 MB.
6. Cuando hay reporte, el archivo y el análisis local también se guardan en
   SQLite (`database_metadatos`). En consola se muestra un resumen con nombre,
   formato, tamaño legible, SHA-256, estado estructural y anomalías, conteo de
   detecciones de VirusTotal, fecha y procedencia del reporte y confirmación de
   persistencia. La cabecera hexadecimal y cada comprobación se conservan en
   la base, pero no se despliegan en la salida normal.
7. Si cierras el selector sin elegir un archivo, vuelves al menú. 
8. Selecciona "Salir" para cerrar el programa.
