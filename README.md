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

   Si instalaste los requisitos dentro de un entorno virtual llamado `.venv`,
   indica a `make` que use el Python de ese entorno:

   ```powershell
   make PYTHON=".venv/Scripts/python.exe"
   ```

   Ejecuta este comando desde la carpeta del proyecto. No importa si el
   entorno virtual está activado: así tanto la compilación como el programa
   usarán el Python de `.venv` y sus paquetes instalados.

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

Desde la carpeta del proyecto, ejecuta el comando correspondiente.

```bash
# Linux y Windows
make

# macOS
gmake
```

El objetivo predeterminado `run` primero ejecuta `build.py`, que compila el
analizador C si hace falta, y después inicia la interfaz Python. Así no tienes
que compilar C y lanzar Python en comandos separados.

```bash
make build # solo compila el analizador C
```

## Cómo funciona

1. Selecciona **1. Seleccionar archivo**. Se abrirá el selector gráfico para
   navegar por tus directorios. En Linux se usa Zenity cuando está instalado
   (ventana GTK de 1100 × 700); si no está disponible, se usa Tkinter. En
   Windows y macOS se utiliza el diálogo del sistema a través de Tkinter.
2. Python invoca el analizador C con la ruta seleccionada. C abre el archivo
   solo para lectura y extrae sus bytes de cabecera.
3. El programa comprueba:
   - **PDF:** firma `%PDF-`, versión y presencia de `%%EOF` cerca del final.
   - **PNG:** firma, chunk `IHDR`, dimensiones y CRC de `IHDR`.
   - **EXE/PE:** firma DOS `MZ`, desplazamiento PE y firma `PE`.
4. Python presenta la cabecera hexadecimal, el resultado de cada comprobación
   y las anomalías encontradas. Se aceptan extensiones `.pdf`, `.png` y `.exe`.
5. Si cierras el selector sin elegir un archivo, vuelves al menú. Selecciona
   **2. Salir** para cerrar el programa.

Estas comprobaciones son iniciales: no validan por completo los formatos ni
determinan si un archivo es seguro. El programa **no ejecuta el archivo ni se
conecta todavía a VirusTotal**.
