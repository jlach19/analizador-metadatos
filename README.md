# Lector y Analizador de Metadatos de Archivos para Forense Digital

Proyecto de la materia de Programación de la UNC.

## Requisitos previos

El proyecto requiere Python 3.10 o posterior, Tkinter, GNU Make y un compilador
C11. **No necesita paquetes de terceros de Python ni librerías externas de C.**
El analizador C solo usa cabeceras incluidas en C11: `ctype.h`, `inttypes.h`,
`limits.h`, `stdint.h`, `stdio.h` y `string.h`. Tkinter forma parte de la
biblioteca estándar de Python, pero algunas distribuciones requieren instalar
por separado los componentes Tk del sistema.

### Linux (Debian o Ubuntu)

Instala Python, Tkinter, GNU Make y GCC:

```bash
sudo apt update
sudo apt install python3 python3-tk make build-essential
```

`build-essential` incluye GCC y las cabeceras estándar necesarias para compilar
C. En Fedora, instala los paquetes equivalentes con:

```bash
sudo dnf install python3 python3-tkinter make gcc
```

Zenity es opcional; si quieres el selector GTK grande, instálalo en Debian o
Ubuntu con `sudo apt install zenity`.

### Windows

1. Instala Python 3.10 o posterior desde
   [python.org](https://www.python.org/downloads/windows/). Deja habilitados
   Tcl/Tk y el lanzador `py` durante la instalación.
2. Instala Chocolatey siguiendo su
   [guía oficial](https://chocolatey.org/install). Es una instalación de una
   sola vez y requiere PowerShell como administrador.
3. En PowerShell como administrador, instala las herramientas de compilación:

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

   El Makefile usa `py -3`: compila el código C con GCC y, si la compilación
   termina correctamente, inicia el programa Python.

Si quieres comprobar la instalación antes de ejecutar, estos comandos deben
mostrar versiones:

```powershell
py -3 --version
make --version
gcc --version
```

Si `py` no se reconoce, repara o reinstala Python incluyendo el lanzador `py`.

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
make build
```

`make build` solo compila el analizador C. También puedes iniciar explícitamente
la aplicación con `make run`. El Makefile usa `python3` en Linux/macOS y `py -3`
en Windows. Si `py` no está disponible en Windows, puedes indicar otro comando
con `make "PYTHON=python"` si `python` está en el `PATH`.

```bash
make "PYTHON=python"
```

El ejecutable C se guarda en `build/` y se vuelve a compilar cuando cambia su
código fuente.

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
