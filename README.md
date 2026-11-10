# Escáner de Red

Aplicación de escritorio para Windows que busca los dispositivos conectados a la
red, muestra sus datos (IP, nombre, MAC, puertos abiertos), guarda los escaneos
para consultarlos o compararlos después, e incluye una herramienta de ping.

Está hecha en Python con Tkinter y usa solo la librería estándar.

## Funciones

### Pestaña Escaneo

- Detecta automáticamente las redes de la PC y propone la principal.
- Acepta una red (`192.168.1.0/24`), un rango (`192.168.1.1-50` o
  `192.168.1.1-192.168.1.50`), una IP suelta o un nombre de equipo.
  El máximo por escaneo es de 65.536 direcciones.
- De cada dispositivo muestra:
  - **IP**
  - **Nombre** (resolución inversa de DNS / NetBIOS)
  - **MAC** (solo para equipos de la misma red local)
  - **Latencia** del ping
  - **Sistema (estimado)**, deducido del TTL de la respuesta; es orientativo
  - **Puertos abiertos**, con el nombre del servicio cuando es conocido
- Encuentra también equipos que no responden al ping, porque además consulta
  por ARP. Esos aparecen como "sin resp. a ping".
- La lista de puertos es editable: `22,80,443,8000-8100`. Si se deja vacía no se
  escanean puertos.
- "Espera (ms)" es el tiempo máximo que se espera cada respuesta (ping y
  puertos). En redes lentas o por VPN conviene subirlo.
- Clic en el encabezado de una columna para ordenar.
- Doble clic en un equipo: le hace ping. Clic derecho: copiar IP, copiar MAC,
  abrir en el navegador.
- **Guardar**: graba el escaneo en el historial con una nota opcional.
- **Exportar...**: genera un CSV (separado por `;`, se abre directo en Excel) o
  un JSON.

### Pestaña Ping

- Ping a una IP o nombre de equipo.
- Parámetros: cantidad de envíos (0 = continuo hasta "Detener"), intervalo,
  espera y tamaño del paquete en bytes.
- Muestra cada respuesta con la hora y, al final, las estadísticas: enviados,
  recibidos, perdidos y tiempos mínimo, máximo y medio.

### Pestaña Historial

- Lista los escaneos guardados con fecha, red, cantidad de dispositivos,
  duración y nota.
- **Abrir**: vuelve a cargar un escaneo guardado en la pestaña Escaneo (desde
  ahí se puede exportar).
- **Comparar dos**: seleccionando dos escaneos con Ctrl+clic, muestra los
  dispositivos nuevos, los que ya no aparecen y los cambios de MAC, nombre o
  puertos en los que siguen estando.
- **Eliminar**: borra los escaneos seleccionados.

## Requisitos

- Windows 10 u 11 (usa la API de red de Windows; no funciona en Linux ni macOS).
- Python 3.10 o superior, instalado con la opción "tcl/tk" (viene marcada por
  defecto en el instalador de python.org). Desarrollado y probado con
  Python 3.14.
- No requiere permisos de administrador.

## Ejecutar

Sin instalar nada, con el Python del sistema:

```
EscanerRed.bat
```

o bien:

```
python escaner_red.py
```

## Entorno virtual

El entorno virtual solo hace falta para generar el `.exe` (la aplicación no
tiene dependencias externas), pero sirve para no instalar PyInstaller en el
Python del sistema.

Desde la carpeta del proyecto, en PowerShell:

```powershell
# 1. Crear el entorno (una sola vez). Crea la carpeta .venv
python -m venv .venv

# 2. Activarlo (cada vez que se abre una consola nueva)
.\.venv\Scripts\Activate.ps1

# 3. Instalar las librerías del requirements.txt
python -m pip install -r requirements.txt

# 4. Ejecutar la aplicación dentro del entorno
python escaner_red.py

# 5. Salir del entorno
deactivate
```

Si se usa la consola clásica (cmd) en vez de PowerShell, el paso 2 es:

```
.venv\Scripts\activate.bat
```

Si PowerShell rechaza la activación con un error de "ejecución de scripts
deshabilitada", habilitarla para el usuario actual y reintentar:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Cuando el entorno está activo, el prompt empieza con `(.venv)`. La carpeta
`.venv` no se sube al repositorio; en otra PC se vuelve a crear con los mismos
pasos.

## Generar el .exe

Con el entorno virtual activo:

```powershell
pyinstaller --noconfirm --onefile --windowed --name EscanerRed escaner_red.py
```

El resultado queda en `dist\EscanerRed.exe`. Es un único archivo que se puede
copiar a cualquier PC con Windows de 64 bits, sin necesidad de tener Python.

A tener en cuenta:

- Después de cambiar el código hay que volver a generar el `.exe`.
- Al no estar firmado digitalmente, SmartScreen o el antivirus pueden mostrar
  una advertencia en otras PC.
- Las carpetas `build\` y `dist\` y el archivo `EscanerRed.spec` que genera
  PyInstaller no se suben al repositorio.

## Dónde se guardan los datos

Los escaneos se guardan en `escaneos.db` (SQLite), en la misma carpeta que
`escaner_red.py` o, si se usa el ejecutable, en la carpeta donde está el `.exe`.
Para llevar el historial a otra PC alcanza con copiar ese archivo.

Se puede indicar otra ubicación con la variable de entorno `ESCANER_DB`:

```powershell
$env:ESCANER_DB = "D:\datos\escaneos.db"
python escaner_red.py
```

La base tiene dos tablas:

| Tabla | Contenido |
|---|---|
| `escaneos` | Un registro por escaneo: `id`, `fecha`, `objetivo` (red o rango), `puertos` (lista pedida), `duracion` (segundos), `nota` |
| `dispositivos` | Un registro por equipo encontrado: `escaneo_id`, `ip`, `nombre`, `mac`, `latencia` (ms, vacío si no respondió al ping), `ttl`, `puertos` (lista JSON de puertos abiertos) |

`escaneos.db` no se sube al repositorio porque contiene datos de la red
(direcciones, nombres y MAC de los equipos).

## Archivos del proyecto

| Archivo | Descripción |
|---|---|
| `escaner_red.py` | Toda la aplicación |
| `EscanerRed.bat` | Acceso directo para abrirla sin consola |
| `requirements.txt` | Librerías a instalar en el entorno virtual |
| `README.md` | Esta documentación |

## Cómo funciona por dentro

`escaner_red.py` está organizado en estas partes:

- **Red a bajo nivel**: `icmp_ping` (ping con `IcmpSendEcho`) y `obtener_mac`
  (ARP con `SendARP`) llaman a `iphlpapi.dll` de Windows mediante `ctypes`. Por
  eso no dependen del idioma del sistema ni abren procesos `ping.exe`.
  `puerto_abierto` prueba una conexión TCP y `resolver_nombre` hace la
  resolución inversa.
- **Detección de redes**: `detectar_redes` consulta las interfaces con el cmdlet
  `Get-NetIPAddress` de PowerShell.
- **Entrada del usuario**: `interpretar_objetivo` e `interpretar_puertos`
  convierten el texto en listas de IP y de puertos.
- **Base de datos**: clase `BaseDatos`.
- **Interfaz**: clase `App`, con las tres pestañas.

El escaneo corre en hilos: hasta 128 direcciones en paralelo y un grupo aparte
de 200 hilos para los puertos. Los hilos nunca tocan la interfaz; mandan los
resultados por una cola que la ventana lee cada 80 ms.

## Limitaciones

- Solo IPv4.
- La MAC solo se obtiene de equipos de la misma red local; a través de un router
  o una VPN se ven la IP y los puertos, pero no la MAC.
- Solo se prueban puertos TCP.
- El sistema estimado puede fallar: se basa únicamente en el TTL.
- No muestra el fabricante del dispositivo.

## Uso responsable

Escanear redes ajenas sin autorización puede ser ilegal o violar políticas de
uso. Usar la aplicación solo en redes propias o con permiso del administrador.
