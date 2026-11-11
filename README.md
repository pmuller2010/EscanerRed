# Escáner de Red

Aplicación de escritorio para Windows que busca los dispositivos conectados a la
red, averigua todo lo posible para identificarlos (nombre, MAC, fabricante,
sistema, puertos y servicios), marca los que no están autorizados, guarda los
escaneos para consultarlos o compararlos después, e incluye una herramienta de
ping.

Está hecha en Python con Tkinter y usa solo la librería estándar.

## Funciones

### Pestaña Escaneo

- Detecta automáticamente las redes de la PC y propone la principal.
- Acepta una red (`192.168.1.0/24`), un rango (`192.168.1.1-50` o
  `192.168.1.1-192.168.1.50`), una IP suelta o un nombre de equipo.
  El máximo por escaneo es de 65.536 direcciones.
- De cada dispositivo muestra:
  - **Estado**: `Autorizado`, `SIN AUTORIZAR` (fila en rojo) o `Este equipo`
  - **IP**
  - **Nombre**
  - **MAC** (solo para equipos de la misma red local)
  - **Fabricante** de la placa de red, según la MAC
  - **Tipo / sistema (estimado)**
  - **Latencia** del ping
  - **Puertos abiertos**, con el nombre del servicio cuando es conocido
- Encuentra también equipos que no responden al ping, porque además consulta
  por ARP. Esos aparecen como "sin resp. a ping".
- Doble clic en un equipo abre el **detalle** con todo lo que se averiguó.

#### Cómo se identifica cada equipo

Los nombres no dependen solo de la resolución de Windows (que falla seguido):
se le pregunta directamente a cada equipo por varios protocolos.

| Dato | De dónde sale |
|---|---|
| Nombre | NetBIOS (UDP 137), mDNS/Bonjour (UDP 5353), DNS inverso, LLMNR (UDP 5355), SMB y UPnP |
| Grupo de trabajo / dominio | NetBIOS y SMB |
| Versión de Windows | SMB (puerto 445), sin iniciar sesión. Da la compilación exacta |
| Fabricante | Los primeros 6 dígitos de la MAC, con la base oficial del IEEE (`fabricantes.txt`) |
| Página web del equipo | Título y servidor en los puertos 80, 8080, 8000, 443 y 8443 |
| Servicios | Primera línea que mandan SSH, FTP y SMTP (versión del software) |
| Modelo | UPnP/SSDP: routers, televisores, impresoras, cámaras, NAS |

Si la MAC es **privada/aleatoria** se indica en la columna Fabricante. Esas MAC
las inventa el propio equipo (celulares, tablets y notebooks con "dirección
Wi-Fi privada"), así que suelen ser dispositivos personales.

El botón **Actualizar fabricantes** baja la última base del IEEE (necesita
internet).

#### Detectar equipos que no son de la empresa

1. Hacer un escaneo y revisar la lista con el detalle de cada equipo.
2. Clic derecho en cada equipo conocido → **Marcar como autorizado...**, con una
   descripción ("Notebook de Juan", "Impresora de recepción"). Si ya se revisó
   toda la lista, **Autorizar todos los de la lista...** lo hace de una vez.
3. En los escaneos siguientes, todo lo que aparezca en rojo como
   `SIN AUTORIZAR` es un equipo nuevo. La barra de estado dice cuántos hay, y
   ordenando por la columna Estado quedan juntos.

Los autorizados se reconocen por la MAC (o por la IP si no se conoce la MAC) y
se guardan en la base, así que valen para todos los escaneos. Un equipo con MAC
privada puede volver a figurar sin autorizar si cambia su MAC.

- La lista de puertos es editable: `22,80,443,8000-8100`. Si se deja vacía no se
  escanean puertos.
- "Espera (ms)" es el tiempo máximo que se espera cada respuesta (ping y
  puertos). En redes lentas o por VPN conviene subirlo.
- Clic en el encabezado de una columna para ordenar.
- Clic derecho: ver detalle, autorizar, hacer ping, copiar IP, copiar MAC, abrir
  en el navegador.
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
pyinstaller --noconfirm --onefile --windowed --name EscanerRed --icon icono.ico --add-data "icono.ico;." --add-data "fabricantes.txt;." escaner_red.py
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
| `dispositivos` | Un registro por equipo encontrado: `escaneo_id`, `ip`, `nombre`, `mac`, `latencia` (ms, vacío si no respondió al ping), `ttl`, `puertos` (lista JSON de puertos abiertos), `info` (JSON con el resto: fabricante, nombres por protocolo, grupo, sistema, web, servicios, UPnP) |
| `autorizados` | Equipos marcados como autorizados: `clave` (MAC, o `ip:` + IP), `descripcion`, `fecha` |

`escaneos.db` no se sube al repositorio porque contiene datos de la red
(direcciones, nombres y MAC de los equipos).

## Archivos del proyecto

| Archivo | Descripción |
|---|---|
| `escaner_red.py` | La aplicación: interfaz, escaneo, base de datos |
| `identificar.py` | Identificación de equipos: NetBIOS, mDNS, LLMNR, SMB, web, UPnP, fabricantes |
| `icono.ico` | Icono de la ventana y del `.exe` |
| `crear_icono.py` | Genera `icono.ico`; solo hace falta si se quiere cambiar el dibujo |
| `fabricantes.txt` | Base de fabricantes del IEEE (prefijo de MAC y nombre) |
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
- **Identificación**: el módulo `identificar.py` arma a mano los paquetes de
  cada protocolo (NetBIOS, mDNS, LLMNR, SMB2 con NTLM, SSDP). Solo consulta
  información que los equipos publican; no intenta iniciar sesión en ninguno.
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
- El tipo/sistema es una estimación. Cuando el equipo no publica nada, se basa
  solo en el TTL del ping y puede fallar.
- La versión de Windows sale de SMB: Windows 10 22H2 figura como compilación
  19041 y los equipos que solo hablan SMB1 (Windows XP) no la informan.
- El fabricante es el de la placa de red, que no siempre coincide con la marca
  del equipo.
- Los celulares y equipos con firewall estricto casi no publican datos: de ellos
  suele verse solo la IP y una MAC privada.

## Uso responsable

Escanear redes ajenas sin autorización puede ser ilegal o violar políticas de
uso. Usar la aplicación solo en redes propias o con permiso del administrador.
