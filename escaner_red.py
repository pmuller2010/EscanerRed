# -*- coding: utf-8 -*-
"""
Escáner de Red - Agrosistemas
Busca dispositivos en la red (IP, nombre, MAC, puertos abiertos), guarda los
escaneos en SQLite y trae una herramienta de ping.

Solo usa la librería estándar de Python (Windows).
"""
import csv
import ctypes
import ipaddress
import json
import os
import queue
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import identificar as ident

APP_TITULO = "Escáner de Red"
MAX_HOSTS = 65536
PUERTOS_DEFECTO = ("21,22,23,25,53,80,110,135,139,143,443,445,515,554,631,993,995,1433,"
                   "1521,3306,3389,5432,5900,8000,8009,8080,8443,9100,62078")
SERVICIOS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 554: "RTSP", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8000: "HTTP-alt", 8080: "HTTP-proxy", 8443: "HTTPS-alt",
    9100: "Impresora", 515: "Impresora LPD", 631: "Impresora IPP",
    8009: "Chromecast", 62078: "iPhone/iPad",
}
PUERTOS_WEB = (80, 8080, 8000, 443, 8443)
PUERTOS_BANNER = (21, 22, 25)
SIN_AUTORIZAR = "SIN AUTORIZAR"
AUTORIZADO = "Autorizado"
ESTE_EQUIPO = "Este equipo"
ERRORES_ICMP = {
    11002: "Red de destino inaccesible",
    11003: "Host de destino inaccesible",
    11010: "Tiempo de espera agotado",
    11013: "TTL expirado en tránsito",
    11050: "Error general",
}


def carpeta_app():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def ruta_recurso(nombre):
    """Archivo que acompaña a la app: junto al programa o dentro del .exe."""
    for carpeta in (carpeta_app(), getattr(sys, "_MEIPASS", "")):
        if carpeta and os.path.exists(os.path.join(carpeta, nombre)):
            return os.path.join(carpeta, nombre)
    return ""


DB_PATH = os.environ.get("ESCANER_DB") or os.path.join(carpeta_app(), "escaneos.db")

# --------------------------------------------------------------------------
# Bajo nivel: ICMP y ARP con la API de Windows (no depende del idioma)
# --------------------------------------------------------------------------
_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_void_p)]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32), ("DataSize", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint16), ("Data", ctypes.c_void_p),
                ("Options", _IP_OPTION_INFORMATION)]


_iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
_iphlpapi.IcmpCreateFile.argtypes = []
_iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
_iphlpapi.IcmpSendEcho.restype = ctypes.c_uint32
_iphlpapi.IcmpSendEcho.argtypes = [
    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint16,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
_iphlpapi.SendARP.restype = ctypes.c_uint32
_iphlpapi.SendARP.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                              ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
_HANDLE_INVALIDO = ctypes.c_void_p(-1).value


def _ip_a_u32(ip):
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def icmp_ping(ip, timeout_ms=1000, size=32):
    """Envía un eco ICMP. Devuelve (ok, ms, ttl, codigo_error)."""
    h = _iphlpapi.IcmpCreateFile()
    if not h or h == _HANDLE_INVALIDO:
        return False, None, None, ctypes.get_last_error()
    try:
        datos = (b"abcdefghijklmnopqrstuvwabcdefghi" * (size // 32 + 1))[:size]
        tam = ctypes.sizeof(_ICMP_ECHO_REPLY) + size + 16
        buf = ctypes.create_string_buffer(tam)
        n = _iphlpapi.IcmpSendEcho(h, _ip_a_u32(ip), datos, size, None, buf, tam,
                                   int(timeout_ms))
        if n == 0:
            return False, None, None, ctypes.get_last_error()
        rep = _ICMP_ECHO_REPLY.from_buffer(buf)
        if rep.Status != 0:
            return False, None, None, rep.Status
        return True, rep.RoundTripTime, rep.Options.Ttl, 0
    finally:
        _iphlpapi.IcmpCloseHandle(h)


def obtener_mac(ip):
    """Resuelve la MAC por ARP (solo funciona dentro de la misma red local)."""
    buf = ctypes.create_string_buffer(8)
    largo = ctypes.c_uint32(8)
    try:
        if _iphlpapi.SendARP(_ip_a_u32(ip), 0, buf, ctypes.byref(largo)) != 0:
            return ""
    except OSError:
        return ""
    if largo.value < 6:
        return ""
    mac = buf.raw[:6]
    if mac == b"\x00" * 6:
        return ""
    return "-".join(f"{b:02X}" for b in mac)


def resolver_nombre(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def puerto_abierto(ip, puerto, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, puerto)) == 0
    except OSError:
        return False


def ip_local_principal():
    """IP de la interfaz que sale a internet (no envía ningún paquete)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return ""


def detectar_redes():
    """Lista de (red, ip_propia, nombre_interfaz); la principal va primero."""
    redes = []
    try:
        cmd = ("Get-NetIPAddress -AddressFamily IPv4 | "
               "Select-Object IPAddress,PrefixLength,InterfaceAlias | ConvertTo-Json -Compress")
        salida = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW).stdout
        datos = json.loads(salida)
        if isinstance(datos, dict):
            datos = [datos]
        for d in datos:
            ip = d.get("IPAddress", "")
            if not ip or ip.startswith(("127.", "169.254.")):
                continue
            iface = ipaddress.ip_interface(f"{ip}/{d.get('PrefixLength', 24)}")
            redes.append((iface.network, ip, d.get("InterfaceAlias") or ""))
    except Exception:
        pass
    principal = ip_local_principal()
    if not redes and principal:
        redes.append((ipaddress.ip_network(principal + "/24", strict=False), principal, ""))
    redes.sort(key=lambda r: r[1] != principal)
    return redes


# --------------------------------------------------------------------------
# Interpretación de lo que escribe el usuario
# --------------------------------------------------------------------------
class ErrorEntrada(ValueError):
    pass


def interpretar_objetivo(texto):
    """Acepta CIDR (192.168.1.0/24), rango (192.168.1.1-50 o ip-ip), IP o nombre."""
    t = texto.strip().split(" ")[0].strip()
    if not t:
        raise ValueError("Indicá una red, un rango o una IP.")
    try:
        if "/" in t:
            red = ipaddress.ip_network(t, strict=False)
            if red.version != 4:
                raise ErrorEntrada("Solo se admite IPv4.")
            if red.num_addresses > MAX_HOSTS:
                raise ErrorEntrada(f"El rango es demasiado grande (máximo {MAX_HOSTS} direcciones).")
            return [str(h) for h in red.hosts()]
        if "-" in t:
            a, b = t.split("-", 1)
            ini = ipaddress.IPv4Address(a.strip())
            b = b.strip()
            if "." not in b:
                b = ".".join(str(ini).split(".")[:3] + [b])
            fin = ipaddress.IPv4Address(b)
            if fin < ini:
                ini, fin = fin, ini
            cant = int(fin) - int(ini) + 1
            if cant > MAX_HOSTS:
                raise ErrorEntrada(f"El rango es demasiado grande (máximo {MAX_HOSTS} direcciones).")
            return [str(ipaddress.IPv4Address(n)) for n in range(int(ini), int(fin) + 1)]
        try:
            return [str(ipaddress.IPv4Address(t))]
        except ValueError:
            return [socket.gethostbyname(t)]
    except ErrorEntrada:
        raise
    except ValueError:
        raise ValueError(f"No entiendo '{t}'. Ejemplos: 192.168.1.0/24, 192.168.1.1-50, 192.168.1.10")
    except OSError:
        raise ValueError(f"No se pudo resolver el nombre '{t}'.")


def interpretar_puertos(texto):
    puertos = set()
    for parte in texto.replace(";", ",").replace(" ", ",").split(","):
        parte = parte.strip()
        if not parte:
            continue
        try:
            if "-" in parte:
                a, b = (int(x) for x in parte.split("-", 1))
                if a > b:
                    a, b = b, a
            else:
                a = b = int(parte)
        except ValueError:
            raise ValueError(f"Puerto inválido: '{parte}'. Ejemplo: 22,80,443,8000-8100")
        if a < 1 or b > 65535:
            raise ValueError("Los puertos van de 1 a 65535.")
        puertos.update(range(a, b + 1))
    return sorted(puertos)


def sistema_estimado(ttl):
    if not ttl:
        return ""
    if ttl <= 64:
        return "Linux/Unix/Android"
    if ttl <= 128:
        return "Windows"
    return "Equipo de red"


def texto_puertos(puertos):
    return ", ".join(f"{p} ({SERVICIOS[p]})" if p in SERVICIOS else str(p) for p in puertos)


def elegir_nombre(nombres):
    """El mejor nombre entre los que contestó el equipo por cada protocolo."""
    for origen in ("dns", "smb", "netbios", "mdns", "llmnr", "upnp"):   # netbios corta a 15 letras
        if nombres.get(origen):
            return nombres[origen]
    return ""


def clave_disp(d):
    """Identificador estable del dispositivo: la MAC, o la IP si no se conoce."""
    return d["mac"] or "ip:" + d["ip"]


def tipo_dispositivo(d):
    """Qué es el equipo, deducido de todo lo que se pudo averiguar (orientativo)."""
    info = d.get("info") or {}
    puertos = d["puertos"]
    fab = info.get("fabricante", "")
    upnp = info.get("upnp") or {}
    nombres = " ".join((info.get("nombres") or {}).values()).lower()
    if info.get("sistema"):
        return info["sistema"]
    if upnp.get("modelo"):
        return " ".join(x for x in (upnp.get("fabricante", ""), upnp["modelo"]) if x)
    if any(p in puertos for p in (9100, 515, 631)):
        return "Impresora"
    if 554 in puertos:
        return "Cámara IP / DVR"
    if 62078 in puertos or "iphone" in nombres or "ipad" in nombres:
        return "iPhone / iPad"
    if "android" in nombres:
        return "Android"
    titulo = next((w["titulo"] for w in (info.get("web") or {}).values() if w.get("titulo")), "")
    if titulo and (23 in puertos or 53 in puertos) and 445 not in puertos:
        return f"Router / equipo de red ({titulo})"
    if 8009 in puertos:
        return "Chromecast / Smart TV"
    if fab.startswith("Apple"):
        return "Apple"
    if any(x in fab for x in ("Espressif", "Tuya", "Shelly", "Sonoff")):
        return "Dispositivo IoT / domótica"
    if ident.mac_privada(d["mac"]) and not puertos:
        return "Celular / tablet (MAC privada)"
    return sistema_estimado(d["ttl"])


def texto_detalle(d, estado, descripcion):
    info = d.get("info") or {}
    lineas = []

    def linea(titulo, valor):
        if valor not in (None, "", [], {}):
            lineas.append(f"{titulo + ':':<24}{valor}")

    linea("Estado", estado + (f"  -  {descripcion}" if descripcion else ""))
    linea("IP", d["ip"])
    linea("Nombre", d["nombre"])
    for origen, nombre in (info.get("nombres") or {}).items():
        linea(f"   según {origen}", nombre)
    linea("Grupo / dominio", info.get("grupo"))
    linea("MAC", d["mac"])
    linea("Fabricante", info.get("fabricante"))
    if ident.mac_privada(d["mac"]):
        lineas.append("   La MAC es privada/aleatoria: la inventa el propio equipo, como hacen")
        lineas.append("   los celulares, tablets y notebooks con 'dirección Wi-Fi privada'.")
        lineas.append("   No permite saber el fabricante y puede cambiar.")
    linea("Tipo / sistema", tipo_dispositivo(d))
    if d["latencia"] is None:
        linea("Ping", "no responde")
    else:
        linea("Ping", f"{d['latencia']} ms, TTL {d['ttl']} ({sistema_estimado(d['ttl'])})")
    linea("Puertos abiertos", texto_puertos(d["puertos"]) or "ninguno de los probados")
    for puerto, web in (info.get("web") or {}).items():
        linea(f"Web (puerto {puerto})", "  |  ".join(
            f"{k}: {v}" for k, v in (("título", web.get("titulo")), ("servidor", web.get("servidor")),
                                     ("pide clave para", web.get("auth"))) if v))
    for puerto, texto in (info.get("banners") or {}).items():
        linea(f"Servicio puerto {puerto}", texto)
    upnp = info.get("upnp") or {}
    for titulo, campo in (("UPnP nombre", "nombre"), ("UPnP fabricante", "fabricante"),
                          ("UPnP modelo", "modelo"), ("UPnP nro. modelo", "modelo_nro"),
                          ("UPnP descripción", "descripcion"), ("UPnP software", "servidor")):
        linea(titulo, upnp.get(campo))
    return "\n".join(lineas)


# --------------------------------------------------------------------------
# Base de datos
# --------------------------------------------------------------------------
class BaseDatos:
    def __init__(self, ruta):
        self.ruta = ruta
        with self._con() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS escaneos(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL, objetivo TEXT, puertos TEXT,
                    duracion REAL, nota TEXT);
                CREATE TABLE IF NOT EXISTS dispositivos(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    escaneo_id INTEGER NOT NULL, ip TEXT, nombre TEXT, mac TEXT,
                    latencia INTEGER, ttl INTEGER, puertos TEXT);
                CREATE INDEX IF NOT EXISTS ix_disp_escaneo ON dispositivos(escaneo_id);
                CREATE TABLE IF NOT EXISTS autorizados(
                    clave TEXT PRIMARY KEY, descripcion TEXT, fecha TEXT);
            """)
            columnas = [f[1] for f in c.execute("PRAGMA table_info(dispositivos)")]
            if "info" not in columnas:      # bases creadas con la primera versión
                c.execute("ALTER TABLE dispositivos ADD COLUMN info TEXT")

    def _con(self):
        return sqlite3.connect(self.ruta)

    def guardar(self, meta, hosts, nota):
        con = self._con()
        try:
            with con:
                cur = con.execute(
                    "INSERT INTO escaneos(fecha,objetivo,puertos,duracion,nota) VALUES(?,?,?,?,?)",
                    (meta["fecha"], meta["objetivo"], meta["puertos"], meta["duracion"], nota))
                eid = cur.lastrowid
                con.executemany(
                    "INSERT INTO dispositivos(escaneo_id,ip,nombre,mac,latencia,ttl,puertos,info) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    [(eid, h["ip"], h["nombre"], h["mac"], h["latencia"], h["ttl"],
                      json.dumps(h["puertos"]),
                      json.dumps(h.get("info") or {}, ensure_ascii=False)) for h in hosts])
            return eid
        finally:
            con.close()

    def listar(self):
        con = self._con()
        try:
            return con.execute(
                "SELECT e.id, e.fecha, e.objetivo, e.duracion, e.nota, e.puertos, "
                "(SELECT COUNT(*) FROM dispositivos d WHERE d.escaneo_id=e.id) "
                "FROM escaneos e ORDER BY e.id DESC").fetchall()
        finally:
            con.close()

    def hosts(self, eid):
        con = self._con()
        try:
            filas = con.execute(
                "SELECT ip,nombre,mac,latencia,ttl,puertos,info FROM dispositivos "
                "WHERE escaneo_id=?",
                (eid,)).fetchall()
        finally:
            con.close()
        return [{"ip": f[0], "nombre": f[1] or "", "mac": f[2] or "", "latencia": f[3],
                 "ttl": f[4], "puertos": json.loads(f[5] or "[]"),
                 "info": json.loads(f[6] or "{}"), "listo": True} for f in filas]

    def autorizados(self):
        con = self._con()
        try:
            return dict(con.execute("SELECT clave, descripcion FROM autorizados").fetchall())
        finally:
            con.close()

    def autorizar(self, claves, descripcion):
        con = self._con()
        try:
            with con:
                con.executemany(
                    "INSERT OR REPLACE INTO autorizados(clave,descripcion,fecha) VALUES(?,?,?)",
                    [(c, descripcion, datetime.now().strftime("%Y-%m-%d %H:%M:%S")) for c in claves])
        finally:
            con.close()

    def desautorizar(self, clave):
        con = self._con()
        try:
            with con:
                con.execute("DELETE FROM autorizados WHERE clave=?", (clave,))
        finally:
            con.close()

    def eliminar(self, eid):
        con = self._con()
        try:
            with con:
                con.execute("DELETE FROM dispositivos WHERE escaneo_id=?", (eid,))
                con.execute("DELETE FROM escaneos WHERE id=?", (eid,))
        finally:
            con.close()


# --------------------------------------------------------------------------
# Interfaz
# --------------------------------------------------------------------------
def clave_ip(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0


class App(tk.Tk):
    COLUMNAS = (("estado", "Estado", 105), ("nombre", "Nombre", 160),
                ("ip", "IP", 105), ("descripcion", "Descripción", 180), ("mac", "MAC", 130),
                ("fabricante", "Fabricante", 180), ("sistema", "Tipo / sistema (estimado)", 220),
                ("latencia", "Latencia", 90), ("puertos", "Puertos abiertos", 260))

    def __init__(self):
        super().__init__()
        self.title(APP_TITULO)
        self.geometry("1500x720")
        try:
            self.iconbitmap(default=ruta_recurso("icono.ico"))      # ventana y barra de tareas
        except tk.TclError:
            pass
        self.minsize(900, 500)
        self.db = BaseDatos(DB_PATH)
        self.q = queue.Queue()
        self.cancelar = threading.Event()
        self.ping_cancelar = threading.Event()
        self.escaneando = False
        self.pingueando = False
        self.resultados = {}
        self.meta = None          # datos del escaneo que se ve en pantalla
        self.guardado = True
        self.redes_locales = []
        self.ips_propias = []
        self.autorizados = self.db.autorizados()
        self.orden = ("ip", False)
        ident.cargar_fabricantes(carpeta_app())

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self.nb = nb
        self.tab_scan = ttk.Frame(nb)
        self.tab_ping = ttk.Frame(nb)
        self.tab_hist = ttk.Frame(nb)
        nb.add(self.tab_scan, text="  Escaneo  ")
        nb.add(self.tab_ping, text="  Ping  ")
        nb.add(self.tab_hist, text="  Historial  ")
        self._armar_escaneo()
        self._armar_ping()
        self._armar_historial()
        self.cargar_historial()

        self.protocol("WM_DELETE_WINDOW", self._cerrar)
        threading.Thread(target=lambda: self.q.put(("redes", detectar_redes())),
                         daemon=True).start()
        self.after(80, self._procesar_cola)

    # ---------------- pestaña Escaneo ----------------
    def _armar_escaneo(self):
        f = self.tab_scan
        sup = ttk.Frame(f)
        sup.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Label(sup, text="Red / rango:").grid(row=0, column=0, sticky="w")
        self.cb_red = ttk.Combobox(sup, width=42)
        self.cb_red.set("Detectando redes...")
        self.cb_red.grid(row=0, column=1, sticky="we", padx=(4, 12))
        ttk.Label(sup, text="Espera (ms):").grid(row=0, column=2, sticky="w")
        self.e_timeout = ttk.Spinbox(sup, from_=100, to=5000, increment=100, width=6)
        self.e_timeout.set(700)
        self.e_timeout.grid(row=0, column=3, padx=(4, 12))
        self.b_escanear = ttk.Button(sup, text="Escanear", command=self.iniciar_escaneo)
        self.b_escanear.grid(row=0, column=4, padx=2)
        self.b_detener = ttk.Button(sup, text="Detener", command=self.detener_escaneo,
                                    state="disabled")
        self.b_detener.grid(row=0, column=5, padx=2)
        ttk.Label(sup, text="Puertos:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.e_puertos = ttk.Entry(sup)
        self.e_puertos.insert(0, PUERTOS_DEFECTO)
        self.e_puertos.grid(row=1, column=1, columnspan=3, sticky="we", padx=(4, 12), pady=(6, 0))
        self.b_guardar = ttk.Button(sup, text="Guardar", command=self.guardar_escaneo)
        self.b_guardar.grid(row=1, column=4, padx=2, pady=(6, 0))
        self.b_exportar = ttk.Button(sup, text="Exportar...", command=self.exportar)
        self.b_exportar.grid(row=1, column=5, padx=2, pady=(6, 0))
        sup.columnconfigure(1, weight=1)
        ttk.Label(f, foreground="#666",
                  text="Formatos: 192.168.1.0/24  ·  192.168.1.1-50  ·  192.168.1.10   |   "
                       "Puertos: 22,80,443,8000-8100 (vacío = no escanear puertos)   |   "
                       "Doble clic en un equipo = detalle, clic derecho = autorizar, ping y más"
                  ).pack(fill="x", padx=10)

        marco = ttk.Frame(f)
        marco.pack(fill="both", expand=True, padx=8, pady=6)
        self.tabla = ttk.Treeview(marco, columns=[c[0] for c in self.COLUMNAS],
                                  show="headings", selectmode="browse")
        for cid, titulo, ancho in self.COLUMNAS:
            self.tabla.heading(cid, text=titulo, command=lambda c=cid: self.ordenar(c))
            self.tabla.column(cid, width=ancho, anchor="w", stretch=(cid == "puertos"))
        sy = ttk.Scrollbar(marco, orient="vertical", command=self.tabla.yview)
        self.tabla.configure(yscrollcommand=sy.set)
        self.tabla.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        self.tabla.tag_configure("sin", background="#ffd9d9")
        self.tabla.bind("<Double-1>", lambda e: self.ver_detalle())
        self.tabla.bind("<Button-3>", self._menu_contextual)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Ver detalle", command=self.ver_detalle)
        self.menu.add_command(label="Autorizar / editar descripción...", command=self.autorizar)
        self.menu.add_command(label="Quitar autorización", command=self.desautorizar)
        self.menu.add_command(label="Autorizar todos los de la lista...",
                              command=self.autorizar_todos)
        self.menu.add_separator()
        self.menu.add_command(label="Hacer ping", command=self.ping_seleccionado)
        self.menu.add_command(label="Copiar IP", command=lambda: self._copiar("ip"))
        self.menu.add_command(label="Copiar MAC", command=lambda: self._copiar("mac"))
        self.menu.add_command(label="Abrir en el navegador", command=self.abrir_navegador)

        inf = ttk.Frame(f)
        inf.pack(fill="x", padx=8, pady=(0, 8))
        self.barra = ttk.Progressbar(inf, length=260)
        self.barra.pack(side="right")
        self.b_oui = ttk.Button(inf, text="Actualizar fabricantes", command=self.actualizar_oui)
        self.b_oui.pack(side="right", padx=8)
        self.estado = ttk.Label(inf, text="Listo.")
        self.estado.pack(side="left")

    def _valores_fila(self, d):
        if d["latencia"] is None:
            lat = "sin resp. a ping"
        elif d["latencia"] == 0:
            lat = "<1 ms"
        else:
            lat = f"{d['latencia']} ms"
        if d.get("listo"):
            puertos = texto_puertos(d["puertos"])
        else:
            puertos = "analizando..."
        return (self._estado(d), d["nombre"], d["ip"], self.autorizados.get(clave_disp(d), ""),
                d["mac"],
                (d.get("info") or {}).get("fabricante", ""), tipo_dispositivo(d), lat, puertos)

    def _estado(self, d):
        if d["ip"] in self.ips_propias:
            return ESTE_EQUIPO
        return AUTORIZADO if clave_disp(d) in self.autorizados else SIN_AUTORIZAR

    def _refrescar_fila(self, d):
        self.tabla.item(d["ip"], values=self._valores_fila(d),
                        tags=("sin",) if self._estado(d) == SIN_AUTORIZAR else ())

    def _poner_fila(self, d):
        ip = d["ip"]
        self.resultados[ip] = d
        if self.tabla.exists(ip):
            self._refrescar_fila(d)
        else:
            # inserta ordenado por IP mientras llega
            pos = "end"
            if self.orden == ("ip", False):
                k = clave_ip(ip)
                for i, iid in enumerate(self.tabla.get_children()):
                    if clave_ip(iid) > k:
                        pos = i
                        break
            self.tabla.insert("", pos, iid=ip)
            self._refrescar_fila(d)

    def ordenar(self, col):
        inverso = self.orden[0] == col and not self.orden[1]
        self.orden = (col, inverso)

        def clave(ip):
            d = self.resultados[ip]
            if col == "ip":
                return clave_ip(ip)
            if col == "latencia":
                return d["latencia"] if d["latencia"] is not None else 10 ** 9
            if col == "puertos":
                return len(d["puertos"])
            return str(self.tabla.set(ip, col)).lower()

        for i, ip in enumerate(sorted(self.tabla.get_children(), key=clave, reverse=inverso)):
            self.tabla.move(ip, "", i)

    def _limpiar_tabla(self):
        self.tabla.delete(*self.tabla.get_children())
        self.resultados = {}
        self.orden = ("ip", False)

    def iniciar_escaneo(self):
        if self.escaneando:
            return
        if not self.guardado and self.resultados:
            if not messagebox.askyesno(APP_TITULO, "El escaneo actual no está guardado.\n"
                                                   "¿Continuar y descartarlo?"):
                return
        try:
            ips = interpretar_objetivo(self.cb_red.get())
            puertos = interpretar_puertos(self.e_puertos.get())
            espera = int(float(self.e_timeout.get()))
            if not 50 <= espera <= 10000:
                raise ValueError("La espera debe estar entre 50 y 10000 ms.")
        except ValueError as e:
            messagebox.showerror(APP_TITULO, str(e))
            return
        if len(ips) * max(len(puertos), 1) > 2_000_000:
            if not messagebox.askyesno(APP_TITULO, "Es un escaneo muy grande y puede tardar "
                                                   "mucho.\n¿Continuar?"):
                return
        self._limpiar_tabla()
        self.meta = {"fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "objetivo": self.cb_red.get().strip().split(" ")[0],
                     "puertos": self.e_puertos.get().strip(), "duracion": 0.0}
        self.guardado = True
        self.escaneando = True
        self.cancelar.clear()
        self.b_escanear.config(state="disabled")
        self.b_detener.config(state="normal")
        self.barra.config(maximum=len(ips), value=0)
        self.estado.config(text=f"Escaneando {len(ips)} direcciones...",
                           foreground="", font=("Segoe UI", 9))
        threading.Thread(target=self._hilo_escaneo,
                         args=(ips, puertos, espera, list(self.redes_locales)),
                         daemon=True).start()

    def detener_escaneo(self):
        self.cancelar.set()
        self.estado.config(text="Deteniendo...")

    def _hilo_escaneo(self, ips, puertos, espera, redes):
        t0 = time.time()
        hechos = 0
        with ThreadPoolExecutor(max_workers=min(128, len(ips))) as pool, \
                ThreadPoolExecutor(max_workers=200) as pool_puertos:
            # búsqueda UPnP en paralelo; cada equipo espera su resultado al final
            ssdp = pool_puertos.submit(ident.ssdp_descubrir, list(self.ips_propias))
            futuros = [pool.submit(self._escanear_host, ip, puertos, espera, redes, pool_puertos,
                                   ssdp) for ip in ips]
            for _ in as_completed(futuros):
                hechos += 1
                if hechos % 4 == 0 or hechos == len(ips):
                    self.q.put(("progreso", hechos, len(ips)))
        self.q.put(("fin", time.time() - t0, self.cancelar.is_set()))

    def _escanear_host(self, ip, puertos, espera, redes, pool_puertos, ssdp):
        if self.cancelar.is_set():
            return
        ok, ms, ttl, _ = icmp_ping(ip, espera)
        mac = ""
        dir_ip = ipaddress.IPv4Address(ip)
        if not redes or any(dir_ip in r for r in redes):
            mac = obtener_mac(ip)      # también detecta equipos que bloquean el ping
        if not ok and not mac:
            return
        nombres = {}
        info = {"fabricante": ident.fabricante(mac), "nombres": nombres}
        d = {"ip": ip, "nombre": "", "mac": mac, "latencia": ms if ok else None,
             "ttl": ttl if ok else None, "puertos": [], "info": info, "listo": False}

        def avisar():
            d["nombre"] = elegir_nombre(nombres)
            self.q.put(("host", json.loads(json.dumps(d))))      # copia independiente

        def seguir():
            return not self.cancelar.is_set()

        avisar()
        seg = max(espera / 1000.0, 1.0)

        # 1) Nombres: se le pregunta al propio equipo por varios protocolos
        if seguir():
            nb = ident.netbios(ip, seg)
            if nb.get("nombre"):
                nombres["netbios"] = nb["nombre"]
            if nb.get("grupo"):
                info["grupo"] = nb["grupo"]
            if nb.get("mac") and not d["mac"]:
                d["mac"] = nb["mac"]
                info["fabricante"] = ident.fabricante(nb["mac"])
        if seguir():
            n = ident.nombre_mdns(ip, seg)
            if n:
                nombres["mdns"] = n
        if seguir() and not nombres:
            n = resolver_nombre(ip)
            if n:
                nombres["dns"] = n
        if seguir() and not nombres:
            n = ident.nombre_llmnr(ip, seg)
            if n:
                nombres["llmnr"] = n
        avisar()

        # 2) Puertos abiertos
        abiertos = []
        if puertos:
            def probar(p):
                return p if (seguir() and puerto_abierto(ip, p, espera / 1000.0)) else None

            for r in pool_puertos.map(probar, puertos):
                if r:
                    abiertos.append(r)
        d["puertos"] = abiertos
        if not d["mac"] and seguir() and (not redes or any(dir_ip in r for r in redes)):
            d["mac"] = obtener_mac(ip)          # segundo intento: a veces el ARP tarda
            info["fabricante"] = ident.fabricante(d["mac"])

        # 3) Qué dicen los servicios que tiene abiertos
        if 445 in abiertos and seguir():
            smb = ident.smb_info(ip)
            propio = smb.get("nombre_dns") or smb.get("nombre") or ""
            if smb.get("sistema"):
                info["sistema"] = smb["sistema"]
            if propio:
                nombres["smb"] = propio
            dominio = smb.get("dominio_dns") or smb.get("dominio") or ""
            if dominio and dominio.lower() != propio.lower():
                info["grupo"] = dominio
        for p in [p for p in PUERTOS_WEB if p in abiertos][:2]:
            if seguir():
                web = ident.http_info(ip, p)
                if web:
                    info.setdefault("web", {})[str(p)] = web
        for p in PUERTOS_BANNER:
            if p in abiertos and seguir():
                texto = ident.banner(ip, p)
                if texto:
                    info.setdefault("banners", {})[str(p)] = texto
        if seguir():
            try:
                encontrados = ssdp.result(timeout=10)
            except Exception:
                encontrados = {}
            if ip in encontrados:
                upnp = ident.upnp_info(ip, encontrados[ip])
                if upnp:
                    info["upnp"] = upnp
                    if upnp.get("nombre"):
                        nombres["upnp"] = upnp["nombre"]
        d["listo"] = True
        avisar()

    def _fin_escaneo(self, duracion, cancelado):
        self.escaneando = False
        self.b_escanear.config(state="normal")
        self.b_detener.config(state="disabled")
        for d in self.resultados.values():      # por si se detuvo a mitad de camino
            if not d.get("listo"):
                d["listo"] = True
                self._refrescar_fila(d)
        if self.meta:
            self.meta["duracion"] = round(duracion, 1)
        self.guardado = not self.resultados
        self.barra.config(value=0)      # barra vacía = no hay escaneo en curso
        self.estado.config(foreground="#b35c00" if cancelado else "#0a7d28",
                           font=("Segoe UI", 9, "bold"))
        self.bell()
        self.estado.config(text=f"{'■ Escaneo detenido' if cancelado else '✔ Escaneo terminado'}: "
                                f"{len(self.resultados)} dispositivos en {duracion:.1f} s, "
                                f"{self._cant_sin_autorizar()} sin autorizar. "
                                f"{'' if self.guardado else 'Sin guardar.'}")

    def _cant_sin_autorizar(self):
        return sum(1 for d in self.resultados.values() if self._estado(d) == SIN_AUTORIZAR)

    def guardar_escaneo(self):
        if self.escaneando:
            messagebox.showinfo(APP_TITULO, "Esperá a que termine el escaneo.")
            return
        if not self.resultados or not self.meta:
            messagebox.showinfo(APP_TITULO, "No hay resultados para guardar.")
            return
        if self.guardado:
            messagebox.showinfo(APP_TITULO, "Este escaneo ya está guardado en el historial.")
            return
        nota = simpledialog.askstring(APP_TITULO, "Nota para identificar el escaneo (opcional):",
                                      parent=self)
        if nota is None:
            return
        hosts = sorted(self.resultados.values(), key=lambda h: clave_ip(h["ip"]))
        try:
            self.db.guardar(self.meta, hosts, nota.strip())
        except sqlite3.Error as e:
            messagebox.showerror(APP_TITULO, f"No se pudo guardar:\n{e}")
            return
        self.guardado = True
        self.cargar_historial()
        self.estado.config(text=f"Escaneo guardado ({len(hosts)} dispositivos).")

    def exportar(self):
        if not self.resultados:
            messagebox.showinfo(APP_TITULO, "No hay resultados para exportar.")
            return
        fecha = (self.meta or {}).get("fecha", "")[:16].replace(":", "").replace(" ", "_")
        ruta = filedialog.asksaveasfilename(
            parent=self, title="Exportar escaneo", defaultextension=".csv",
            initialfile=f"escaneo_{fecha}",
            filetypes=[("CSV (Excel)", "*.csv"), ("JSON", "*.json")])
        if not ruta:
            return
        hosts = [self.resultados[ip] for ip in self.tabla.get_children()]
        try:
            if ruta.lower().endswith(".json"):
                datos = {"escaneo": self.meta, "dispositivos": [
                    {"estado": self._estado(h),
                     "descripcion": self.autorizados.get(clave_disp(h), ""),
                     "ip": h["ip"], "nombre": h["nombre"], "mac": h["mac"],
                     "latencia_ms": h["latencia"], "ttl": h["ttl"],
                     "tipo_estimado": tipo_dispositivo(h),
                     "puertos_abiertos": h["puertos"], **(h.get("info") or {})}
                    for h in hosts]}
                with open(ruta, "w", encoding="utf-8") as fh:
                    json.dump(datos, fh, ensure_ascii=False, indent=2)
            else:
                with open(ruta, "w", encoding="utf-8-sig", newline="") as fh:
                    w = csv.writer(fh, delimiter=";")
                    w.writerow(["Estado", "Descripción", "IP", "Nombre", "MAC", "Fabricante",
                                "Tipo / sistema (estimado)", "Grupo / dominio", "Latencia (ms)",
                                "TTL", "Puertos abiertos", "Web", "Servicios", "UPnP"])
                    for h in hosts:
                        i = h.get("info") or {}
                        web = " / ".join(f"{p}: {w_.get('titulo', '')} [{w_.get('servidor', '')}]"
                                         for p, w_ in (i.get("web") or {}).items())
                        serv = " / ".join(f"{p}: {t}" for p, t in (i.get("banners") or {}).items())
                        upnp = " ".join(str(v) for v in (i.get("upnp") or {}).values())
                        w.writerow([self._estado(h), self.autorizados.get(clave_disp(h), ""),
                                    h["ip"], h["nombre"], h["mac"], i.get("fabricante", ""),
                                    tipo_dispositivo(h), i.get("grupo", ""),
                                    "" if h["latencia"] is None else h["latencia"],
                                    h["ttl"] or "", texto_puertos(h["puertos"]), web, serv, upnp])
        except OSError as e:
            messagebox.showerror(APP_TITULO, f"No se pudo escribir el archivo:\n{e}")
            return
        self.estado.config(text=f"Exportado a {ruta}")

    def _seleccion(self):
        sel = self.tabla.selection()
        return self.resultados.get(sel[0]) if sel else None

    def _menu_contextual(self, ev):
        fila = self.tabla.identify_row(ev.y)
        if fila:
            self.tabla.selection_set(fila)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    def _copiar(self, campo):
        d = self._seleccion()
        if d:
            self.clipboard_clear()
            self.clipboard_append(d[campo])

    def ver_detalle(self):
        d = self._seleccion()
        if not d:
            return
        v = tk.Toplevel(self)
        v.title(f"Detalle de {d['ip']}  {d['nombre']}")
        v.geometry("860x480")
        t = tk.Text(v, font=("Consolas", 10), wrap="word", padx=10, pady=10)
        t.pack(fill="both", expand=True)
        t.insert("1.0", texto_detalle(d, self._estado(d), self.autorizados.get(clave_disp(d), "")))
        t.config(state="disabled")

    def _refrescar_estados(self):
        self.autorizados = self.db.autorizados()
        for d in self.resultados.values():
            self._refrescar_fila(d)

    def autorizar(self):
        d = self._seleccion()
        if not d:
            return
        desc = simpledialog.askstring(
            APP_TITULO, f"Descripción del equipo {d['ip']} (ej.: Notebook de Juan, Impresora "
                        "de recepción):", parent=self,
            initialvalue=self.autorizados.get(clave_disp(d), "") or d["nombre"])
        if desc is None:
            return
        self.db.autorizar([clave_disp(d)], desc.strip())
        self._refrescar_estados()

    def desautorizar(self):
        d = self._seleccion()
        if d:
            self.db.desautorizar(clave_disp(d))
            self._refrescar_estados()

    def autorizar_todos(self):
        pendientes = [d for d in self.resultados.values() if self._estado(d) == SIN_AUTORIZAR]
        if not pendientes:
            messagebox.showinfo(APP_TITULO, "No hay equipos sin autorizar en la lista.")
            return
        if not messagebox.askyesno(
                APP_TITULO, f"Se van a marcar como autorizados los {len(pendientes)} equipos que "
                            "figuran SIN AUTORIZAR.\n\nHacelo solo si ya revisaste que todos "
                            "pertenecen a la empresa.\n\n¿Continuar?"):
            return
        self.db.autorizar([clave_disp(d) for d in pendientes], "")
        self._refrescar_estados()

    def actualizar_oui(self):
        self.b_oui.config(state="disabled")
        self.estado.config(text="Descargando la base de fabricantes del IEEE...",
                           foreground="", font=("Segoe UI", 9))

        def tarea():
            try:
                self.q.put(("oui", ident.descargar_fabricantes(carpeta_app()), ""))
            except Exception as e:
                self.q.put(("oui", 0, str(e)))

        threading.Thread(target=tarea, daemon=True).start()

    def abrir_navegador(self):
        d = self._seleccion()
        if d:
            https = 443 in d["puertos"] and 80 not in d["puertos"]
            webbrowser.open(f"{'https' if https else 'http'}://{d['ip']}")

    def ping_seleccionado(self):
        d = self._seleccion()
        if d:
            self.e_host.delete(0, "end")
            self.e_host.insert(0, d["ip"])
            self.nb.select(self.tab_ping)
            self.iniciar_ping()

    # ---------------- pestaña Ping ----------------
    def _armar_ping(self):
        f = self.tab_ping
        sup = ttk.Frame(f)
        sup.pack(fill="x", padx=8, pady=8)
        ttk.Label(sup, text="IP o nombre:").pack(side="left")
        self.e_host = ttk.Entry(sup, width=28)
        self.e_host.pack(side="left", padx=(4, 12))
        self.e_host.bind("<Return>", lambda e: self.iniciar_ping())
        ttk.Label(sup, text="Cantidad (0 = continuo):").pack(side="left")
        self.e_cant = ttk.Spinbox(sup, from_=0, to=100000, width=6)
        self.e_cant.set(4)
        self.e_cant.pack(side="left", padx=(4, 12))
        ttk.Label(sup, text="Intervalo (ms):").pack(side="left")
        self.e_interv = ttk.Spinbox(sup, from_=100, to=60000, increment=100, width=6)
        self.e_interv.set(1000)
        self.e_interv.pack(side="left", padx=(4, 12))
        ttk.Label(sup, text="Espera (ms):").pack(side="left")
        self.e_ptimeout = ttk.Spinbox(sup, from_=100, to=10000, increment=100, width=6)
        self.e_ptimeout.set(1000)
        self.e_ptimeout.pack(side="left", padx=(4, 12))
        ttk.Label(sup, text="Bytes:").pack(side="left")
        self.e_bytes = ttk.Spinbox(sup, from_=1, to=1400, width=6)
        self.e_bytes.set(32)
        self.e_bytes.pack(side="left", padx=(4, 12))
        self.b_ping = ttk.Button(sup, text="Iniciar", command=self.iniciar_ping)
        self.b_ping.pack(side="left", padx=2)
        self.b_ping_stop = ttk.Button(sup, text="Detener", state="disabled",
                                      command=self.ping_cancelar.set)
        self.b_ping_stop.pack(side="left", padx=2)
        ttk.Button(sup, text="Limpiar", command=self._limpiar_ping).pack(side="left", padx=2)

        marco = ttk.Frame(f)
        marco.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.txt_ping = tk.Text(marco, font=("Consolas", 10), state="disabled", wrap="none",
                                background="#101418", foreground="#d8dee9")
        self.txt_ping.tag_configure("error", foreground="#ff6b6b")
        self.txt_ping.tag_configure("titulo", foreground="#8fbcbb")
        sy = ttk.Scrollbar(marco, orient="vertical", command=self.txt_ping.yview)
        self.txt_ping.configure(yscrollcommand=sy.set)
        self.txt_ping.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        self.estado_ping = ttk.Label(f, text="")
        self.estado_ping.pack(fill="x", padx=8, pady=(0, 8))

    def _limpiar_ping(self):
        self.txt_ping.config(state="normal")
        self.txt_ping.delete("1.0", "end")
        self.txt_ping.config(state="disabled")

    def _linea_ping(self, texto, tag=""):
        self.txt_ping.config(state="normal")
        self.txt_ping.insert("end", texto + "\n", tag)
        if int(self.txt_ping.index("end-1c").split(".")[0]) > 5000:
            self.txt_ping.delete("1.0", "1000.0")
        self.txt_ping.see("end")
        self.txt_ping.config(state="disabled")

    def iniciar_ping(self):
        if self.pingueando:
            return
        host = self.e_host.get().strip()
        if not host:
            messagebox.showinfo(APP_TITULO, "Indicá una IP o un nombre de equipo.")
            return
        try:
            cant = int(self.e_cant.get())
            interv = int(self.e_interv.get())
            espera = int(self.e_ptimeout.get())
            tam = int(self.e_bytes.get())
            if cant < 0 or interv < 50 or not 50 <= espera <= 60000 or not 1 <= tam <= 1400:
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_TITULO, "Revisá los valores de cantidad, intervalo, "
                                             "espera y bytes.")
            return
        self.pingueando = True
        self.ping_cancelar.clear()
        self.b_ping.config(state="disabled")
        self.b_ping_stop.config(state="normal")
        threading.Thread(target=self._hilo_ping, args=(host, cant, interv, espera, tam),
                         daemon=True).start()

    def _hilo_ping(self, host, cant, interv, espera, tam):
        put = self.q.put
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            put(("ping", f"No se pudo resolver '{host}'.", "error"))
            put(("ping_fin", ""))
            return
        nombre = f"{host} [{ip}]" if host != ip else ip
        put(("ping", f"Haciendo ping a {nombre} con {tam} bytes de datos:", "titulo"))
        env = rec = 0
        tiempos = []
        while not self.ping_cancelar.is_set() and (cant == 0 or env < cant):
            env += 1
            ok, ms, ttl, err = icmp_ping(ip, espera, tam)
            hora = datetime.now().strftime("%H:%M:%S")
            if ok:
                rec += 1
                tiempos.append(ms)
                t = "<1ms" if ms == 0 else f"={ms}ms"
                put(("ping", f"[{hora}] Respuesta desde {ip}: bytes={tam} tiempo{t} TTL={ttl}", ""))
            else:
                put(("ping", f"[{hora}] {ERRORES_ICMP.get(err, f'Sin respuesta (error {err})')}.",
                     "error"))
            perd = env - rec
            resumen = f"Enviados: {env}   Recibidos: {rec}   Perdidos: {perd} ({perd * 100 // env}%)"
            if tiempos:
                resumen += (f"   Mín: {min(tiempos)} ms   Máx: {max(tiempos)} ms   "
                            f"Media: {sum(tiempos) / len(tiempos):.1f} ms")
            put(("ping_estado", resumen))
            if cant and env >= cant:
                break
            if self.ping_cancelar.wait(interv / 1000.0):
                break
        perd = env - rec
        fin = (f"\nEstadísticas de ping para {ip}:\n"
               f"    Paquetes: enviados = {env}, recibidos = {rec}, perdidos = {perd} "
               f"({perd * 100 // env if env else 0}% perdidos)")
        if tiempos:
            fin += (f"\n    Tiempos: mínimo = {min(tiempos)}ms, máximo = {max(tiempos)}ms, "
                    f"media = {sum(tiempos) / len(tiempos):.1f}ms")
        put(("ping", fin + "\n", "titulo"))
        put(("ping_fin", ""))

    # ---------------- pestaña Historial ----------------
    def _armar_historial(self):
        f = self.tab_hist
        sup = ttk.Frame(f)
        sup.pack(fill="x", padx=8, pady=8)
        ttk.Button(sup, text="Abrir", command=self.abrir_guardado).pack(side="left", padx=2)
        ttk.Button(sup, text="Comparar dos", command=self.comparar).pack(side="left", padx=2)
        ttk.Button(sup, text="Eliminar", command=self.eliminar_guardado).pack(side="left", padx=2)
        ttk.Label(sup, foreground="#666",
                  text="   Para comparar, seleccioná dos escaneos con Ctrl+clic.  "
                       f"Base: {DB_PATH}").pack(side="left")
        marco = ttk.Frame(f)
        marco.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        cols = (("fecha", "Fecha", 150), ("objetivo", "Red / rango", 190),
                ("cant", "Dispositivos", 90), ("dur", "Duración", 80), ("nota", "Nota", 500))
        self.t_hist = ttk.Treeview(marco, columns=[c[0] for c in cols], show="headings",
                                   selectmode="extended")
        for cid, titulo, ancho in cols:
            self.t_hist.heading(cid, text=titulo)
            self.t_hist.column(cid, width=ancho, anchor="w", stretch=(cid == "nota"))
        sy = ttk.Scrollbar(marco, orient="vertical", command=self.t_hist.yview)
        self.t_hist.configure(yscrollcommand=sy.set)
        self.t_hist.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        self.t_hist.bind("<Double-1>", lambda e: self.abrir_guardado())
        self.historial = {}

    def cargar_historial(self):
        self.t_hist.delete(*self.t_hist.get_children())
        self.historial = {}
        for eid, fecha, objetivo, dur, nota, puertos, cant in self.db.listar():
            self.historial[str(eid)] = {"fecha": fecha, "objetivo": objetivo or "",
                                        "puertos": puertos or "", "duracion": dur or 0}
            self.t_hist.insert("", "end", iid=str(eid),
                               values=(fecha, objetivo, cant, f"{dur or 0:.1f} s", nota or ""))

    def abrir_guardado(self):
        sel = self.t_hist.selection()
        if len(sel) != 1:
            messagebox.showinfo(APP_TITULO, "Seleccioná un escaneo del historial.")
            return
        if self.escaneando:
            messagebox.showinfo(APP_TITULO, "Hay un escaneo en curso.")
            return
        if not self.guardado and self.resultados:
            if not messagebox.askyesno(APP_TITULO, "El escaneo actual no está guardado.\n"
                                                   "¿Descartarlo y abrir el guardado?"):
                return
        self._limpiar_tabla()
        self.meta = dict(self.historial[sel[0]])
        for h in sorted(self.db.hosts(int(sel[0])), key=lambda h: clave_ip(h["ip"])):
            if not h["info"].get("fabricante"):      # escaneos de la primera versión
                h["info"]["fabricante"] = ident.fabricante(h["mac"])
            self._poner_fila(h)
        self.guardado = True
        self.estado.config(foreground="", font=("Segoe UI", 9))
        self.estado.config(text=f"Escaneo guardado del {self.meta['fecha']} "
                                f"({self.meta['objetivo']}): {len(self.resultados)} dispositivos.")
        self.barra.config(value=0)
        self.nb.select(self.tab_scan)

    def eliminar_guardado(self):
        sel = self.t_hist.selection()
        if not sel:
            messagebox.showinfo(APP_TITULO, "Seleccioná al menos un escaneo.")
            return
        if not messagebox.askyesno(APP_TITULO, f"¿Eliminar {len(sel)} escaneo(s) del historial?"):
            return
        for eid in sel:
            self.db.eliminar(int(eid))
        self.cargar_historial()

    def comparar(self):
        sel = self.t_hist.selection()
        if len(sel) != 2:
            messagebox.showinfo(APP_TITULO, "Seleccioná exactamente dos escaneos (Ctrl+clic).")
            return
        viejo, nuevo = sorted(sel, key=int)
        a = {h["ip"]: h for h in self.db.hosts(int(viejo))}
        b = {h["ip"]: h for h in self.db.hosts(int(nuevo))}

        def desc(h):
            partes = [h["ip"].ljust(16), (h["nombre"] or "-").ljust(26), (h["mac"] or "-").ljust(18),
                      (h.get("info") or {}).get("fabricante", ""), "·", tipo_dispositivo(h)]
            return "  ".join(partes)

        lineas = [f"ANTERIOR: {self.historial[viejo]['fecha']}  ({self.historial[viejo]['objetivo']})"
                  f"  -  {len(a)} dispositivos",
                  f"NUEVO:    {self.historial[nuevo]['fecha']}  ({self.historial[nuevo]['objetivo']})"
                  f"  -  {len(b)} dispositivos", ""]
        nuevos = sorted(set(b) - set(a), key=clave_ip)
        faltan = sorted(set(a) - set(b), key=clave_ip)
        lineas.append(f"== Dispositivos nuevos ({len(nuevos)}) ==")
        lineas += ["  + " + desc(b[ip]) for ip in nuevos] or ["  (ninguno)"]
        lineas.append("")
        lineas.append(f"== Dispositivos que ya no aparecen ({len(faltan)}) ==")
        lineas += ["  - " + desc(a[ip]) for ip in faltan] or ["  (ninguno)"]
        lineas.append("")
        cambios = []
        for ip in sorted(set(a) & set(b), key=clave_ip):
            x, y = a[ip], b[ip]
            dif = []
            if x["mac"] and y["mac"] and x["mac"] != y["mac"]:
                dif.append(f"MAC {x['mac']} -> {y['mac']} (¿otro equipo con la misma IP?)")
            if x["nombre"] and y["nombre"] and x["nombre"].lower() != y["nombre"].lower():
                dif.append(f"nombre {x['nombre']} -> {y['nombre']}")
            abiertos = sorted(set(y["puertos"]) - set(x["puertos"]))
            cerrados = sorted(set(x["puertos"]) - set(y["puertos"]))
            if abiertos:
                dif.append("puertos abiertos nuevos: " + texto_puertos(abiertos))
            if cerrados:
                dif.append("puertos que ya no están abiertos: " + texto_puertos(cerrados))
            if dif:
                cambios.append(f"  * {ip}  {y['nombre']}")
                cambios += [f"        {d}" for d in dif]
        lineas.append(f"== Cambios en dispositivos existentes ==")
        lineas += cambios or ["  (sin cambios)"]

        v = tk.Toplevel(self)
        v.title("Comparación de escaneos")
        v.geometry("900x560")
        t = tk.Text(v, font=("Consolas", 10), wrap="none")
        sy = ttk.Scrollbar(v, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sy.set)
        sy.pack(side="right", fill="y")
        t.pack(fill="both", expand=True)
        t.insert("1.0", "\n".join(lineas))
        t.config(state="disabled")

    # ---------------- cola de mensajes de los hilos ----------------
    def _procesar_cola(self):
        try:
            for _ in range(800):
                m = self.q.get_nowait()
                tipo = m[0]
                if tipo == "host":
                    self._poner_fila(m[1])
                elif tipo == "progreso":
                    self.barra.config(value=m[1])
                    if not self.cancelar.is_set():
                        self.estado.config(text=f"Escaneando... {m[1] * 100 // m[2]}%  "
                                                f"({m[1]}/{m[2]} direcciones), "
                                                f"{len(self.resultados)} dispositivos encontrados")
                elif tipo == "fin":
                    self._fin_escaneo(m[1], m[2])
                elif tipo == "redes":
                    self._redes_detectadas(m[1])
                elif tipo == "oui":
                    self.b_oui.config(state="normal")
                    if m[2]:
                        self.estado.config(text=f"No se pudo actualizar la base de fabricantes: {m[2]}")
                    else:
                        for d in self.resultados.values():
                            if d["mac"]:
                                d.setdefault("info", {})["fabricante"] = ident.fabricante(d["mac"])
                            self._refrescar_fila(d)
                        self.estado.config(text=f"Base de fabricantes actualizada: {m[1]} entradas.")
                elif tipo == "ping":
                    self._linea_ping(m[1], m[2])
                elif tipo == "ping_estado":
                    self.estado_ping.config(text=m[1])
                elif tipo == "ping_fin":
                    self.pingueando = False
                    self.b_ping.config(state="normal")
                    self.b_ping_stop.config(state="disabled")
        except queue.Empty:
            pass
        self.after(80, self._procesar_cola)

    def _redes_detectadas(self, redes):
        self.redes_locales = [r[0] for r in redes]
        self.ips_propias = [r[1] for r in redes]
        opciones = []
        for red, ip, alias in redes:
            if red.prefixlen < 22:      # red enorme: se propone solo el /24 propio
                red = ipaddress.ip_network(ip + "/24", strict=False)
            opciones.append(f"{red}   ({alias + ', ' if alias else ''}mi IP: {ip})")
        self.cb_red.config(values=opciones)
        if self.cb_red.get().startswith("Detectando"):
            self.cb_red.set(opciones[0] if opciones else "192.168.1.0/24")

    def _cerrar(self):
        if not self.guardado and self.resultados:
            if not messagebox.askyesno(APP_TITULO, "El escaneo actual no está guardado.\n"
                                                   "¿Salir de todos modos?"):
                return
        self.cancelar.set()
        self.ping_cancelar.set()
        self.destroy()


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App().mainloop()


if __name__ == "__main__":
    main()
