# -*- coding: utf-8 -*-
"""
Identificación de dispositivos: le pregunta a cada equipo, por varios
protocolos, quién es. Todas las funciones devuelven vacío si el equipo no
contesta; ninguna lanza excepciones.

Solo librería estándar.
"""
import http.client
import os
import re
import socket
import ssl
import struct
import sys
import urllib.request

# --------------------------------------------------------------------------
# Fabricante según la MAC (base OUI del IEEE)
# --------------------------------------------------------------------------
ARCHIVO_OUI = "fabricantes.txt"
URL_OUI = "https://standards-oui.ieee.org/oui/oui.csv"
_oui = None


def _rutas_oui(carpeta):
    rutas = [os.path.join(carpeta, ARCHIVO_OUI)]
    if getattr(sys, "_MEIPASS", None):          # dentro del .exe
        rutas.append(os.path.join(sys._MEIPASS, ARCHIVO_OUI))
    return rutas


def cargar_fabricantes(carpeta):
    """Carga la base (XXXXXX<tab>Fabricante). Devuelve la cantidad de entradas."""
    global _oui
    _oui = {}
    for ruta in _rutas_oui(carpeta):
        try:
            with open(ruta, encoding="utf-8") as fh:
                for linea in fh:
                    pref, _, nombre = linea.rstrip("\n").partition("\t")
                    if len(pref) == 6 and nombre:
                        _oui[pref] = nombre
            if _oui:
                break
        except OSError:
            continue
    return len(_oui)


def descargar_fabricantes(carpeta):
    """Baja la base oficial del IEEE y la guarda compacta. Devuelve la cantidad."""
    import csv
    import io
    req = urllib.request.Request(URL_OUI, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        texto = r.read().decode("utf-8", "replace")
    filas = {}
    for f in csv.reader(io.StringIO(texto)):
        if len(f) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", f[1].strip()):
            filas[f[1].strip().upper()] = " ".join(f[2].split())
    if len(filas) < 10000:
        raise ValueError("La base descargada parece incompleta.")
    with open(os.path.join(carpeta, ARCHIVO_OUI), "w", encoding="utf-8", newline="\n") as fh:
        for pref in sorted(filas):
            fh.write(f"{pref}\t{filas[pref]}\n")
    return cargar_fabricantes(carpeta)


def mac_privada(mac):
    """MAC 'administrada localmente': la inventa el equipo (celulares, notebooks
    con 'dirección privada', máquinas virtuales). No identifica al fabricante."""
    h = mac.replace("-", "").replace(":", "")
    return len(h) == 12 and h[1].upper() in "26AE"


def fabricante(mac):
    if not mac:
        return ""
    if mac_privada(mac):
        return "(MAC privada/aleatoria)"
    if _oui is None:
        return ""
    return _oui.get(mac.replace("-", "").replace(":", "").upper()[:6], "")


# --------------------------------------------------------------------------
# Nombres: DNS inverso, NetBIOS, mDNS, LLMNR
# --------------------------------------------------------------------------
def nombre_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def netbios(ip, timeout=1.5):
    """Consulta de estado NetBIOS (UDP 137). Devuelve {nombre, grupo, mac}."""
    paquete = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
               b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(paquete, (ip, 137))
            datos, _ = s.recvfrom(2048)
    except OSError:
        return {}
    try:
        cant = datos[56]
        info = {}
        pos = 57
        for _ in range(cant):
            nombre = datos[pos:pos + 15].decode("cp850", "replace").strip()
            sufijo = datos[pos + 15]
            grupo = struct.unpack(">H", datos[pos + 16:pos + 18])[0] & 0x8000
            if sufijo == 0x00 and nombre:
                info.setdefault("grupo" if grupo else "nombre", nombre)
            pos += 18
        mac = datos[pos:pos + 6]
        if len(mac) == 6 and mac != b"\x00" * 6:
            info["mac"] = "-".join(f"{b:02X}" for b in mac)
        return info
    except (IndexError, struct.error):
        return {}


def _leer_nombre_dns(datos, pos, saltos=0):
    """Decodifica un nombre DNS (con compresión). Devuelve (nombre, pos_siguiente)."""
    partes = []
    fin = None
    while True:
        largo = datos[pos]
        if largo == 0:
            pos += 1
            break
        if largo & 0xC0 == 0xC0:
            if saltos > 10:
                raise IndexError
            puntero = struct.unpack(">H", datos[pos:pos + 2])[0] & 0x3FFF
            if fin is None:
                fin = pos + 2
            resto, _ = _leer_nombre_dns(datos, puntero, saltos + 1)
            if resto:
                partes.append(resto)
            return ".".join(partes), fin
        partes.append(datos[pos + 1:pos + 1 + largo].decode("utf-8", "replace"))
        pos += 1 + largo
    return ".".join(partes), fin if fin is not None else pos


def _consulta_ptr(ip, puerto, timeout):
    """Pregunta al propio equipo por su nombre (PTR) usando mDNS o LLMNR."""
    nombre = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    pregunta = b"".join(bytes([len(p)]) + p.encode() for p in nombre.split(".")) + b"\x00"
    clase = 0x8001 if puerto == 5353 else 0x0001       # mDNS: pedir respuesta unicast
    paquete = b"\x4a\x53\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + pregunta + \
              struct.pack(">HH", 12, clase)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(paquete, (ip, puerto))
            datos, _ = s.recvfrom(4096)
        preguntas, respuestas = struct.unpack(">HH", datos[4:8])
        pos = 12
        for _ in range(preguntas):
            _, pos = _leer_nombre_dns(datos, pos)
            pos += 4
        for _ in range(respuestas):
            _, pos = _leer_nombre_dns(datos, pos)
            tipo, _, _, largo = struct.unpack(">HHIH", datos[pos:pos + 10])
            pos += 10
            if tipo == 12:
                return _leer_nombre_dns(datos, pos)[0].rstrip(".")
            pos += largo
    except (OSError, IndexError, struct.error):
        pass
    return ""


def nombre_mdns(ip, timeout=1.5):
    """Nombre Bonjour/mDNS (Apple, Linux, impresoras, Chromecast...)."""
    return _consulta_ptr(ip, 5353, timeout)


def nombre_llmnr(ip, timeout=1.5):
    """Nombre LLMNR (Windows)."""
    return _consulta_ptr(ip, 5355, timeout)


# --------------------------------------------------------------------------
# SMB: nombre, dominio y versión de Windows (sin iniciar sesión)
# --------------------------------------------------------------------------
def _der(etiqueta, contenido):
    n = len(contenido)
    largo = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else b"\x82" + struct.pack(">H", n)
    return bytes([etiqueta]) + largo + contenido


def _smb2_cabecera(comando, msg_id):
    return (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, comando, 1, 0, 0, msg_id, 0, 0, 0)
            + b"\x00" * 16)


def _smb_enviar(s, cuerpo):
    s.sendall(struct.pack(">I", len(cuerpo)) + cuerpo)
    cab = b""
    while len(cab) < 4:
        parte = s.recv(4 - len(cab))
        if not parte:
            raise OSError("conexión cerrada")
        cab += parte
    largo = struct.unpack(">I", cab)[0] & 0xFFFFFF
    datos = b""
    while len(datos) < largo:
        parte = s.recv(largo - len(datos))
        if not parte:
            break
        datos += parte
    return datos


def _version_windows(mayor, menor, build):
    if build == 0:
        return "Samba / NAS / impresora (SMB no Windows)"
    if mayor == 10:
        if build >= 26100:
            base = "Windows 11 24H2+ / Server 2025"
        elif build >= 22000:
            base = "Windows 11"
        elif build == 20348:
            base = "Windows Server 2022"
        elif build == 17763:
            base = "Windows 10 1809 / Server 2019"
        elif build == 14393:
            base = "Windows 10 1607 / Server 2016"
        else:
            base = "Windows 10"
    else:
        base = {(6, 3): "Windows 8.1 / Server 2012 R2", (6, 2): "Windows 8 / Server 2012",
                (6, 1): "Windows 7 / Server 2008 R2", (6, 0): "Windows Vista / Server 2008",
                (5, 2): "Windows Server 2003", (5, 1): "Windows XP"}.get(
            (mayor, menor), f"Windows {mayor}.{menor}")
    return f"{base} (compilación {build})"


def smb_info(ip, timeout=2.0):
    """Devuelve {nombre, dominio, nombre_dns, dominio_dns, sistema} vía SMB2/NTLM."""
    ntlm = (b"NTLMSSP\x00" + struct.pack("<II", 1, 0xE2088297) + b"\x00" * 16
            + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f")
    oid_spnego = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    oid_ntlm = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    token = _der(0x60, oid_spnego + _der(0xA0, _der(0x30,
                 _der(0xA0, _der(0x30, oid_ntlm)) + _der(0xA2, _der(0x04, ntlm)))))
    negociar = _smb2_cabecera(0, 0) + struct.pack("<HHHHI", 36, 2, 1, 0, 0) + b"\x11" * 16 + \
        b"\x00" * 8 + struct.pack("<HH", 0x0202, 0x0210)
    sesion = _smb2_cabecera(1, 1) + struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(token), 0) + token
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            r = _smb_enviar(s, negociar)
            if r[:4] != b"\xfeSMB":
                return {}
            r = _smb_enviar(s, sesion)
    except OSError:
        return {}
    try:
        i = r.find(b"NTLMSSP\x00")
        if i < 0 or struct.unpack("<I", r[i + 8:i + 12])[0] != 2:
            return {}
        m = r[i:]
        info = {}
        largo, _, pos = struct.unpack("<HHI", m[40:48])
        mayor, menor, build = struct.unpack("<BBH", m[48:52])
        if pos >= 56:
            info["sistema"] = _version_windows(mayor, menor, build)
        campos = {1: "nombre", 2: "dominio", 3: "nombre_dns", 4: "dominio_dns"}
        fin = pos + largo
        while pos + 4 <= fin:
            tipo, n = struct.unpack("<HH", m[pos:pos + 4])
            if tipo == 0:
                break
            if tipo in campos:
                info[campos[tipo]] = m[pos + 4:pos + 4 + n].decode("utf-16-le", "replace")
            pos += 4 + n
        return info
    except (IndexError, struct.error):
        return {}


# --------------------------------------------------------------------------
# Servicios: página web, banners
# --------------------------------------------------------------------------
_SIN_VERIFICAR = ssl.create_default_context()
_SIN_VERIFICAR.check_hostname = False
_SIN_VERIFICAR.verify_mode = ssl.CERT_NONE
try:
    _SIN_VERIFICAR.set_ciphers("DEFAULT:@SECLEVEL=0")      # equipos viejos
    _SIN_VERIFICAR.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
except (ssl.SSLError, ValueError, AttributeError):
    pass


def _limpio(texto, maximo=120):
    texto = re.sub(r"\s+", " ", "".join(c if c.isprintable() else " " for c in texto)).strip()
    return texto[:maximo]


def http_info(ip, puerto, timeout=3.0):
    """Devuelve {servidor, titulo, auth} de la página web del equipo."""
    seguro = puerto in (443, 8443)
    try:
        if seguro:
            con = http.client.HTTPSConnection(ip, puerto, timeout=timeout, context=_SIN_VERIFICAR)
        else:
            con = http.client.HTTPConnection(ip, puerto, timeout=timeout)
        try:
            con.request("GET", "/", headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
            r = con.getresponse()
            cuerpo = r.read(65536).decode("utf-8", "replace")
            info = {}
            if r.getheader("Server"):
                info["servidor"] = _limpio(r.getheader("Server"))
            m = re.search(r"<title[^>]*>(.*?)</title>", cuerpo, re.I | re.S)
            if m and _limpio(m.group(1)):
                info["titulo"] = _limpio(m.group(1))
            auth = r.getheader("WWW-Authenticate") or ""
            m = re.search(r'realm="([^"]*)"', auth)
            if m and m.group(1):
                info["auth"] = _limpio(m.group(1))
            if not info and r.getheader("Location"):
                info["titulo"] = "redirige a " + _limpio(r.getheader("Location"), 80)
            return info
        finally:
            con.close()
    except (OSError, http.client.HTTPException, ValueError):
        return {}


def banner(ip, puerto, timeout=2.5):
    """Primera línea que manda el servicio al conectarse (SSH, FTP, SMTP...)."""
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            s.settimeout(timeout)
            datos = s.recv(256)
    except OSError:
        return ""
    return _limpio(datos.decode("latin-1").split("\n")[0])


# --------------------------------------------------------------------------
# UPnP / SSDP: routers, televisores, impresoras, cámaras, NAS...
# --------------------------------------------------------------------------
def ssdp_descubrir(ips_locales, espera=3.0):
    """Pregunta por multidifusión quién habla UPnP. Devuelve {ip: {servidor, urls}}."""
    import time
    mensaje = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    socks = []
    for ip_local in ips_locales or [""]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.bind((ip_local, 0))
            s.settimeout(0.3)
            s.sendto(mensaje, ("239.255.255.250", 1900))
            s.sendto(mensaje, ("239.255.255.250", 1900))
            socks.append(s)
        except OSError:
            pass
    encontrados = {}
    fin = time.time() + espera
    while socks and time.time() < fin:
        for s in socks:
            try:
                datos, (ip, _) = s.recvfrom(4096)
            except OSError:
                continue
            cab = {}
            for linea in datos.decode("utf-8", "replace").split("\r\n")[1:]:
                k, sep, v = linea.partition(":")
                if sep:
                    cab[k.strip().lower()] = v.strip()
            e = encontrados.setdefault(ip, {"servidor": "", "urls": []})
            if cab.get("server"):
                e["servidor"] = _limpio(cab["server"])
            url = cab.get("location", "")
            if url and url not in e["urls"]:
                e["urls"].append(url)
    for s in socks:
        s.close()
    return encontrados


def upnp_info(ip, datos_ssdp, timeout=3.0):
    """Lee la descripción UPnP del equipo: {nombre, fabricante, modelo, servidor}."""
    info = {}
    if datos_ssdp.get("servidor"):
        info["servidor"] = datos_ssdp["servidor"]
    for url in datos_ssdp.get("urls", [])[:3]:
        # solo se consulta al propio equipo, nunca a una dirección que él indique
        if not re.match(rf"http://{re.escape(ip)}[:/]", url):
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                xml = r.read(131072).decode("utf-8", "replace")
        except (OSError, ValueError, http.client.HTTPException):
            continue
        for campo, etiqueta in (("nombre", "friendlyName"), ("fabricante", "manufacturer"),
                                ("modelo", "modelName"), ("modelo_nro", "modelNumber"),
                                ("descripcion", "modelDescription")):
            m = re.search(rf"<{etiqueta}>(.*?)</{etiqueta}>", xml, re.S)
            if m and _limpio(m.group(1)):
                info.setdefault(campo, _limpio(m.group(1)))
        if "nombre" in info:
            break
    return info
