# -*- coding: utf-8 -*-
"""
Genera icono.ico (un radar) sin librerías externas.
Solo hace falta ejecutarlo si se quiere cambiar el dibujo:  python crear_icono.py
"""
import math
import os
import struct
import sys
import zlib

BASE = 768                                  # se dibuja grande y se reduce (suaviza bordes)
TAMANOS = (16, 24, 32, 48, 64, 128, 256)
FONDO_A, FONDO_B = (18, 52, 86), (8, 22, 38)
VERDE = (61, 220, 132)


def mezclar(abajo, arriba, alfa):
    return tuple(a + (b - a) * alfa for a, b in zip(abajo, arriba))


def pixel(x, y):
    """Color (r, g, b, a) del punto x, y en coordenadas 0..1."""
    # cuadrado de esquinas redondeadas
    radio = 0.22
    dx = max(abs(x - 0.5) - (0.5 - radio), 0)
    dy = max(abs(y - 0.5) - (0.5 - radio), 0)
    if math.hypot(dx, dy) > radio:
        return (0, 0, 0, 0)
    color = mezclar(FONDO_A, FONDO_B, y)
    cx, cy = x - 0.5, y - 0.5
    r = math.hypot(cx, cy)
    ang = math.degrees(math.atan2(-cy, cx)) % 360
    if r <= 0.40:
        # barrido: cuña que se desvanece detrás de la aguja (aguja a 55 grados)
        atras = (ang - 55) % 360
        if atras <= 110:
            color = mezclar(color, VERDE, 0.55 * (1 - atras / 110) ** 1.5)
        # mira
        if abs(cx) < 0.004 or abs(cy) < 0.004:
            color = mezclar(color, VERDE, 0.30)
    # anillos
    for anillo, grosor in ((0.40, 0.022), (0.27, 0.014), (0.14, 0.014)):
        if abs(r - anillo) < grosor / 2:
            color = mezclar(color, VERDE, 0.95 if anillo == 0.40 else 0.60)
    # aguja
    if r <= 0.40:
        ux, uy = math.cos(math.radians(55)), -math.sin(math.radians(55))
        largo = cx * ux + cy * uy
        if 0 <= largo and abs(cx * uy - cy * ux) < 0.011:
            color = mezclar(color, (200, 255, 220), 0.95)
    # equipos detectados
    for px, py, pr in ((0.66, 0.36, 0.045), (0.36, 0.60, 0.036), (0.60, 0.68, 0.030)):
        d = math.hypot(x - px, y - py)
        if d < pr:
            color = mezclar(color, (235, 255, 240), 1.0)
        elif d < pr * 1.7:
            color = mezclar(color, VERDE, 0.5 * (1 - (d - pr) / (pr * 0.7)))
    if r < 0.03:
        color = mezclar(color, (235, 255, 240), 1.0)
    return (*color, 255)


def dibujar():
    return [[pixel((i + 0.5) / BASE, (j + 0.5) / BASE) for i in range(BASE)] for j in range(BASE)]


def reducir(img, n):
    """Promedia bloques (con alfa premultiplicado) hasta n x n. Devuelve filas de bytes RGBA."""
    k = BASE // n
    filas = []
    for j in range(n):
        fila = bytearray()
        for i in range(n):
            r = g = b = a = 0.0
            for y in range(j * k, (j + 1) * k):
                linea = img[y]
                for x in range(i * k, (i + 1) * k):
                    pr, pg, pb, pa = linea[x]
                    r += pr * pa
                    g += pg * pa
                    b += pb * pa
                    a += pa
            if a:
                fila += bytes((round(r / a), round(g / a), round(b / a), round(a / (k * k))))
            else:
                fila += b"\x00\x00\x00\x00"
        filas.append(bytes(fila))
    return filas


def png(filas, n):
    def bloque(tipo, datos):
        return struct.pack(">I", len(datos)) + tipo + datos + \
            struct.pack(">I", zlib.crc32(tipo + datos) & 0xFFFFFFFF)
    crudo = b"".join(b"\x00" + f for f in filas)
    return (b"\x89PNG\r\n\x1a\n" + bloque(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0))
            + bloque(b"IDAT", zlib.compress(crudo, 9)) + bloque(b"IEND", b""))


def dib(filas, n):
    """Formato clásico de los .ico: mapa de bits BGRA de abajo hacia arriba + máscara."""
    cab = struct.pack("<IiiHHIIiiII", 40, n, n * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pix = b"".join(bytes(b for i in range(0, len(f), 4) for b in (f[i + 2], f[i + 1], f[i], f[i + 3]))
                   for f in reversed(filas))
    mascara = b"\x00" * (((n + 31) // 32) * 4) * n
    return cab + pix + mascara


def main():
    carpeta = os.path.dirname(os.path.abspath(__file__))
    img = dibujar()
    imagenes = []
    for n in TAMANOS:
        filas = reducir(img, n)
        imagenes.append((n, png(filas, n) if n == 256 else dib(filas, n)))
        if n == 256 and len(sys.argv) > 1:          # vista previa opcional en PNG
            with open(sys.argv[1], "wb") as fh:
                fh.write(png(filas, n))
    salida = struct.pack("<HHH", 0, 1, len(imagenes))
    pos = 6 + 16 * len(imagenes)
    for n, datos in imagenes:
        salida += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(datos), pos)
        pos += len(datos)
    salida += b"".join(d for _, d in imagenes)
    with open(os.path.join(carpeta, "icono.ico"), "wb") as fh:
        fh.write(salida)
    print(f"icono.ico generado ({len(salida)} bytes, tamaños {TAMANOS})")


if __name__ == "__main__":
    main()
