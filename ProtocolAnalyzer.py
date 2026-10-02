#!/usr/bin/env python3
import os
import socket
import struct
import sys
from collections import Counter
from datetime import datetime
ICMP_TIPOS = {0: "Echo reply", 3: "Destino inalcanzable", 8: "Echo request",
              11: "TTL excedido"}
ICMP6_TIPOS = {128: "Echo request", 129: "Echo reply", 133: "Router solicit",
               134: "Router advert", 135: "Neighbor solicit",
               136: "Neighbor advert"}
DNS_TIPOS = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
             28: "AAAA", 33: "SRV", 65: "HTTPS"}
PUERTOS_UDP = {67: "DHCP", 68: "DHCP", 123: "NTP", 137: "NetBIOS",
               1900: "SSDP", 5353: "mDNS", 443: "QUIC"}
METODOS_HTTP = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"HTTP/1.")

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

fuente = sys.argv[1]
maximo = int(sys.argv[2]) if len(sys.argv) > 2 else 0
filtro = sys.argv[3].upper() if len(sys.argv) > 3 else None

def mac_str(raw):return ":".join(f"{b:02x}" for b in raw)

def texto_seguro(datos, limite=80):return "".join(chr(b) if 32 <= b < 127 else "." for b in datos[:limite])

def dns_nombre(data, off):
    etiquetas, saltado, fin, saltos = [], False, off, 0
    while off < len(data):
        largo = data[off]
        if largo == 0:
            off += 1
            if not saltado:fin = off
            break
        if largo & 0xC0 == 0xC0:
            ptr = ((largo & 0x3F) << 8) | data[off + 1]
            if not saltado:fin = off + 2
            off, saltado, saltos = ptr, True, saltos + 1
            if saltos > 10:break
            continue
        off += 1
        etiquetas.append(data[off:off + largo].decode(errors="ignore"))
        off += largo
    return ".".join(etiquetas), fin

def decodificar_dns(data, info):
    try:
        ident, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
        es_resp = flags >> 15
        off = 12
        preguntas = []
        for _ in range(qd):
            nombre, off = dns_nombre(data, off)
            qtipo = struct.unpack("!H", data[off:off + 2])[0]
            off += 4
            preguntas.append(f"{nombre} ({DNS_TIPOS.get(qtipo, qtipo)})")
        info["capas"].append("DNS")
        tipo = "Respuesta" if es_resp else "Consulta"
        info["resumen"] = f"DNS {tipo} id=0x{ident:04x} " + ", ".join(preguntas)
        if es_resp:
            for _ in range(an):
                nombre, off = dns_nombre(data, off)
                rtipo, _, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
                off += 10
                rdata = data[off:off + rdlen]
                if rtipo == 1 and rdlen == 4:valor = socket.inet_ntoa(rdata)
                elif rtipo == 28 and rdlen == 16:valor = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtipo in (2, 5, 12):valor, _ = dns_nombre(data, off)
                else:valor = f"{rdlen} bytes"
                info["detalles"].append(f"  {nombre} {DNS_TIPOS.get(rtipo, rtipo)} -> {valor} (TTL {ttl})")
                off += rdlen
    except (struct.error, IndexError, OSError):info["detalles"].append("  [DNS malformado o truncado]")

def decodificar_http(data, info):
    lineas = data.split(b"\r\n")
    primera = lineas[0].decode(errors="ignore")[:100]
    info["capas"].append("HTTP")
    info["resumen"] = f"HTTP {primera}"
    for linea in lineas[1:12]:
        l = linea.decode(errors="ignore")
        if l.lower().startswith(("host:", "user-agent:", "content-type:", "server:")):info["detalles"].append(f"  {l[:100]}")

def extraer_sni(data):
    try:
        if data[0] != 0x16 or data[5] != 0x01:return None
        off = 43  # 5 (registro) + 4 (handshake) + 2 (versión) + 32 (random)
        off += 1 + data[off]                                  # session id
        off += 2 + struct.unpack("!H", data[off:off + 2])[0]  # cipher suites
        off += 1 + data[off]                                  # compresión
        fin = off + 2 + struct.unpack("!H", data[off:off + 2])[0]
        off += 2
        while off + 4 <= fin:
            tipo, largo = struct.unpack("!HH", data[off:off + 4])
            off += 4
            if tipo == 0:
                nlen = struct.unpack("!H", data[off + 3:off + 5])[0]
                return data[off + 5:off + 5 + nlen].decode(errors="ignore")
            off += largo
    except (IndexError, struct.error):pass
    return None

def decodificar_tls(data, info):
    tipos = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",23: "Application Data"}
    versiones = {0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}
    ver = struct.unpack("!H", data[1:3])[0]
    info["capas"].append("TLS")
    info["resumen"] = (f"TLS {tipos.get(data[0], data[0])} "f"(v{versiones.get(ver, hex(ver))})")
    sni = extraer_sni(data)
    if sni:info["resumen"] += f" ClientHello SNI={sni}"

def decodificar_tcp(data, info):
    if len(data) < 20:return
    sp, dp, seq, ack, off_flags, ventana = struct.unpack("!HHLLHH", data[:16])
    offset = (off_flags >> 12) * 4
    nombres = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]
    flags = [n for i, n in enumerate(nombres) if off_flags & (1 << i)]
    payload = data[offset:]
    info["capas"].append("TCP")
    info["resumen"] = (f"TCP {info['src']}:{sp} -> {info['dst']}:{dp} "f"[{','.join(flags) or '-'}] seq={seq} ack={ack} "f"win={ventana} len={len(payload)}")
    if not payload:return
    if payload.startswith(METODOS_HTTP):decodificar_http(payload, info)
    elif len(payload) > 6 and payload[0] in (20, 21, 22, 23) and payload[1] == 3:decodificar_tls(payload, info)
    else:info["detalles"].append(f"  Payload: {texto_seguro(payload)}")

def decodificar_udp(data, info):
    if len(data) < 8:return
    sp, dp, largo = struct.unpack("!HHH", data[:6])
    payload = data[8:]
    info["capas"].append("UDP")
    info["resumen"] = (f"UDP {info['src']}:{sp} -> {info['dst']}:{dp} "f"len={len(payload)}")
    if 53 in (sp, dp) or 5353 in (sp, dp):decodificar_dns(payload, info)
    else:
        servicio = PUERTOS_UDP.get(sp) or PUERTOS_UDP.get(dp)
        if servicio:
            info["capas"].append(servicio.upper())
            info["resumen"] += f" ({servicio})"

def decodificar_icmp(data, info, v6=False):
    if len(data) < 4:return
    tipo, codigo = data[0], data[1]
    tabla = ICMP6_TIPOS if v6 else ICMP_TIPOS
    info["capas"].append("ICMPv6" if v6 else "ICMP")
    info["resumen"] = (f"{'ICMPv6' if v6 else 'ICMP'} {info['src']} -> "f"{info['dst']} {tabla.get(tipo, f'tipo {tipo}')} "f"(código {codigo})")

def decodificar_ipv4(data, info):
    if len(data) < 20:return
    ihl = (data[0] & 0x0F) * 4
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", data[:20])
    info["src"], info["dst"] = socket.inet_ntoa(src), socket.inet_ntoa(dst)
    info["capas"].append("IPv4")
    info["resumen"] = f"IPv4 {info['src']} -> {info['dst']} proto={proto} ttl={ttl}"
    despacho_transporte(proto, data[ihl:], info)

def decodificar_ipv6(data, info):
    if len(data) < 40:return
    siguiente, hop = struct.unpack("!6xBB", data[:8])
    info["src"] = socket.inet_ntop(socket.AF_INET6, data[8:24])
    info["dst"] = socket.inet_ntop(socket.AF_INET6, data[24:40])
    info["capas"].append("IPv6")
    info["resumen"] = f"IPv6 {info['src']} -> {info['dst']} hop={hop}"
    despacho_transporte(siguiente, data[40:], info)

def despacho_transporte(proto, payload, info):
    if proto == 6:decodificar_tcp(payload, info)
    elif proto == 17:decodificar_udp(payload, info)
    elif proto == 1:decodificar_icmp(payload, info)
    elif proto == 58:decodificar_icmp(payload, info, v6=True)

def decodificar_arp(data, info):
    if len(data) < 28:return
    op = struct.unpack("!H", data[6:8])[0]
    smac, sip = mac_str(data[8:14]), socket.inet_ntoa(data[14:18])
    tip = socket.inet_ntoa(data[24:28])
    info["capas"].append("ARP")
    info["src"], info["dst"] = sip, tip
    if op == 1:info["resumen"] = f"ARP ¿Quién tiene {tip}? Dímelo {sip} ({smac})"
    else:info["resumen"] = f"ARP {sip} está en {smac}"

def analizar(data, linktype):
    info = {"capas": [], "src": "?", "dst": "?", "resumen": "", "detalles": []}
    try:
        if linktype == 1:  # Ethernet
            ethertype = struct.unpack("!H", data[12:14])[0]
            payload = data[14:]
            info["capas"].append("ETH")
            if ethertype == 0x8100:  # VLAN
                ethertype = struct.unpack("!H", payload[2:4])[0]
                payload = payload[4:]
        elif linktype == 113:  # Linux cooked
            ethertype = struct.unpack("!H", data[14:16])[0]
            payload = data[16:]
        elif linktype == 101:  # IP crudo
            ethertype = 0x0800 if data[0] >> 4 == 4 else 0x86DD
            payload = data
        else:info["resumen"] = f"Tipo de enlace no soportado ({linktype})";return info

        if ethertype == 0x0800:decodificar_ipv4(payload, info)
        elif ethertype == 0x86DD:decodificar_ipv6(payload, info)
        elif ethertype == 0x0806:decodificar_arp(payload, info)
        else:info["resumen"] = f"Ethertype 0x{ethertype:04x}"
    except (struct.error, IndexError, OSError):info["resumen"] = "[Paquete malformado]"
    return info

def leer_pcap(ruta):
    with open(ruta, "rb") as f:
        cabecera = f.read(24)
        magic = cabecera[:4]
        if magic == b"\x0a\x0d\x0d\x0a":print("[!] Formato pcapng no soportado. Exporta como .pcap clásico.");sys.exit(1)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):e = ">"
        else:print("[!] Archivo pcap inválido.");sys.exit(1)
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(e + "I", cabecera[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:break
            seg, frac, incl, _ = struct.unpack(e + "IIII", rh)
            datos = f.read(incl)
            yield seg + frac / (1e9 if nano else 1e6), linktype, datos

def captura_viva():
    try:s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("[!] Se necesitan permisos root. Ejecuta 'tsu' primero, ""o analiza un archivo .pcap sin root.")
        sys.exit(1)
    except AttributeError:
        print("[!] AF_PACKET no está disponible en este sistema.");sys.exit(1)
    import time
    try:
        while True:
            datos, _ = s.recvfrom(65535)
            yield time.time(), 1, datos
    finally:s.close()

if fuente.lower() == "live":
    paquetes = captura_viva()
    print("[*] Captura en vivo (Ctrl+C para detener)")
elif os.path.isfile(fuente):
    paquetes = leer_pcap(fuente)
    print(f"[*] Analizando archivo: {fuente}")
else:
    print(f"[!] No se encontró el archivo: {fuente}")
    sys.exit(1)

if filtro:print(f"[*] Filtro activo: {filtro}")
print()

stats_proto = Counter()
stats_flujos = Counter()
total, mostrados, total_bytes = 0, 0, 0

try:
    for ts, linktype, datos in paquetes:
        total += 1
        total_bytes += len(datos)
        info = analizar(datos, linktype)
        principal = info["capas"][-1] if info["capas"] else "OTRO"
        stats_proto[principal] += 1
        if info["src"] != "?":stats_flujos[(info["src"], info["dst"])] += 1

        if filtro and filtro not in [c.upper() for c in info["capas"]]:continue

        mostrados += 1
        hora = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        print(f"#{total} {hora} [{principal}] {len(datos)}B")
        print(f"  {info['resumen']}")
        for linea in info["detalles"]:print(linea)
        print()

        if maximo and mostrados >= maximo:break
except KeyboardInterrupt:print("\n[!] Interrumpido por el usuario.")

print("=" * 50)
print(f"Paquetes procesados: {total} | Mostrados: {mostrados} | Bytes: {total_bytes}")
print("\nProtocolos:")
for nombre, cantidad in stats_proto.most_common():print(f"  {nombre:<8} {cantidad}")
print("\nTop conversaciones:")
for (a, b), cantidad in stats_flujos.most_common(5):print(f"  {a} -> {b}: {cantidad} paquetes")
