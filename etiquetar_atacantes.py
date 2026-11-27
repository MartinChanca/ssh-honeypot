#!/usr/bin/env python3
"""Etiqueta a cada IP atacante del honeypot por familia de comportamiento. SOLO LEE los logs.

No toca el honeypot, no escribe en logs/, no cambia lo que ve el atacante: la medicion sigue igual.
Solo libreria estandar. Corre en cualquier maquina que tenga una copia de los logs.

    python3 etiquetar_atacantes.py --logs ~/honeypot-aws/logs --salida etiquetas.csv
    python3 etiquetar_atacantes.py --logs ~/honeypot-aws/logs --evaluar-ml     # ademas, matriz contra el clasificador ML
    python3 etiquetar_atacantes.py --logs LOGS --desde 2026-11-01              # solo eventos desde esa fecha

Lee (si existen): shell_commands.json, ssh_connections.json, attempts.json, http_attempts.json,
ftp_attempts.json, ml_classifications.json. Cada archivo puede ser una linea JSON por evento
o una lista JSON.

Cada IP puede tener varias etiquetas (un bot puede probar la shell Y pedir /mcp). "principal" es
la de mayor prioridad segun ORDEN, para poder armar una tabla simple. Las firmas son las que ya
se vieron en el honeypot (ver registro de hipotesis), no un modelo: si una familia nueva no
tiene firma, la IP sale como "sin_clasificar" y eso es informacion util, no un error.
"""
import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict

ARCHIVOS = {
    "shell_commands.json": "shell_command",
    "ssh_connections.json": "ssh_connection",
    "attempts.json": "ssh_login_attempt",
    "http_attempts.json": "http_request",
    "ftp_attempts.json": "ftp_attempt",
}

# Orden = prioridad de la etiqueta principal (la primera que tenga la IP).
ORDEN = [
    "escaner_investigacion", # IP de un escaner de investigacion conocido (Shadowserver, Palo Alto Xpanse): trafico documentado, no un ataque
    "instalador",            # pide instalar/descargar herramientas o ejecutar un script remoto
    "credenciales_cloud",    # busca credenciales cloud / IMDS
    "exploit_iot",           # exploits de routers y camaras (Mirai y familia)
    "mcp_buscador",          # busca servidores MCP/SSE abiertos
    "api_ia_llmjacking",     # busca APIs de modelos de IA abiertas
    "sondeo_open_webui",     # /api/v1/auths/...: intenta registrarse o entrar en una interfaz Open WebUI
    "proxy_abierto_canario", # proxy abierto con destinos de control del operador (dominios raros, IPs sueltas)
    "proxy_abierto_eco_ip",  # proxy abierto que pide su IP de vuelta (ipify, httpbin...)
    "proxy_abierto",         # URL absoluta o CONNECT a otros destinos: busca un proxy abierto
    "sondeo_c2_checksum8",   # rutas de 4 caracteres tipo /aab9: caza de servidores Cobalt Strike/Metasploit
    "sondeo_weblogic_t3",    # saludo del protocolo T3 de WebLogic (como el script weblogic-t3-info de Nmap)
    "sondeo_rdp",            # solicitud de conexion RDP (cookie mstshash) mandada al puerto web
    "anti_honeypot",         # verifica si la shell es real (H-003)
    "perfilado_sistema",     # mide CPU/RAM/SO (H-006)
    "fuerza_bruta_ssh",      # muchos logins, sin llegar a usar shell
    "sondeo_ssh_corto",      # conexiones SSH de menos de 1 s (H-004)
    "sondeo_ci_jenkins",     # /crumbIssuer, /hudson, /api/json: busca Jenkins
    "sondeo_trino_presto",   # POST /v1/statement: API de consultas SQL de Trino/Presto
    "sondeo_citrix_netscaler", # /vpn/js/rdx, /vpn/pluginlist.xml, /logon/LogonPoint/: huella o login de Citrix NetScaler/Gateway
    "busca_config_expuesta", # /.env, /actuator, phpinfo, wp-json: busca secretos y configuracion
    "sondeo_paneles_login",  # /login, VPN/firewalls, GeoServer: busca paneles de administracion
    "sondeo_spotify_zeroconf", # /zc?action=getInfo: descubre dispositivos con Spotify Connect
    "login_pocos_intentos",  # 1 a 9 logins SSH sin shell: rociado lento de credenciales
    "otro_con_shell",        # uso shell pero no encaja en ninguna firma
    "protocolo_raro",        # HTTP con basura o un protocolo que no es HTTP
    "recon_web_generico",    # solo pide /, favicon, robots.txt: mira que hay
    "escaneo_solo_conexion", # solo se conecta por SSH (banner, puerto abierto), sin probar logins
    "sin_clasificar",
]

R = lambda p: re.compile(p, re.I)
FIRMAS_CMD = {
    "instalador": R(r"\b(which|command\s+-v|type)\s+(curl|wget|python3?|gcc|perl)\b|\b(apt(-get)?|yum|dnf|apk|pip3?|npm)\s+(-y\s+)?(install|add)\b|\b(curl|wget)\b[^|;&\n]*\|\s*(ba|z|da)?sh\b|\b(wget|curl)\s+\S*https?://|\bchmod\s+\+x\b"),
    "credenciales_cloud": R(r"\.aws/credentials|169\.254\.169\.254|\bmetadata\.google\.internal\b|\.docker/config|\.kube/config|AWS_(SECRET|ACCESS)"),
    "anti_honeypot": R(r"\bf?_?check_[0-9a-f]{16,}|\$\(\(\s*\d+\s*[*+\-]\s*\d+|\bset\s+--\s+\S*check_"),
    "perfilado_sistema": R(r"/proc/(cpuinfo|meminfo)|\bnproc\b|\blscpu\b|\buname\b|\bfree\s+-[mhg]\b|/etc/(os-release|issue)\b"),
}
FIRMAS_HTTP = {
    "mcp_buscador": R(r"^/(api/)?(mcp|sse)(/|$|\?)"),
    "sondeo_open_webui": R(r"^/api/v1/auths/"),
    "sondeo_trino_presto": R(r"^/v1/statement\b"),
    "sondeo_citrix_netscaler": R(r"^/(vpn/(js/rdx/|pluginlist\.xml)|logon/LogonPoint/)"),
    "api_ia_llmjacking": R(r"^/(api/)?(v1|v1beta)/models\b|^/api/tags\b|^/v1/(chat|completions)"),
    "sondeo_ci_jenkins": R(r"^/(crumbIssuer|script|jenkins|hudson|api/json)\b"),
    "sondeo_paneles_login": R(r"^/(login|remote/login|\+CSCOE\+|geoserver|admin|manager|dana-na|global-protect|owa)\b"),
    "busca_config_expuesta": R(r"^/(\.env[\w.\-]*|\.git/|actuator\b|info\.php|phpinfo\.php|wp-json|wp-config|server-status|.*GetPhpInfo\.php|@vite/|api/(env|environment|secrets|config/env|system/environment)\b)"),
    "sondeo_spotify_zeroconf": R(r"^/zc\?action=(getInfo|addUser)\b"),
    "recon_web_generico": R(r"^/(index\.(html?|php)|favicon\.ico|robots\.txt)?$"),
    "exploit_iot": R(r"setup\.cgi|boaform|/GponForm|/cgi-bin/(luci|\.%2e)|/HNAP1|/shell\?cmd=|/cgi-bin/cstecgi\.cgi|/board\.cgi|/tmUnblock\.cgi|[?&](cmd|command|exec|shell)=[^&\s]*(wget|curl|tftp|ftpget|busybox)\b"),
}

# Saludo T3 de WebLogic: "t3 12.1.2\nAS:2048\nHL:19\n\n". El honeypot a veces se come el "t3 " (lo toma de metodo HTTP).
RE_T3 = re.compile(r"^(t3\s+)?\d+\.\d+\.\d+\s*\n\s*AS:\d+\s*\n\s*HL:\d+", re.I)
# Rutas de 4 caracteres alfanumericos cuya suma ASCII mod 256 es 92 o 93 (checksum8 de los stagers de Cobalt Strike y Metasploit)
RE_RUTA_4 = re.compile(r"^/([A-Za-z0-9]{4})/?$")
CHECKSUM8_VALORES = (92, 93)
# Escaneres de investigacion: se reconocen por el DUENO de la IP (campo "isp" que el honeypot ya guarda en cada pedido
# HTTP), no por lo que piden. Que el trafico venga de una IP suya es solido (hay handshake TCP, no se puede falsificar
# el origen); que el pedido sea "bueno" no: ellos dicen que publican reportes a los duenos de redes. Lista editable:
# se agrega aca solo lo que se vio en el honeypot. Visto el 25/11: "The Shadowserver Foundation, Inc." (199.165.159.x).
ISP_INVESTIGACION = re.compile(r"shadowserver", re.I)
# Palo Alto Networks (Cortex Xpanse) publica los rangos desde los que escanea (cortex-docs.paloaltonetworks.com, pagina
# "Scanning activity", leida el 27/11). Que la IP este en uno de esos rangos es la senal fuerte (se aplica a cualquier tipo
# de evento, tambien SSH); lo que ellos dicen de su proposito (mapear la superficie de ataque de sus clientes, "CFAA-compliant")
# es declaracion suya, no verificada. Lista editable: se copia de su pagina, no se inventa.
REDES_INVESTIGACION = [ipaddress.ip_network(x) for x in (
    "35.203.210.0/23", "144.86.173.0/24", "147.185.132.0/23", "162.216.149.0/24", "162.216.150.0/24",
    "172.105.147.0/24", "198.235.24.0/24", "205.210.31.0/24", "216.25.88.0/21",
    "2604:a940:300:5b6::/64", "2604:a940:301:225::/64", "2604:a940:302:118::/64")]
# Ademas se identifican en el User-Agent (visto el 27/11: "Hello from Palo Alto Networks, find out more about our scans in
# ..."). El UA lo controla quien manda el pedido: es senal debil por si sola.
RE_UA_INVESTIGACION = re.compile(r"palo alto networks", re.I)
# Solicitud de conexion RDP (X.224 con cookie "mstshash=") mandada al puerto web: no es HTTP
RE_RDP = re.compile(r"mstshash=|^\x03\x00", re.I)
# Algunos verificadores de proxy se identifican en el User-Agent (visto el 26/11: "proxy-prefilter/1", 204.76.x.x)
RE_UA_VERIFICADOR_PROXY = re.compile(r"proxy[-_ ]?prefilter", re.I)
# Destinos que los verificadores de proxy usan para que el proxy "devuelva" una IP o los headers (listas editables)
ECO_IP_HOSTS = {"api.ipify.org", "api64.ipify.org", "ipify.org", "httpbin.org", "api.myip.la",
                "ifconfig.me", "icanhazip.com", "checkip.amazonaws.com", "ipinfo.io"}
# Dominios raros vistos como destino de proxy y que ninguna fuente publica documenta: se agrupan por observacion, no por reputacion
CANARIO_DOMINIOS = ("bunnyfeet.baby", "tooyoungtoholdon.world", "youshouldvecomeover.lol", "overflow.biz")
RE_IP_SUELTA = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_HOST_PUERTO = re.compile(r"^\[?[\w.\-]+\]?:\d{1,5}$")   # objetivo de un CONNECT: host:puerto
UMBRAL_FUERZA_BRUTA = 10     # logins distintos
UMBRAL_CORTAS = 3            # conexiones de menos de 1 s


def leer(ruta):
    """Devuelve la lista de eventos (dict) de un archivo, tolerando JSONL o lista. Ignora lineas rotas."""
    try:
        texto = open(ruta, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    t = texto.lstrip()
    if t.startswith("["):
        try:
            return [e for e in json.loads(t) if isinstance(e, dict)]
        except ValueError:
            pass
    eventos = []
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        try:
            e = json.loads(linea)
        except ValueError:
            continue
        if isinstance(e, dict):
            eventos.append(e)
    return eventos


def cargar(carpeta, desde=None):
    por_ip = defaultdict(list)
    for nombre, tipo in ARCHIVOS.items():
        for e in leer(os.path.join(carpeta, nombre)):
            ip = e.get("ip") or e.get("src_ip") or e.get("client_ip")
            if not ip:
                continue
            ts = str(e.get("timestamp", ""))
            if desde and ts and ts[:10] < desde:
                continue
            e.setdefault("honeypot_event", tipo)
            por_ip[ip].append(e)
    return por_ip


def es_checksum8(ruta):
    m = RE_RUTA_4.match(ruta)
    return bool(m) and sum(ord(c) for c in m.group(1)) % 256 in CHECKSUM8_VALORES


def host_destino(ruta):
    """Host al que un pedido de proxy quiere llegar (URL absoluta o host:puerto); '' si no es de proxy."""
    m = re.match(r"(?i)^https?://\[?([^/:?#\]]+)", ruta) or re.match(r"^\[?([\w.\-]+)\]?:\d{1,5}$", ruta)
    return m.group(1).lower() if m else ""


def en_rango_investigacion(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(a in r for r in REDES_INVESTIGACION if r.version == a.version)


def _ruta_http(e):
    return str(e.get("path") or e.get("url") or e.get("uri") or "")


def etiquetar_ip(eventos):
    """Devuelve (set de etiquetas, dict de rasgos) para los eventos de una IP."""
    et, f = set(), Counter()
    logins = set()
    for e in eventos:
        tipo = e.get("honeypot_event")
        if en_rango_investigacion(e.get("ip") or e.get("src_ip") or e.get("client_ip")):
            et.add("escaner_investigacion")
            f["ip_rango_investigacion"] += 1
        if tipo == "shell_command":
            f["comandos"] += 1
            cmd = str(e.get("command", ""))
            hallada = False
            for nombre, rx in FIRMAS_CMD.items():
                if rx.search(cmd):
                    et.add(nombre)
                    f["cmd_" + nombre] += 1
                    hallada = True
            if not hallada:
                f["cmd_sin_firma"] += 1
        elif tipo == "http_request":
            f["http"] += 1
            ruta, metodo = _ruta_http(e), str(e.get("method", "")).upper()
            if ISP_INVESTIGACION.search(str(e.get("isp", ""))):
                et.add("escaner_investigacion")
                f["http_isp_investigacion"] += 1
            if RE_UA_INVESTIGACION.search(str(e.get("user_agent", ""))):
                et.add("escaner_investigacion")
                f["http_ua_investigacion"] += 1
            if RE_UA_VERIFICADOR_PROXY.search(str(e.get("user_agent", ""))):
                f["http_ua_verificador_proxy"] += 1
            if RE_RDP.search(str(e.get("method", "")) + ruta):
                et.add("sondeo_rdp")
                f["http_rdp"] += 1
                continue
            if RE_T3.match(ruta) or metodo == "T3":
                et.add("sondeo_weblogic_t3")
                f["http_t3"] += 1
                continue
            if re.search(r"[\x00-\x08\x0a-\x1f]", ruta):
                et.add("protocolo_raro")
                f["http_protocolo_raro"] += 1
                continue
            if metodo == "CONNECT" or re.match(r"(?i)^https?://", ruta) or RE_HOST_PUERTO.match(ruta):
                f["http_proxy"] += 1
                host = host_destino(ruta)
                if host.endswith(CANARIO_DOMINIOS) or RE_IP_SUELTA.match(host):
                    et.add("proxy_abierto_canario")
                elif host in ECO_IP_HOSTS:
                    et.add("proxy_abierto_eco_ip")
                else:
                    et.add("proxy_abierto")
            if es_checksum8(ruta):
                et.add("sondeo_c2_checksum8")
                f["http_c2_checksum8"] += 1
            for nombre, rx in FIRMAS_HTTP.items():
                if rx.search(ruta):
                    et.add(nombre)
                    f["http_" + nombre] += 1
        elif tipo == "ssh_login_attempt":
            f["logins"] += 1
            logins.add((e.get("username"), e.get("password")))
        elif tipo == "ssh_connection":
            f["conexiones"] += 1
            try:
                if float(e.get("duracion_seg")) < 1.0:
                    f["conexiones_cortas"] += 1
            except (TypeError, ValueError):
                pass
    # Un verificador de proxy que se identifica por UA cuenta como proxy abierto aunque el pedido venga raro
    if f["http_ua_verificador_proxy"] and not et & {"proxy_abierto", "proxy_abierto_eco_ip", "proxy_abierto_canario"}:
        et.add("proxy_abierto")
        et.discard("protocolo_raro")
    f["logins_distintos"] = len(logins)
    if f["logins_distintos"] >= UMBRAL_FUERZA_BRUTA and not f["comandos"]:
        et.add("fuerza_bruta_ssh")
    if f["conexiones_cortas"] >= UMBRAL_CORTAS:
        et.add("sondeo_ssh_corto")
    if f["comandos"] and not et:
        et.add("otro_con_shell")
    if not et and 0 < f["logins_distintos"] < UMBRAL_FUERZA_BRUTA:
        et.add("login_pocos_intentos")
    if not et and f["conexiones"] and not f["http"]:
        et.add("escaneo_solo_conexion")
    if not et:
        et.add("sin_clasificar")
    return et, f


def principal(etiquetas):
    for nombre in ORDEN:
        if nombre in etiquetas:
            return nombre
    return "sin_clasificar"


def procesar(por_ip):
    filas = []
    for ip, evs in sorted(por_ip.items()):
        et, f = etiquetar_ip(evs)
        marcas = sorted(str(e.get("timestamp", "")) for e in evs if e.get("timestamp"))
        filas.append({
            "ip": ip,
            "principal": principal(et),
            "etiquetas": "|".join(n for n in ORDEN if n in et),
            "eventos": len(evs),
            "comandos": f["comandos"],
            "http": f["http"],
            "logins_distintos": f["logins_distintos"],
            "conexiones_cortas": f["conexiones_cortas"],
            "primera_vez": marcas[0] if marcas else "",
            "ultima_vez": marcas[-1] if marcas else "",
        })
    return filas


def matriz_ml(filas, carpeta):
    """Cruza la etiqueta principal con la ultima categoria que el clasificador ML le dio a cada IP."""
    ml = {}
    for e in leer(os.path.join(carpeta, "ml_classifications.json")):
        if e.get("ip") and e.get("categoria"):
            ml[e["ip"]] = e["categoria"]          # la ultima gana
    cruce = Counter()
    for fila in filas:
        if fila["ip"] in ml:
            cruce[(fila["principal"], ml[fila["ip"]])] += 1
    return cruce, len(ml)


def imprimir_matriz(cruce):
    filas = sorted({k[0] for k in cruce})
    cols = sorted({k[1] for k in cruce})
    ancho = max([len(x) for x in filas + ["familia \\ ML"]]) + 2
    print("familia \\ ML".ljust(ancho) + "".join(c[:18].rjust(20) for c in cols))
    for fam in filas:
        print(fam.ljust(ancho) + "".join(str(cruce.get((fam, c), 0)).rjust(20) for c in cols))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Etiqueta IPs del honeypot por familia (solo lectura)")
    ap.add_argument("--logs", required=True, help="carpeta con los logs del honeypot (logs/)")
    ap.add_argument("--salida", default="", help="CSV de salida (por defecto solo imprime el resumen)")
    ap.add_argument("--desde", default="", help="solo eventos desde AAAA-MM-DD")
    ap.add_argument("--evaluar-ml", action="store_true", help="matriz familia vs categoria del clasificador ML")
    a = ap.parse_args(argv)

    if not os.path.isdir(a.logs):
        print(f"No existe la carpeta {a.logs}", file=sys.stderr)
        return 2
    por_ip = cargar(a.logs, a.desde or None)
    if not por_ip:
        print("No se encontraron eventos con IP en esa carpeta.", file=sys.stderr)
        return 1
    filas = procesar(por_ip)
    if a.salida:
        with open(a.salida, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(filas[0]))
            w.writeheader()
            w.writerows(filas)
        print(f"CSV escrito: {a.salida}")
    cuenta = Counter(f["principal"] for f in filas)
    print(f"\n{len(filas)} IPs, {sum(f['eventos'] for f in filas)} eventos\n")
    print("Familia principal".ljust(24) + "IPs".rjust(6) + "  %")
    for nombre in ORDEN:
        if cuenta[nombre]:
            print(nombre.ljust(24) + str(cuenta[nombre]).rjust(6) + f"  {100 * cuenta[nombre] / len(filas):.0f}%")
    multi = sum(1 for f in filas if "|" in f["etiquetas"])
    print(f"\nIPs con mas de una etiqueta: {multi}")
    if a.evaluar_ml:
        cruce, n = matriz_ml(filas, a.logs)
        print(f"\nClasificador ML vs familias reales ({n} IPs con clasificacion ML):\n")
        if cruce:
            imprimir_matriz(cruce)
        else:
            print("Ninguna IP etiquetada tiene clasificacion en ml_classifications.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
