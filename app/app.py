#!/usr/bin/env python3
"""haproxy-ui: Weboberfläche für haproxy-unraid.

Bearbeitet die Dateien in <appdata>/bearbeiten/ (gemeinsamer Ordner mit dem HAProxy-Container),
zeigt Unterschiede zu aktiv/, stößt Prüfen/Übernehmen/Zurück über eine Auftragsdatei an
(HAProxy-Container führt hap-uebernehmen aus – mit Prüfung und Rücksprung), zeigt die Statistik
von HAProxy und meldet sie optional per MQTT (Discovery) an Home Assistant.
Nur Python-Standardbibliothek; MQTT über paho-mqtt (optional).
"""
import base64, csv, difflib, hashlib, hmac, io, json, os, re, secrets, shutil, subprocess
import threading, time, urllib.request
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

D = os.environ.get("HAPROXY_DIR", "/haproxy")
BEARB = os.path.join(D, "bearbeiten")
AKTIV = os.path.join(D, "aktiv")
UIDIR = os.path.join(D, ".ui")
PORT = int(os.environ.get("UI_PORT", "8080"))
UI_PASS = os.environ.get("UI_PASS", "")
HAP_URL = os.environ.get("HAP_URL", "").rstrip("/")          # z. B. http://<IP_HAProxy>:8404
STATS_USER = os.environ.get("STATS_USER", "admin")
STATS_PASS = os.environ.get("STATS_PASS", "")
MQTT_HOST = os.environ.get("MQTT_HOST", "")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "")
MQTT_PASS = os.environ.get("MQTT_PASS", "")
MQTT_INTERVALL = int(os.environ.get("MQTT_INTERVALL", "60"))
MQTT_PREFIX = os.environ.get("MQTT_PREFIX", "homeassistant")
GERAET = os.environ.get("HA_GERAET", "haproxy")
HERE = os.path.dirname(os.path.abspath(__file__))

ERLAUBT = re.compile(r"^(haproxy\.cfg|dienste\.cfg|listen/[A-Za-z0-9._-]+\.(lst|map))$")
SESSIONS = {}           # token -> ablauf
SESSION_DAUER = 12 * 3600
FEHLVERSUCHE = {}       # ip -> [anzahl, seit]


def log(*a):
    print("[haproxy-ui]", *a, flush=True)


# ------------------------------------------------------------------ Dateien
def pfad(rel, basis=BEARB):
    if rel == "certs.conf":
        return os.path.join(D, "certs.conf")
    if not ERLAUBT.match(rel or ""):
        raise ValueError("Datei nicht erlaubt")
    return os.path.join(basis, rel)


def lesen(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def schreiben(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    text = text.replace("\r\n", "\n")
    if not text.endswith("\n"):
        text += "\n"
    tmp = p + ".ui-neu"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if os.path.exists(p):
        shutil.copymode(p, tmp)
    os.replace(tmp, p)


def dateiliste():
    out = []
    for basis, _, files in os.walk(BEARB):
        for n in sorted(files):
            rel = os.path.relpath(os.path.join(basis, n), BEARB).replace("\\", "/")
            if ERLAUBT.match(rel):
                out.append(rel)
    out.sort(key=lambda r: (r.count("/"), r))
    if os.path.exists(os.path.join(D, "certs.conf")):
        out.append("certs.conf")
    return out


def unterschiede():
    teile = []
    namen = set()
    for basis in (BEARB, AKTIV):
        for b, _, files in os.walk(basis):
            for n in files:
                rel = os.path.relpath(os.path.join(b, n), basis).replace("\\", "/")
                if ERLAUBT.match(rel):
                    namen.add(rel)
    for rel in sorted(namen):
        a = lesen(os.path.join(AKTIV, rel)).splitlines(keepends=True)
        b = lesen(os.path.join(BEARB, rel)).splitlines(keepends=True)
        if a != b:
            teile.append("".join(difflib.unified_diff(a, b, "aktiv/" + rel, "bearbeiten/" + rel)))
    return "\n".join(teile)


# ------------------------------------------------------------------ dienste.map
MAP_REL = "listen/dienste.map"


def dienste_lesen():
    zeilen = []
    for z in lesen(pfad(MAP_REL)).splitlines():
        s = z.strip()
        if not s or s.startswith("#"):
            continue
        teile = s.split()
        if len(teile) < 2:
            continue
        be, zugang, modus = (teile[1].split(":") + ["", ""])[:3]
        kommentar = s.split("#", 1)[1].strip() if "#" in s else ""
        zeilen.append({"name": teile[0], "backend": be, "zugang": zugang, "modus": modus, "notiz": kommentar})
    return zeilen


def dienste_schreiben(liste):
    # Kopfkommentar behalten (nur der Block am Anfang)
    # auskommentierte Beispiele weiter unten bleiben am Ende erhalten
    alt = lesen(pfad(MAP_REL)).splitlines()
    kopf, rest, im_kopf = [], [], True
    for z in alt:
        if z.strip().startswith("#") or not z.strip():
            (kopf if im_kopf else rest).append(z)
        else:
            im_kopf = False
    while rest and not rest[0].strip():
        rest.pop(0)
    neu = []
    for d in liste:
        name = str(d.get("name", "")).strip().lower()
        be = str(d.get("backend", "")).strip()
        zug = str(d.get("zugang", "")).strip()
        mod = str(d.get("modus", "")).strip()
        notiz = str(d.get("notiz", "")).strip().replace("\n", " ")
        if not re.match(r"^[a-z0-9*][a-z0-9.*-]*$", name):
            raise ValueError(f"Name ungültig: {name!r}")
        if not re.match(r"^[A-Za-z0-9_.-]+$", be):
            raise ValueError(f"Backend ungültig: {be!r}")
        if zug not in ("alle", "intern") or mod not in ("tls", "durch"):
            raise ValueError(f"{name}: Zugang alle|intern, Modus tls|durch")
        z = f"{name:<32} {be}:{zug}:{mod}"
        if notiz:
            z += f"   # {notiz}"
        neu.append(z)
    schreiben(pfad(MAP_REL), "\n".join(kopf + neu + ([""] + rest if rest else [])))


def backends():
    namen = []
    for rel in ("haproxy.cfg", "dienste.cfg"):
        for z in lesen(pfad(rel)).splitlines():
            m = re.match(r"^\s*backend\s+(\S+)", z)
            if m:
                namen.append(m.group(1))
    return namen


# ------------------------------------------------------------------ Aufträge an den HAProxy-Container
AKTIONEN = {"pruefen", "uebernehmen", "zurueck", "zertifikate"}


def auftrag_stellen(aktion):
    if aktion not in AKTIONEN:
        raise ValueError("unbekannte Aktion")
    os.makedirs(UIDIR, exist_ok=True)
    if os.path.exists(os.path.join(UIDIR, "auftrag")):
        raise ValueError("Es läuft noch ein Auftrag")
    aid = f"{int(time.time())}-{secrets.token_hex(3)}"
    tmp = os.path.join(UIDIR, "auftrag.neu")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{aid} {aktion}\n")
    os.replace(tmp, os.path.join(UIDIR, "auftrag"))
    return aid


def auftrag_ergebnis():
    laeuft = os.path.exists(os.path.join(UIDIR, "auftrag"))
    text = lesen(os.path.join(UIDIR, "ergebnis"))
    erg = None
    if text:
        kopf, _, rest = text.partition("\n")
        t = kopf.split()
        if len(t) >= 4:
            erg = {"id": t[0], "aktion": t[1], "code": int(t[2]) if t[2].lstrip("-").isdigit() else -1,
                   "zeit": t[3], "log": rest}
    waechter = os.path.join(UIDIR, "waechter")
    try:
        waechter_ok = time.time() - os.path.getmtime(waechter) < 30
    except OSError:
        waechter_ok = False
    return {"laeuft": laeuft, "ergebnis": erg, "waechter": waechter_ok}


# ------------------------------------------------------------------ Statistik
def stats():
    if not HAP_URL:
        return {"fehler": "HAP_URL nicht gesetzt", "zeilen": []}
    req = urllib.request.Request(HAP_URL + "/;csv;norefresh")
    if STATS_PASS:
        tok = base64.b64encode(f"{STATS_USER}:{STATS_PASS}".encode()).decode()
        req.add_header("Authorization", "Basic " + tok)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return {"fehler": f"HAProxy nicht erreichbar: {e}", "zeilen": []}
    text = text.lstrip("# ")
    zeilen = []
    for z in csv.DictReader(io.StringIO(text)):
        def zahl(k):
            try:
                return int(z.get(k) or 0)
            except ValueError:
                return 0
        zeilen.append({
            "proxy": z.get("pxname"), "name": z.get("svname"), "status": z.get("status"),
            "typ": {"0": "frontend", "1": "backend", "2": "server", "3": "listener"}.get(z.get("type"), "?"),
            "scur": zahl("scur"), "smax": zahl("smax"), "stot": zahl("stot"),
            "bin": zahl("bin"), "bout": zahl("bout"), "rate": zahl("rate"),
            "req_rate": zahl("req_rate"), "ereq": zahl("ereq"), "econ": zahl("econ"),
            "hrsp_4xx": zahl("hrsp_4xx"), "hrsp_5xx": zahl("hrsp_5xx"),
            "check": z.get("check_status") or "", "lastchg": zahl("lastchg"),
        })
    return {"fehler": None, "zeilen": [r for r in zeilen if r["typ"] != "listener"]}


def zertifikate():
    out = []
    cdir = os.path.join(D, "certs")
    try:
        namen = sorted(n for n in os.listdir(cdir) if n.endswith(".pem"))
    except OSError:
        return out
    for n in namen:
        p = os.path.join(cdir, n)
        try:
            r = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-subject", "-ext", "subjectAltName",
                                "-in", p], capture_output=True, text=True, timeout=10)
            txt = r.stdout
            m = re.search(r"notAfter=(.+)", txt)
            ende = datetime.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z") \
                .replace(tzinfo=timezone.utc) if m else None
            cn = (re.search(r"CN\s*=\s*([^,\n]+)", txt) or [None, ""])[1]
            sans = re.findall(r"DNS:([^,\s]+)", txt)
            tage = int((ende - datetime.now(timezone.utc)).total_seconds() // 86400) if ende else None
            out.append({"datei": n, "cn": cn.strip(), "namen": sans, "ende": ende.isoformat() if ende else None,
                        "tage": tage})
        except Exception as e:  # noqa: BLE001
            out.append({"datei": n, "fehler": str(e)})
    return out


def zustand():
    s = stats()
    return {
        "stats": s, "zertifikate": zertifikate(), "auftrag": auftrag_ergebnis(),
        "offen": bool(unterschiede()), "mqtt": MQTT_STATUS, "hap_url": HAP_URL,
    }


# ------------------------------------------------------------------ MQTT / Home Assistant
MQTT_STATUS = {"aktiv": bool(MQTT_HOST), "verbunden": False, "fehler": None}


def slug(s):
    return re.sub(r"[^a-z0-9_]+", "_", s.lower()).strip("_")


def mqtt_schleife():
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        MQTT_STATUS["fehler"] = "paho-mqtt fehlt"
        return
    basis = f"haproxy_ui/{slug(GERAET)}"
    verf = f"{basis}/verfuegbar"
    try:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"haproxy-ui-{slug(GERAET)}")
    except AttributeError:
        c = mqtt.Client(client_id=f"haproxy-ui-{slug(GERAET)}")
    if MQTT_USER:
        c.username_pw_set(MQTT_USER, MQTT_PASS)
    c.will_set(verf, "offline", retain=True)

    def verbunden(*a):
        MQTT_STATUS["verbunden"] = True
        MQTT_STATUS["fehler"] = None
        c.publish(verf, "online", retain=True)
        bekannt.clear()

    def getrennt(*a):
        MQTT_STATUS["verbunden"] = False

    c.on_connect = verbunden
    c.on_disconnect = getrennt
    bekannt = set()
    geraet = {"identifiers": [f"haproxy_ui_{slug(GERAET)}"], "name": f"HAProxy {GERAET}",
              "manufacturer": "haproxy-unraid", "model": "HAProxy + haproxy-ui"}

    def entdecken(komp, oid, name, extra):
        key = f"{komp}/{oid}"
        if key in bekannt:
            return
        cfg = {"name": name, "unique_id": f"haproxy_ui_{slug(GERAET)}_{oid}", "object_id": f"haproxy_{oid}",
               "state_topic": f"{basis}/{oid}", "availability_topic": verf, "device": geraet}
        cfg.update(extra)
        c.publish(f"{MQTT_PREFIX}/{komp}/haproxy_ui_{slug(GERAET)}/{oid}/config", json.dumps(cfg), retain=True)
        bekannt.add(key)

    while True:
        try:
            if not MQTT_STATUS["verbunden"]:
                try:
                    c.connect(MQTT_HOST, MQTT_PORT, 60)
                    c.loop_start()
                    time.sleep(2)
                except Exception as e:  # noqa: BLE001
                    MQTT_STATUS["fehler"] = str(e)
                    time.sleep(MQTT_INTERVALL)
                    continue
            s = stats()
            entdecken("binary_sensor", "erreichbar", "Erreichbar",
                      {"device_class": "connectivity", "payload_on": "ON", "payload_off": "OFF"})
            c.publish(f"{basis}/erreichbar", "OFF" if s["fehler"] else "ON", retain=True)
            for r in s["zeilen"]:
                if r["typ"] == "server":
                    continue
                oid = slug(f"{r['proxy']}_{r['typ']}")
                attr_t = f"{basis}/{oid}/attr"
                entdecken("sensor", oid + "_status", f"{r['proxy']} Status",
                          {"icon": "mdi:lan-connect", "json_attributes_topic": attr_t})
                entdecken("sensor", oid + "_sitzungen", f"{r['proxy']} Sitzungen",
                          {"state_class": "measurement", "icon": "mdi:account-multiple"})
                entdecken("sensor", oid + "_rate", f"{r['proxy']} Rate",
                          {"state_class": "measurement", "unit_of_measurement": "1/s", "icon": "mdi:speedometer"})
                entdecken("sensor", oid + "_gesamt", f"{r['proxy']} Verbindungen gesamt",
                          {"state_class": "total_increasing", "icon": "mdi:counter"})
                c.publish(f"{basis}/{oid}_status", r["status"] or "?", retain=True)
                c.publish(f"{basis}/{oid}_sitzungen", r["scur"], retain=True)
                c.publish(f"{basis}/{oid}_rate", r["rate"], retain=True)
                c.publish(f"{basis}/{oid}_gesamt", r["stot"], retain=True)
                c.publish(attr_t, json.dumps({k: r[k] for k in ("bin", "bout", "smax", "ereq", "econ",
                                                                  "hrsp_4xx", "hrsp_5xx", "req_rate")}), retain=True)
            for z in zertifikate():
                if z.get("tage") is None:
                    continue
                oid = "zert_" + slug(z["datei"][:-4])
                entdecken("sensor", oid, f"Zertifikat {z['cn'] or z['datei']}",
                          {"unit_of_measurement": "d", "icon": "mdi:certificate",
                           "json_attributes_topic": f"{basis}/{oid}/attr"})
                c.publish(f"{basis}/{oid}", z["tage"], retain=True)
                c.publish(f"{basis}/{oid}/attr", json.dumps({"ende": z["ende"], "namen": z["namen"]}), retain=True)
            entdecken("binary_sensor", "aenderungen_offen", "Änderungen nicht übernommen",
                      {"icon": "mdi:file-document-edit", "payload_on": "ON", "payload_off": "OFF"})
            c.publish(f"{basis}/aenderungen_offen", "ON" if unterschiede() else "OFF", retain=True)
            a = auftrag_ergebnis()["ergebnis"]
            if a:
                entdecken("sensor", "letzter_auftrag", "Letzter Auftrag",
                          {"icon": "mdi:check-decagram", "json_attributes_topic": f"{basis}/letzter_auftrag/attr"})
                c.publish(f"{basis}/letzter_auftrag", f"{a['aktion']}: {'OK' if a['code'] == 0 else 'Fehler'}",
                          retain=True)
                c.publish(f"{basis}/letzter_auftrag/attr", json.dumps({"zeit": a["zeit"], "log": a["log"][-2000:]}),
                          retain=True)
        except Exception as e:  # noqa: BLE001
            MQTT_STATUS["fehler"] = str(e)
            log("MQTT:", e)
        time.sleep(MQTT_INTERVALL)


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "haproxy-ui"

    def log_message(self, fmt, *a):
        if os.environ.get("UI_DEBUG"):
            log(self.address_string(), fmt % a)

    # --- Hilfen
    def antwort(self, code, daten, typ="application/json; charset=utf-8", extra=None):
        body = daten if isinstance(daten, bytes) else (
            json.dumps(daten, ensure_ascii=False).encode() if typ.startswith("application/json") else daten.encode())
        self.send_response(code)
        self.send_header("Content-Type", typ)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def daten(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2_000_000:
            raise ValueError("zu groß")
        return json.loads(self.rfile.read(n) or b"{}")

    def angemeldet(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie") or "")
        tok = c.get("hapui")
        if not tok:
            return False
        ab = SESSIONS.get(tok.value)
        if ab and ab > time.time():
            SESSIONS[tok.value] = time.time() + SESSION_DAUER
            return True
        return False

    def gleiche_quelle(self):
        # einfacher CSRF-Schutz: schreibende Anfragen nur mit eigenem Header (setzt fetch() der Seite)
        return self.headers.get("X-HapUI") == "1"

    # --- Routen
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self.antwort(200, lesen(os.path.join(HERE, "index.html")), "text/html; charset=utf-8")
        if u.path == "/gesund":
            return self.antwort(200, {"ok": True})
        if not self.angemeldet():
            return self.antwort(401, {"fehler": "nicht angemeldet"})
        q = parse_qs(u.query)
        try:
            if u.path == "/api/zustand":
                return self.antwort(200, zustand())
            if u.path == "/api/dienste":
                return self.antwort(200, {"dienste": dienste_lesen(), "backends": backends()})
            if u.path == "/api/dateien":
                return self.antwort(200, {"dateien": dateiliste()})
            if u.path == "/api/datei":
                rel = q.get("pfad", [""])[0]
                return self.antwort(200, {"pfad": rel, "text": lesen(pfad(rel))})
            if u.path == "/api/diff":
                return self.antwort(200, {"diff": unterschiede()})
            if u.path == "/api/auftrag":
                return self.antwort(200, auftrag_ergebnis())
        except ValueError as e:
            return self.antwort(400, {"fehler": str(e)})
        self.antwort(404, {"fehler": "unbekannt"})

    def do_POST(self):
        u = urlparse(self.path)
        if not self.gleiche_quelle():
            return self.antwort(403, {"fehler": "Header fehlt"})
        try:
            d = self.daten()
        except Exception:  # noqa: BLE001
            return self.antwort(400, {"fehler": "ungültige Daten"})
        if u.path == "/api/anmelden":
            ip = self.client_address[0]
            n, seit = FEHLVERSUCHE.get(ip, [0, time.time()])
            if n >= 5 and time.time() - seit < 300:
                return self.antwort(429, {"fehler": "Zu viele Versuche – 5 Minuten warten"})
            if UI_PASS and hmac.compare_digest(hashlib.sha256(str(d.get("passwort", "")).encode()).digest(),
                                               hashlib.sha256(UI_PASS.encode()).digest()):
                FEHLVERSUCHE.pop(ip, None)
                tok = secrets.token_urlsafe(32)
                SESSIONS[tok] = time.time() + SESSION_DAUER
                return self.antwort(200, {"ok": True}, extra={
                    "Set-Cookie": f"hapui={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_DAUER}"})
            FEHLVERSUCHE[ip] = [n + 1 if time.time() - seit < 300 else 1, seit if time.time() - seit < 300 else time.time()]
            return self.antwort(403, {"fehler": "Passwort falsch"})
        if not self.angemeldet():
            return self.antwort(401, {"fehler": "nicht angemeldet"})
        try:
            if u.path == "/api/abmelden":
                c = cookies.SimpleCookie(self.headers.get("Cookie") or "")
                if c.get("hapui"):
                    SESSIONS.pop(c["hapui"].value, None)
                return self.antwort(200, {"ok": True}, extra={"Set-Cookie": "hapui=; Path=/; Max-Age=0"})
            if u.path == "/api/dienste":
                dienste_schreiben(d.get("dienste", []))
                return self.antwort(200, {"ok": True})
            if u.path == "/api/datei":
                schreiben(pfad(d.get("pfad", "")), str(d.get("text", "")))
                return self.antwort(200, {"ok": True})
            if u.path == "/api/neue-liste":
                name = str(d.get("name", ""))
                if not re.match(r"^[A-Za-z0-9_-]+\.(lst|map)$", name):
                    raise ValueError("Name: buchstaben-zahlen.lst oder .map")
                p = pfad("listen/" + name)
                if os.path.exists(p):
                    raise ValueError("Datei gibt es schon")
                schreiben(p, f"# {name}\n")
                return self.antwort(200, {"ok": True, "pfad": "listen/" + name})
            if u.path == "/api/verwerfen":
                for rel in dateiliste():
                    if rel == "certs.conf":
                        continue
                    a = os.path.join(AKTIV, rel)
                    if os.path.exists(a):
                        schreiben(os.path.join(BEARB, rel), lesen(a))
                    else:
                        os.remove(os.path.join(BEARB, rel))
                return self.antwort(200, {"ok": True})
            if u.path == "/api/auftrag":
                return self.antwort(200, {"id": auftrag_stellen(str(d.get("aktion", "")))})
        except ValueError as e:
            return self.antwort(400, {"fehler": str(e)})
        self.antwort(404, {"fehler": "unbekannt"})


def main():
    if not UI_PASS or "<" in UI_PASS:
        raise SystemExit("[haproxy-ui] FEHLER: UI_PASS in der Unraid-Vorlage setzen")
    if not os.path.isdir(BEARB):
        log(f"Hinweis: {BEARB} fehlt noch – startet haproxy-unraid mit demselben Ordner?")
    if MQTT_HOST:
        threading.Thread(target=mqtt_schleife, daemon=True).start()
        log(f"MQTT an {MQTT_HOST}:{MQTT_PORT} alle {MQTT_INTERVALL}s")
    log(f"Weboberfläche auf Port {PORT}, Konfiguration {D}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
