"""Baukasten für haproxy-ui: Dienste (Adresse -> Zugang -> Backend -> Regeln) als Daten
speichern und daraus die HAProxy-Konfiguration erzeugen.

Gespeichert in bearbeiten/baukasten.json; erzeugt werden
  - die Zeile in listen/dienste.map           (Name Backend:Zugang:Modus)
  - der Backend-Block in dienste.cfg          (zwischen ">>> haproxy-ui: backends" und "<<<")
  - die Regeln in haproxy.cfg                  (Blöcke regeln-tcp / regeln-pruefen / regeln-aktionen)
Alles außerhalb der markierten Blöcke bleibt unangetastet (eigene Backends, Handarbeit).
"""
import ipaddress
import json
import re

ZUGAENGE = ("alle", "intern", "extern")
MODI = ("tls", "durch")
WER = ("alle", "extern", "intern", "quelle", "nicht_quelle", "liste", "nicht_liste")
PFAD_ARTEN = ("alle", "beginnt", "genau", "nicht_beginnt")
AKTIONEN_HTTP = ("sperren", "umleiten", "backend", "header_anfrage", "header_antwort", "header_entfernen")
VERTEILUNG = ("roundrobin", "leastconn", "source", "first")

RE_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
RE_BACKEND = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
RE_ADRESSE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\$\{[A-Z_][A-Z0-9_]*\})$")
RE_PFAD = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
RE_HEADER = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
RE_LISTE = re.compile(r"^listen/[A-Za-z0-9._-]+\.lst$")
RE_URL = re.compile(r"^https?://[^\s\"'\\<>]+$")

M_ANF = "# >>> haproxy-ui: "
M_END = "# <<< haproxy-ui: "


class Fehler(ValueError):
    pass


# ------------------------------------------------------------------ Daten
def leer():
    return {"version": 1, "dienste": {}, "backends": {}}


def laden(text):
    try:
        d = json.loads(text) if text.strip() else leer()
    except json.JSONDecodeError:
        d = leer()
    d.setdefault("dienste", {})
    d.setdefault("backends", {})
    return d


def speichern_text(daten):
    return json.dumps(daten, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


# ------------------------------------------------------------------ Prüfen
def _ips(text):
    werte = [w for w in re.split(r"[\s,;]+", str(text or "").strip()) if w]
    if not werte:
        raise Fehler("Bitte mindestens eine IP-Adresse oder ein Netz angeben")
    for w in werte:
        try:
            ipaddress.ip_network(w, strict=False)
        except ValueError:
            raise Fehler(f"Keine gültige IP / kein Netz: {w}")
    return werte


def _wert(text, feld):
    s = str(text or "")
    if any(c in s for c in "\r\n\0"):
        raise Fehler(f"{feld}: keine Zeilenumbrüche")
    if len(s) > 500:
        raise Fehler(f"{feld}: zu lang")
    return s


def regel_pruefen(r, modus, backends_modus):
    r = dict(r or {})
    wer = r.get("wer", "alle")
    if wer not in WER:
        raise Fehler(f"Bedingung „wer“ unbekannt: {wer}")
    out = {"wer": wer, "aktiv": bool(r.get("aktiv", True)), "notiz": _wert(r.get("notiz", ""), "Notiz")[:120]}
    if wer in ("quelle", "nicht_quelle"):
        out["quellen"] = " ".join(_ips(r.get("quellen")))
    if wer in ("liste", "nicht_liste"):
        liste = str(r.get("liste", ""))
        if not RE_LISTE.match(liste):
            raise Fehler("Liste: Datei listen/<name>.lst wählen")
        out["liste"] = liste
    pfad_art = r.get("pfad_art", "alle")
    if pfad_art not in PFAD_ARTEN:
        raise Fehler(f"Pfad-Bedingung unbekannt: {pfad_art}")
    out["pfad_art"] = pfad_art
    if pfad_art != "alle":
        p = str(r.get("pfad", "")).strip()
        if not RE_PFAD.match(p):
            raise Fehler(f"Pfad muss mit / beginnen und darf keine Leerzeichen enthalten: {p!r}")
        out["pfad"] = p
    aktion = r.get("aktion", "sperren")
    if modus == "durch":
        if aktion != "sperren":
            raise Fehler("Beim Durchreichen (verschlüsselt) sind nur Sperr-Regeln möglich")
        if pfad_art != "alle":
            raise Fehler("Beim Durchreichen sieht HAProxy keinen Pfad – Pfad-Bedingung entfernen")
    if aktion not in AKTIONEN_HTTP:
        raise Fehler(f"Aktion unbekannt: {aktion}")
    out["aktion"] = aktion
    if aktion == "sperren":
        code = int(r.get("code") or 403)
        if code not in (403, 404, 429, 503):
            raise Fehler("Sperr-Antwort: 403, 404, 429 oder 503")
        out["code"] = code
    elif aktion == "umleiten":
        ziel = str(r.get("ziel", "")).strip()
        art = r.get("umleiten_art", "adresse")
        if art not in ("adresse", "praefix"):
            raise Fehler("Umleitung: Art adresse|praefix")
        if not RE_URL.match(ziel):
            raise Fehler("Umleitung: Ziel als https://… ohne Leerzeichen angeben")
        if art == "praefix" and ziel.rstrip("/") != ziel:
            ziel = ziel.rstrip("/")
        code = int(r.get("code") or 302)
        if code not in (301, 302, 307, 308):
            raise Fehler("Umleitung: Code 301, 302, 307 oder 308")
        out.update(ziel=ziel, umleiten_art=art, code=code)
    elif aktion == "backend":
        be = str(r.get("ziel", "")).strip()
        if not RE_BACKEND.match(be):
            raise Fehler("Anderes Backend: Namen wählen")
        if be in backends_modus and backends_modus[be] != "http":
            raise Fehler(f"Backend {be} ist mode {backends_modus[be]} – für Pfad-Weiterleitung muss es mode http sein")
        out["ziel"] = be
    else:
        h = str(r.get("header", "")).strip()
        if not RE_HEADER.match(h):
            raise Fehler(f"Header-Name ungültig: {h!r}")
        out["header"] = h
        if aktion != "header_entfernen":
            out["wert"] = _wert(r.get("wert", ""), "Header-Wert")
    return out


def backend_pruefen(name, b, modus):
    if not RE_BACKEND.match(name or ""):
        raise Fehler(f"Backend-Name ungültig: {name!r} (Buchstaben, Zahlen, _ . -)")
    b = dict(b or {})
    server = []
    for i, s in enumerate(b.get("server") or []):
        adr = str(s.get("adresse", "")).strip()
        if not adr:
            continue
        if not RE_ADRESSE.match(adr):
            try:
                ipaddress.ip_address(adr)
            except ValueError:
                raise Fehler(f"Server {i + 1}: Adresse ungültig: {adr!r}")
        try:
            port = int(s.get("port"))
        except (TypeError, ValueError):
            raise Fehler(f"Server {i + 1}: Port fehlt")
        if not 1 <= port <= 65535:
            raise Fehler(f"Server {i + 1}: Port 1–65535")
        server.append({"adresse": adr, "port": port, "https": bool(s.get("https")) and modus == "tls",
                       "pruefen": bool(s.get("pruefen", True)), "reserve": bool(s.get("reserve"))})
    if not server:
        raise Fehler("Mindestens einen Server (Adresse + Port) angeben")
    out = {"modus": modus, "server": server, "notiz": _wert(b.get("notiz", ""), "Notiz")[:200],
           "vorlage": str(b.get("vorlage", ""))[:40], "lange_verbindungen": bool(b.get("lange_verbindungen"))}
    v = b.get("verteilung", "roundrobin")
    if v not in VERTEILUNG:
        raise Fehler("Lastverteilung unbekannt")
    out["verteilung"] = v
    if modus == "tls":
        cp = str(b.get("check_pfad", "") or "").strip()
        if cp and not RE_PFAD.match(cp):
            raise Fehler("Prüf-Pfad muss mit / beginnen")
        out["check_pfad"] = cp
        st = str(b.get("check_status", "") or "").strip()
        if st and not re.match(r"^[1-5][0-9]{2}(-[1-5][0-9]{2})?$", st):
            raise Fehler("Erwarteter Status: z. B. 200 oder 200-399")
        out["check_status"] = st
        hh = str(b.get("host_header", "") or "").strip().lower()
        if hh and not re.match(r"^[a-z0-9.-]+(:[0-9]+)?$", hh):
            raise Fehler("Host-Header ungültig")
        out["host_header"] = hh
        out["forwarded_port"] = bool(b.get("forwarded_port"))
        out["sticky"] = bool(b.get("sticky"))
        to = str(b.get("timeout_server", "") or "").strip()
        if to and not re.match(r"^[0-9]+(ms|s|m|h)$", to):
            raise Fehler("Zeitlimit: z. B. 60s, 5m, 1h")
        out["timeout_server"] = to
    return out


def eintrag_pruefen(e, backends_modus, verwaltet):
    """e = {name, zugang, modus, notiz, backend, backend_neu (bool), backend_def, regeln}"""
    name = str(e.get("name", "")).strip().lower().rstrip(".")
    if not RE_NAME.match(name):
        raise Fehler(f"Adresse ungültig: {name!r} (z. B. dienst.example.de)")
    zugang = e.get("zugang")
    modus = e.get("modus")
    if zugang not in ZUGAENGE:
        raise Fehler("Zugang: intern, extern oder alle")
    if modus not in MODI:
        raise Fehler("Modus: tls oder durch")
    be = str(e.get("backend", "")).strip()
    if not RE_BACKEND.match(be):
        raise Fehler("Backend-Name fehlt oder ist ungültig")
    out = {"name": name, "zugang": zugang, "modus": modus, "backend": be,
           "notiz": _wert(e.get("notiz", ""), "Notiz")[:120].replace("#", "")}
    bm = dict(backends_modus)
    if e.get("backend_neu"):
        if be in backends_modus and be not in verwaltet:
            raise Fehler(f"Backend {be} gibt es schon (von Hand in dienste.cfg) – anderen Namen wählen "
                         f"oder „vorhandenes Backend“ nehmen")
        out["backend_def"] = backend_pruefen(be, e.get("backend_def"), modus)
        bm[be] = "http" if modus == "tls" else "tcp"
    else:
        if be not in backends_modus:
            raise Fehler(f"Backend {be} gibt es nicht")
        want = "http" if modus == "tls" else "tcp"
        if backends_modus[be] != want:
            raise Fehler(f"Backend {be} hat mode {backends_modus[be]}, Modus {modus} braucht mode {want}")
    out["regeln"] = [regel_pruefen(r, modus, bm) for r in (e.get("regeln") or [])]
    return out


# ------------------------------------------------------------------ Erzeugen
def _q(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _bed(r, ebene):
    """HAProxy-Bedingung aus einer Regel (ohne Dienstname)."""
    teile = []
    wer = r["wer"]
    if wer == "extern":
        teile.append("!intern")
    elif wer == "intern":
        teile.append("intern")
    elif wer == "quelle":
        teile.append("{ src " + r["quellen"] + " }")
    elif wer == "nicht_quelle":
        teile.append("!{ src " + r["quellen"] + " }")
    elif wer == "liste":
        teile.append("{ src -f " + r["liste"] + " }")
    elif wer == "nicht_liste":
        teile.append("!{ src -f " + r["liste"] + " }")
    if ebene == "http":
        art = r.get("pfad_art", "alle")
        if art == "beginnt":
            teile.append("{ var(txn.pfad) -m beg " + r["pfad"] + " }")
        elif art == "nicht_beginnt":
            teile.append("!{ var(txn.pfad) -m beg " + r["pfad"] + " }")
        elif art == "genau":
            teile.append("{ var(txn.pfad) -m str " + r["pfad"] + " }")
    return " ".join(teile)


def regel_text(r):
    """Kurzbeschreibung in Worten (für Kommentar und Oberfläche)."""
    wer = {"alle": "alle", "extern": "von außen", "intern": "von innen",
           "quelle": f"von {r.get('quellen', '')}", "nicht_quelle": f"nicht von {r.get('quellen', '')}",
           "liste": f"aus {r.get('liste', '')}", "nicht_liste": f"nicht aus {r.get('liste', '')}"}[r["wer"]]
    pfad = {"alle": "", "beginnt": f", Pfad beginnt mit {r.get('pfad')}",
            "nicht_beginnt": f", Pfad beginnt nicht mit {r.get('pfad')}",
            "genau": f", Pfad genau {r.get('pfad')}"}[r.get("pfad_art", "alle")]
    a = r["aktion"]
    tat = {"sperren": f"sperren ({r.get('code', 403)})",
           "umleiten": f"umleiten nach {r.get('ziel')}{' (+Pfad)' if r.get('umleiten_art') == 'praefix' else ''}",
           "backend": f"an {r.get('ziel')}",
           "header_anfrage": f"Header {r.get('header')} an Ziel setzen",
           "header_antwort": f"Header {r.get('header')} in Antwort setzen",
           "header_entfernen": f"Header {r.get('header')} aus Antwort entfernen"}[a]
    if r["wer"] == "alle" and not pfad:
        return f"immer: {tat}"
    return f"wenn {wer}{pfad}: {tat}".replace("wenn alle, ", "wenn ")


def regeln_erzeugen(daten, map_zeilen):
    """-> {"regeln-tcp": [...], "regeln-pruefen": [...], "regeln-aktionen": [...]}"""
    out = {"regeln-tcp": [], "regeln-pruefen": [], "regeln-aktionen": []}
    weiter = []   # use_backend-Zeilen kommen ans Ende (HAProxy wertet http-request-Regeln immer vorher aus)
    modus_von = {z["name"]: z["modus"] for z in map_zeilen}
    for name in sorted(daten["dienste"]):
        if name not in modus_von:
            continue
        modus = modus_von[name]
        regeln = [r for r in daten["dienste"][name].get("regeln", []) if r.get("aktiv", True)]
        if not regeln:
            continue
        for i, r in enumerate(regeln, 1):
            kopf = f"    # {name} #{i}: {regel_text(r)}"
            if modus == "durch":
                if r["aktion"] != "sperren":
                    continue
                bed = " ".join(x for x in ["{ var(sess.sni) -m str " + name + " }", _bed(r, "tcp")] if x)
                out["regeln-tcp"] += [kopf, f"    tcp-request content set-var(sess.grund) str(regel) if !hat_grund {bed}"]
                continue
            bed = " ".join(x for x in ["{ var(txn.host) -m str " + name + " }", _bed(r, "http")] if x)
            a = r["aktion"]
            if a == "sperren":
                grund = {403: "regel", 404: "regel_404", 429: "regel_429", 503: "regel_503"}[r.get("code", 403)]
                out["regeln-pruefen"] += [kopf, f"    http-request set-var(txn.grund) str({grund}) if !hat_grund {bed}"]
            elif a == "umleiten":
                art = "prefix" if r.get("umleiten_art") == "praefix" else "location"
                out["regeln-aktionen"] += [kopf, f"    http-request redirect {art} {_q(r['ziel'])} code {r['code']} if {bed}"]
            elif a == "backend":
                weiter += [kopf, f"    use_backend {r['ziel']} if {bed}"]
            elif a == "header_anfrage":
                out["regeln-aktionen"] += [kopf, f"    http-request set-header {r['header']} {_q(r.get('wert', ''))} if {bed}"]
            elif a == "header_antwort":
                out["regeln-aktionen"] += [kopf, f"    http-response set-header {r['header']} {_q(r.get('wert', ''))} if {bed}"]
            elif a == "header_entfernen":
                out["regeln-aktionen"] += [kopf, f"    http-response del-header {r['header']} if {bed}"]
    out["regeln-aktionen"] += weiter
    # Sperren mit anderem Code als 403 brauchen eigene deny-Zeilen (403 macht die Vorlage schon)
    extra = []
    for code in (404, 429, 503):
        if any(f"str(regel_{code})" in z for z in out["regeln-pruefen"]):
            extra.append(f"    http-request deny deny_status {code} if {{ var(txn.grund) -m str regel_{code} }}")
    if extra:
        out["regeln-pruefen"] += ["    # Antwortcodes der Sperr-Regeln",
                                  "    http-request set-var(txn.aktion) str(abgelehnt) if { var(txn.grund) -m beg regel_ }"] + extra
    return out


def backend_erzeugen(name, b, nutzer=()):
    z = [f"# {name}" + (f" – {b['notiz']}" if b.get("notiz") else "") +
         (f"  (für {', '.join(sorted(nutzer))})" if nutzer else ""),
         f"backend {name}"]
    if b["modus"] == "tls":
        z.append("    mode http")
    else:
        z.append("    mode tcp")
    if len(b["server"]) > 1:
        z.append(f"    balance {b.get('verteilung', 'roundrobin')}")
    if b["modus"] == "tls":
        if b.get("check_pfad"):
            z.append(f"    option httpchk GET {b['check_pfad']}")
            if b.get("check_status"):
                z.append(f"    http-check expect status {b['check_status']}")
        if b.get("host_header"):
            z.append(f"    http-request set-header Host {b['host_header']}")
        if b.get("forwarded_port"):
            z.append("    http-request set-header X-Forwarded-Port 443")
        if b.get("sticky") and len(b["server"]) > 1:
            z.append("    cookie HAPSRV insert indirect nocache httponly secure")
        if b.get("timeout_server"):
            z.append(f"    timeout server {b['timeout_server']}")
    if b.get("lange_verbindungen"):
        if not (b["modus"] == "tls" and b.get("timeout_server")):
            z.append("    timeout server 1h")
        z.append("    timeout tunnel 1h")
    for i, s in enumerate(b["server"], 1):
        adr = s["adresse"]
        if ":" in adr and not adr.startswith("${"):
            ziel = f"[{adr}]:{s['port']}"
        elif adr.startswith("${"):
            ziel = f'"{adr}:{s["port"]}"'
        else:
            ziel = f"{adr}:{s['port']}"
        opt = []
        if s.get("https"):
            opt.append("ssl verify none")
        if s.get("pruefen", True):
            opt.append("check")
        if s.get("reserve"):
            opt.append("backup")
        if b.get("sticky") and len(b["server"]) > 1 and b["modus"] == "tls":
            opt.append(f"cookie s{i}")
        z.append(f"    server s{i} {ziel}" + ("" if not opt else " " + " ".join(opt)))
    return "\n".join(z)


def backends_erzeugen(daten, map_zeilen):
    benutzt = {}
    for zl in map_zeilen:
        benutzt.setdefault(zl["backend"], set()).add(zl["name"])
    for d in daten["dienste"].values():
        for r in d.get("regeln", []):
            if r.get("aktion") == "backend":
                benutzt.setdefault(r["ziel"], set())
    bloecke = []
    for name in sorted(daten["backends"]):
        if name not in benutzt:
            continue
        bloecke.append(backend_erzeugen(name, daten["backends"][name], benutzt[name]))
    return "\n\n".join(bloecke)


# ------------------------------------------------------------------ Blöcke in Dateien ersetzen
def block_ersetzen(text, marke, inhalt, anhaengen=False):
    """Ersetzt die Zeilen zwischen '# >>> haproxy-ui: <marke>' und '# <<< haproxy-ui: <marke>'."""
    zeilen = text.split("\n")
    a = next((i for i, z in enumerate(zeilen) if z.strip().startswith(M_ANF + marke)), None)
    e = next((i for i, z in enumerate(zeilen) if z.strip().startswith(M_END + marke)), None)
    if a is None or e is None or e < a:
        if not anhaengen:
            raise Fehler(f"Markierung „{marke}“ fehlt in der Datei – haproxy.cfg vorbereiten lassen")
        while zeilen and zeilen[-1] == "":
            zeilen.pop()
        zeilen += ["", f"{M_ANF}{marke} (automatisch erzeugt – über den Assistenten in haproxy-ui ändern)",
                   f"{M_END}{marke}", ""]
        a, e = len(zeilen) - 3, len(zeilen) - 2
    einr = re.match(r"^\s*", zeilen[a]).group(0)
    neu = [z for z in (inhalt.split("\n") if inhalt else [])]
    return "\n".join(zeilen[:a + 1] + neu + [einr + zeilen[e].strip()] + zeilen[e + 1:])


def cfg_vorbereiten(text):
    """Bringt eine ältere haproxy.cfg auf den Stand mit Zugang 'extern' und den Regel-Markierungen.
    Gibt (text, liste_der_änderungen) zurück; wirft Fehler, wenn die Ankerzeilen fehlen."""
    geaendert = []
    zeilen = text.split("\n")

    def finde(muster, ab=0):
        for i in range(ab, len(zeilen)):
            if re.match(muster, zeilen[i]):
                return i
        return None

    def nach(i, neu):
        einr = re.match(r"^\s*", zeilen[i]).group(0)
        for k, z in enumerate(neu, 1):
            zeilen.insert(i + k, einr + z)

    def vor(i, neu):
        einr = re.match(r"^\s*", zeilen[i]).group(0)
        for k, z in enumerate(neu):
            zeilen.insert(i + k, einr + z)

    t = "\n".join(zeilen)
    if "nur_extern var(sess.dienst)" not in t:
        i = finde(r"^\s*acl nur_intern var\(sess\.dienst\)")
        j = finde(r"^\s*tcp-request content set-var\(sess\.grund\) str\(nur_intern\)")
        if i is None or j is None:
            raise Fehler("haproxy.cfg: Stufe 1 (fe_https) hat nicht die erwartete Form – Zugang „extern“ "
                         "kann nicht ergänzt werden. Bitte an die aktuelle Vorlage von haproxy-unraid angleichen.")
        nach(i, ["acl nur_extern var(sess.dienst),field(2,:) -m str extern"])
        j += 1
        nach(j, ["tcp-request content set-var(sess.grund) str(nur_extern)            if !hat_grund nur_extern intern"])
        geaendert.append("Zugang „extern“ in Stufe 1")
    if "nur_extern var(txn.dienst)" not in "\n".join(zeilen):
        i = finde(r"^\s*acl nur_intern var\(txn\.dienst\)")
        j = finde(r"^\s*http-request set-var\(txn\.grund\) str\(nur_intern\)")
        if i is None or j is None:
            raise Fehler("haproxy.cfg: Stufe 2 (fe_tls) hat nicht die erwartete Form – Zugang „extern“ "
                         "kann nicht ergänzt werden.")
        nach(i, ["acl nur_extern var(txn.dienst),field(2,:) -m str extern"])
        j += 1
        nach(j, ["http-request set-var(txn.grund) str(nur_extern)        if !hat_grund nur_extern intern"])
        geaendert.append("Zugang „extern“ in Stufe 2")
    t = "\n".join(zeilen)
    if M_ANF + "regeln-tcp" not in t:
        j = finde(r"^\s*tcp-request content set-var\(sess\.grund\) str\(nur_extern\)")
        if j is None:
            raise Fehler("haproxy.cfg: Ankerzeile für regeln-tcp fehlt")
        nach(j, [M_ANF + "regeln-tcp (automatisch – über den Assistenten in haproxy-ui ändern)", M_END + "regeln-tcp"])
        geaendert.append("Markierung regeln-tcp")
    t = "\n".join(zeilen)
    if M_ANF + "regeln-pruefen" not in t:
        j = finde(r"^\s*http-request sc-inc-gpc0\(0\)")
        if j is None:
            j = finde(r"^\s*http-request set-var\(txn\.aktion\) str\(abgelehnt\)")
        if j is None:
            raise Fehler("haproxy.cfg: Ankerzeile für regeln-pruefen fehlt")
        vor(j, [M_ANF + "regeln-pruefen (automatisch – über den Assistenten in haproxy-ui ändern)", M_END + "regeln-pruefen"])
        geaendert.append("Markierung regeln-pruefen")
    t = "\n".join(zeilen)
    if M_ANF + "regeln-aktionen" not in t:
        j = None
        for i in range(len(zeilen) - 1, -1, -1):
            if re.match(r"^\s*use_backend %\[var\(txn\.dienst\)", zeilen[i]):
                j = i
                break
        if j is None:
            raise Fehler("haproxy.cfg: Ankerzeile für regeln-aktionen fehlt")
        vor(j, [M_ANF + "regeln-aktionen (automatisch – über den Assistenten in haproxy-ui ändern)", M_END + "regeln-aktionen"])
        geaendert.append("Markierung regeln-aktionen")
    return "\n".join(zeilen), geaendert


def cfg_bereit(text):
    """Ist die haproxy.cfg schon vorbereitet? (für die Anzeige)"""
    return all(s in text for s in ("nur_extern var(sess.dienst)", "nur_extern var(txn.dienst)",
                                    M_ANF + "regeln-tcp", M_ANF + "regeln-pruefen", M_ANF + "regeln-aktionen"))
