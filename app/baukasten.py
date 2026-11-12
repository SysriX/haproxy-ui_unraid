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
    return {"version": 1, "dienste": {}, "backends": {}, "benutzerlisten": {}}


def laden(text):
    try:
        d = json.loads(text) if text.strip() else leer()
    except json.JSONDecodeError:
        d = leer()
    d.setdefault("dienste", {})
    d.setdefault("backends", {})
    d.setdefault("benutzerlisten", {})
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


SEKTIONEN = ("backend", "frontend", "listen", "defaults", "global", "userlist", "peers", "resolvers", "cache",
             "program", "ring", "http-errors", "mailers", "crt-store", "traces", "log-forward")
HEADER_RICHTUNG = ("anfrage", "antwort")
HEADER_ART = ("setzen", "hinzufuegen", "entfernen")
ANMELDUNG = ("keine", "basic", "authentik", "basic_authentik")
RE_LISTE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")
RE_BENUTZER = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
RE_HASH = re.compile(r"^\$(1|5|6|2[aby])\$[A-Za-z0-9./$]{8,200}$")
RE_ZEIT = re.compile(r"^[0-9]+(ms|s|m|h)$")


def eigene_zeilen(text, feld="Eigene Zeilen"):
    """Freie HAProxy-Zeilen (Experten) – nur innerhalb des Abschnitts, keine neuen Abschnitte."""
    out = []
    for z in str(text or "").replace("\r\n", "\n").split("\n"):
        s = z.strip()
        if not s:
            continue
        if "\0" in s or "\r" in s or len(s) > 400:
            raise Fehler(f"{feld}: Zeile ungültig")
        if s.split()[0].lower() in SEKTIONEN:
            raise Fehler(f"{feld}: „{s.split()[0]}“ würde einen neuen Abschnitt beginnen – nicht erlaubt")
        if "haproxy-ui:" in s:
            raise Fehler(f"{feld}: Markierungen von haproxy-ui sind nicht erlaubt")
        out.append(s)
    if len(out) > 60:
        raise Fehler(f"{feld}: höchstens 60 Zeilen")
    return "\n".join(out)


def _zeit(b, feld, name):
    v = str(b.get(feld, "") or "").strip()
    if v and not RE_ZEIT.match(v):
        raise Fehler(f"{name}: z. B. 10s, 5m, 1h")
    return v


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
        opt = str(s.get("optionen", "") or "").strip()
        if opt and (any(c in opt for c in "\r\n\0#") or len(opt) > 200):
            raise Fehler(f"Server {i + 1}: weitere Optionen ungültig")
        gew = s.get("gewicht")
        gew = int(gew) if str(gew or "").strip() else None
        if gew is not None and not 0 <= gew <= 256:
            raise Fehler(f"Server {i + 1}: Gewicht 0–256")
        server.append({"adresse": adr, "port": port, "https": bool(s.get("https")) and modus == "tls",
                       "pruefen": bool(s.get("pruefen", True)), "reserve": bool(s.get("reserve")),
                       "gewicht": gew, "optionen": opt})
    if not server:
        raise Fehler("Mindestens einen Server (Adresse + Port) angeben")
    out = {"modus": modus, "server": server, "notiz": _wert(b.get("notiz", ""), "Notiz")[:200].replace("\n", " "),
           "vorlage": str(b.get("vorlage", ""))[:40], "lange_verbindungen": bool(b.get("lange_verbindungen")),
           "proxy_protokoll": bool(b.get("proxy_protokoll")), "redispatch": bool(b.get("redispatch")),
           "pruef_intervall": _zeit(b, "pruef_intervall", "Prüf-Intervall"),
           "eigene": eigene_zeilen(b.get("eigene"), "Eigene Zeilen im Backend")}
    mv = str(b.get("max_verbindungen", "") or "").strip()
    if mv and (not mv.isdigit() or not 1 <= int(mv) <= 100000):
        raise Fehler("Max. Verbindungen je Server: Zahl 1–100000")
    out["max_verbindungen"] = int(mv) if mv else None
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
        out["forwarded"] = bool(b.get("forwarded"))
        out["sticky"] = bool(b.get("sticky"))
        out["kompression"] = bool(b.get("kompression"))
        out["sicherheits_header"] = bool(b.get("sicherheits_header"))
        out["ziel_zert_pruefen"] = bool(b.get("ziel_zert_pruefen"))
        out["sni"] = bool(b.get("sni"))
        out["timeout_server"] = _zeit(b, "timeout_server", "Zeitlimit")
        ip_h = str(b.get("client_ip_header", "") or "").strip()
        if ip_h and not RE_HEADER.match(ip_h):
            raise Fehler("Header für die Client-IP: nur Name, z. B. CF-Connecting-IP")
        out["client_ip_header"] = ip_h
        pr = str(b.get("praefix_entfernen", "") or "").strip().rstrip("/")
        if pr and not re.match(r"^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*$", pr):
            raise Fehler("Pfad-Präfix: z. B. /app (nur Buchstaben, Zahlen, . _ ~ -)")
        out["praefix_entfernen"] = pr
        header = []
        for h in b.get("header") or []:
            n = str(h.get("name", "")).strip()
            if not n:
                continue
            if not RE_HEADER.match(n):
                raise Fehler(f"Header-Name ungültig: {n!r}")
            ri, art = h.get("richtung", "anfrage"), h.get("art", "setzen")
            if ri not in HEADER_RICHTUNG or art not in HEADER_ART:
                raise Fehler("Header: Richtung/Art unbekannt")
            header.append({"richtung": ri, "art": art, "name": n,
                           "wert": "" if art == "entfernen" else _wert(h.get("wert", ""), f"Header {n}")})
        out["header"] = header
    return out


def anmeldung_pruefen(a, modus, backends_modus, listen):
    a = dict(a or {})
    art = a.get("art", "keine")
    if art not in ANMELDUNG:
        raise Fehler("Anmeldung: Art unbekannt")
    if art == "keine":
        return {"art": "keine"}
    if modus != "tls":
        raise Fehler("Anmeldung geht nur, wenn HAProxy entschlüsselt (nicht beim Durchreichen)")
    out = {"art": art, "intern_frei": bool(a.get("intern_frei"))}
    aus = []
    for p in re.split(r"[\s,]+", str(a.get("ausnahmen", "") or "").strip()):
        if not p:
            continue
        if not RE_PFAD.match(p):
            raise Fehler(f"Pfad ohne Anmeldung muss mit / beginnen: {p!r}")
        aus.append(p)
    out["ausnahmen"] = " ".join(aus)
    if art in ("basic", "basic_authentik"):
        realm = str(a.get("realm", "") or "Anmeldung").strip()
        if not re.match(r"^[A-Za-z0-9 ._äöüÄÖÜß-]{1,60}$", realm):
            raise Fehler("Name im Anmeldefenster: Buchstaben, Zahlen, Leerzeichen")
        out["realm"] = realm
    if art == "basic":
        liste = str(a.get("liste", "")).strip()
        if liste not in listen:
            raise Fehler("Benutzerliste wählen oder anlegen")
        out["liste"] = liste
        out["header_entfernen"] = bool(a.get("header_entfernen", True))
    if art in ("authentik", "basic_authentik"):
        be = str(a.get("authentik_backend", "")).strip()
        if be not in backends_modus or backends_modus[be] != "http":
            raise Fehler("Authentik-Backend wählen (vorher eine Adresse für Authentik mit der Vorlage „Authentik“ anlegen)")
        out["authentik_backend"] = be
    return out


def benutzerlisten_pruefen(listen_ein, alt):
    """listen_ein = {name: {"benutzer": [{"name", "hash"?, "passwort"?}]}} – Passwörter werden hier NICHT gehasht,
    sondern als 'passwort' durchgereicht; app.py hasht vor dem Speichern."""
    out = {}
    for name, l in (listen_ein or {}).items():
        if not RE_LISTE_NAME.match(name or ""):
            raise Fehler(f"Name der Benutzerliste ungültig: {name!r} (klein, Buchstaben/Zahlen/-/_)")
        nutzer, gesehen = [], set()
        for u in (l or {}).get("benutzer") or []:
            n = str(u.get("name", "")).strip()
            if not n:
                continue
            if not RE_BENUTZER.match(n):
                raise Fehler(f"Benutzername ungültig: {n!r}")
            if n in gesehen:
                raise Fehler(f"Benutzer {n} doppelt in Liste {name}")
            gesehen.add(n)
            pw = u.get("passwort")
            h = u.get("hash") or next((x.get("hash") for x in (alt.get(name, {}).get("benutzer") or [])
                                       if x.get("name") == n), None)
            if pw:
                if len(str(pw)) < 8:
                    raise Fehler(f"Passwort für {n}: mindestens 8 Zeichen")
                nutzer.append({"name": n, "passwort": str(pw)})
            elif h and RE_HASH.match(h):
                nutzer.append({"name": n, "hash": h})
            else:
                raise Fehler(f"Passwort für {n} fehlt")
        out[name] = {"benutzer": nutzer}
    return out


def eintrag_pruefen(e, backends_modus, verwaltet, listen=()):
    """e = {name, zugang, modus, notiz, backend, backend_neu, backend_def, regeln, anmeldung}"""
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
            raise Fehler(f"Backend {be} gibt es schon (von Hand in dienste.cfg) – anderen Namen wählen, "
                         f"„vorhandenes Backend“ nehmen oder es erst in den Assistenten übernehmen")
        out["backend_def"] = backend_pruefen(be, e.get("backend_def"), modus)
        bm[be] = "http" if modus == "tls" else "tcp"
    else:
        if be not in backends_modus:
            raise Fehler(f"Backend {be} gibt es nicht")
        want = "http" if modus == "tls" else "tcp"
        if backends_modus[be] != want:
            raise Fehler(f"Backend {be} hat mode {backends_modus[be]}, Modus {modus} braucht mode {want}")
    out["anmeldung"] = anmeldung_pruefen(e.get("anmeldung"), modus, bm, listen)
    if out["anmeldung"]["art"] in ("authentik", "basic_authentik") and out["anmeldung"]["authentik_backend"] == be:
        raise Fehler("Bei Anmeldung über Authentik ist das Ziel der eigentliche Dienst, nicht das Authentik-Backend")
    out["regeln"] = [regel_pruefen(r, modus, bm) for r in (e.get("regeln") or [])]
    return out


def map_backend(dienst_def, ziel):
    """Backend, das in dienste.map steht: bei Authentik das Authentik-Backend, sonst das Ziel."""
    a = (dienst_def or {}).get("anmeldung") or {}
    if a.get("art") in ("authentik", "basic_authentik"):
        return a["authentik_backend"]
    return ziel


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


def _frei(a):
    """Bedingungsteile, unter denen KEINE Anmeldung nötig ist (als Liste von Einzelbedingungen)."""
    teile = []
    if a.get("intern_frei"):
        teile.append("intern")
    if a.get("ausnahmen"):
        teile.append("{ var(txn.pfad) -m beg " + a["ausnahmen"] + " }")
    return teile


def anmeldung_text(a):
    art = (a or {}).get("art", "keine")
    t = {"keine": "keine", "basic": f"HTTP-Basic, Benutzerliste {a.get('liste')}",
         "authentik": "Authentik (Anmeldeseite)", "basic_authentik": "HTTP-Basic, geprüft von Authentik"}[art]
    if art != "keine":
        if a.get("intern_frei"):
            t += ", intern ohne"
        if a.get("ausnahmen"):
            t += f", frei: {a['ausnahmen']}"
    return t


def regeln_erzeugen(daten, map_zeilen):
    """-> {"regeln-tcp": [...], "regeln-pruefen": [...], "regeln-aktionen": [...]}"""
    out = {"regeln-tcp": [], "regeln-pruefen": [], "regeln-aktionen": []}
    anmeldung = []  # Anmeldung zuerst (nach den Sperren)
    weiter = []     # use_backend-Zeilen kommen ans Ende (HAProxy wertet http-request-Regeln immer vorher aus)
    modus_von = {z["name"]: z["modus"] for z in map_zeilen}
    for name in sorted(daten["dienste"]):
        if name not in modus_von:
            continue
        modus = modus_von[name]
        d = daten["dienste"][name]
        host = "{ var(txn.host) -m str " + name + " }"
        a = d.get("anmeldung") or {}
        if modus == "tls" and a.get("art", "keine") != "keine":
            kopf = f"    # {name}: Anmeldung – {anmeldung_text(a)}"
            frei = _frei(a)
            bed = " ".join([host] + ["!" + f for f in frei])
            if a["art"] == "basic":
                ul = "ul_" + a["liste"]
                anmeldung += [kopf, f"    http-request auth realm {_q(a['realm'])} if {bed} !{{ http_auth({ul}) }}"]
                if a.get("header_entfernen", True):
                    anmeldung.append(f"    http-request del-header Authorization if {host} {{ http_auth({ul}) }}")
            elif a["art"] == "basic_authentik":
                anmeldung += [kopf, f"    http-request auth realm {_q(a['realm'])} if {bed} !{{ req.hdr(authorization) -m beg -i basic }}"]
            if a["art"] in ("authentik", "basic_authentik") and d.get("ziel"):
                for f in frei:
                    weiter += [f"    # {name}: ohne Anmeldung direkt zum Dienst",
                               f"    use_backend {d['ziel']} if {host} {f}"]
        regeln = [r for r in d.get("regeln", []) if r.get("aktiv", True)]
        for i, r in enumerate(regeln, 1):
            kopf = f"    # {name} #{i}: {regel_text(r)}"
            if modus == "durch":
                if r["aktion"] != "sperren":
                    continue
                bed = " ".join(x for x in ["{ var(sess.sni) -m str " + name + " }", _bed(r, "tcp")] if x)
                out["regeln-tcp"] += [kopf, f"    tcp-request content set-var(sess.grund) str(regel) if !hat_grund {bed}"]
                continue
            bed = " ".join(x for x in [host, _bed(r, "http")] if x)
            ak = r["aktion"]
            if ak == "sperren":
                grund = {403: "regel", 404: "regel_404", 429: "regel_429", 503: "regel_503"}[r.get("code", 403)]
                out["regeln-pruefen"] += [kopf, f"    http-request set-var(txn.grund) str({grund}) if !hat_grund {bed}"]
            elif ak == "umleiten":
                art = "prefix" if r.get("umleiten_art") == "praefix" else "location"
                out["regeln-aktionen"] += [kopf, f"    http-request redirect {art} {_q(r['ziel'])} code {r['code']} if {bed}"]
            elif ak == "backend":
                weiter += [kopf, f"    use_backend {r['ziel']} if {bed}"]
            elif ak == "header_anfrage":
                out["regeln-aktionen"] += [kopf, f"    http-request set-header {r['header']} {_q(r.get('wert', ''))} if {bed}"]
            elif ak == "header_antwort":
                out["regeln-aktionen"] += [kopf, f"    http-response set-header {r['header']} {_q(r.get('wert', ''))} if {bed}"]
            elif ak == "header_entfernen":
                out["regeln-aktionen"] += [kopf, f"    http-response del-header {r['header']} if {bed}"]
    out["regeln-aktionen"] = anmeldung + out["regeln-aktionen"] + weiter
    # Sperren mit anderem Code als 403 brauchen eigene deny-Zeilen (403 macht die Vorlage schon)
    extra = []
    for code in (404, 429, 503):
        if any(f"str(regel_{code})" in z for z in out["regeln-pruefen"]):
            extra.append(f"    http-request deny deny_status {code} if {{ var(txn.grund) -m str regel_{code} }}")
    if extra:
        out["regeln-pruefen"] += ["    # Antwortcodes der Sperr-Regeln",
                                  "    http-request set-var(txn.aktion) str(abgelehnt) if { var(txn.grund) -m beg regel_ }"] + extra
    return out


SICHERHEITS_HEADER = [("Strict-Transport-Security", "max-age=31536000"), ("X-Content-Type-Options", "nosniff"),
                      ("X-Frame-Options", "SAMEORIGIN"), ("Referrer-Policy", "strict-origin-when-cross-origin")]
KOMPRESSION_TYPEN = "text/html text/plain text/css text/javascript application/javascript application/json image/svg+xml"


def _server_ziel(s):
    adr = s["adresse"]
    if adr.startswith("${"):
        return f'"{adr}:{s["port"]}"'
    if ":" in adr:
        return f"[{adr}]:{s['port']}"
    return f"{adr}:{s['port']}"


def backend_erzeugen(name, b, nutzer=()):
    tls = b["modus"] == "tls"
    mehr = len(b["server"]) > 1
    z = [f"# {name}" + (f" – {b['notiz']}" if b.get("notiz") else "") +
         (f"  (für {', '.join(sorted(nutzer))})" if nutzer else ""),
         f"backend {name}", "    mode http" if tls else "    mode tcp"]
    if mehr:
        z.append(f"    balance {b.get('verteilung', 'roundrobin')}")
    if tls and b.get("forwarded"):
        z.append("    option forwarded proto host for")
    if tls and b.get("check_pfad"):
        z.append(f"    option httpchk GET {b['check_pfad']}")
        if b.get("check_status"):
            z.append(f"    http-check expect status {b['check_status']}")
    if b.get("redispatch") and mehr:
        z += ["    retries 3", "    option redispatch"]
    if tls and b.get("kompression"):
        z += ["    compression algo gzip deflate", f"    compression type {KOMPRESSION_TYPEN}"]
    if tls and b.get("sticky") and mehr:
        z.append("    cookie HAPSRV insert indirect nocache httponly secure")
    if tls:
        if b.get("host_header"):
            z.append(f"    http-request set-header Host {b['host_header']}")
        if b.get("forwarded_port"):
            z.append("    http-request set-header X-Forwarded-Port 443")
        if b.get("client_ip_header"):
            z.append(f"    http-request set-header {b['client_ip_header']} %[src]")
        if b.get("praefix_entfernen"):
            pr = b["praefix_entfernen"].replace(".", "\\.")
            z.append(f"    http-request replace-path '^{pr}/?(.*)$' '/\\1'")
        for h in b.get("header") or []:
            wo = "http-request" if h["richtung"] == "anfrage" else "http-response"
            if h["art"] == "entfernen":
                z.append(f"    {wo} del-header {h['name']}")
            else:
                z.append(f"    {wo} {'set' if h['art'] == 'setzen' else 'add'}-header {h['name']} {_q(h['wert'])}")
        if b.get("sicherheits_header"):
            for hn, hw in SICHERHEITS_HEADER:
                z.append(f"    http-response set-header {hn} {_q(hw)} if !{{ res.hdr({hn}) -m found }}")
        if b.get("timeout_server"):
            z.append(f"    timeout server {b['timeout_server']}")
    if b.get("lange_verbindungen"):
        if not (tls and b.get("timeout_server")):
            z.append("    timeout server 1h")
        z.append("    timeout tunnel 1h")
    for e in (b.get("eigene") or "").split("\n"):
        if e.strip():
            z.append("    " + e.strip())
    for i, s in enumerate(b["server"], 1):
        opt = []
        if s.get("https"):
            opt.append("ssl verify required ca-file @system-ca" if b.get("ziel_zert_pruefen") else "ssl verify none")
            if b.get("sni"):
                opt.append("sni req.hdr(host)")
        if b.get("proxy_protokoll"):
            opt.append("send-proxy-v2")
        if s.get("pruefen", True):
            opt.append("check")
            if b.get("pruef_intervall"):
                opt.append(f"inter {b['pruef_intervall']}")
        if s.get("reserve"):
            opt.append("backup")
        if s.get("gewicht") is not None:
            opt.append(f"weight {s['gewicht']}")
        if b.get("max_verbindungen"):
            opt.append(f"maxconn {b['max_verbindungen']}")
        if tls and b.get("sticky") and mehr:
            opt.append(f"cookie s{i}")
        if s.get("optionen"):
            opt.append(s["optionen"])
        z.append(f"    server s{i} {_server_ziel(s)}" + ("" if not opt else " " + " ".join(opt)))
    return "\n".join(z)


def benutzt_von(daten, map_zeilen):
    benutzt = {}
    for zl in map_zeilen:
        benutzt.setdefault(zl["backend"], set()).add(zl["name"])
    for n, d in daten["dienste"].items():
        if d.get("ziel"):
            benutzt.setdefault(d["ziel"], set()).add(n)
        for r in d.get("regeln", []):
            if r.get("aktion") == "backend":
                benutzt.setdefault(r["ziel"], set())
    return benutzt


def backends_erzeugen(daten, map_zeilen):
    benutzt = benutzt_von(daten, map_zeilen)
    bloecke = [backend_erzeugen(n, daten["backends"][n], benutzt[n]) for n in sorted(daten["backends"]) if n in benutzt]
    return "\n\n".join(bloecke)


def benutzer_erzeugen(daten):
    bloecke = []
    for name in sorted(daten.get("benutzerlisten", {})):
        l = daten["benutzerlisten"][name]
        z = [f"userlist ul_{name}"]
        for u in l.get("benutzer", []):
            if u.get("hash"):
                z.append(f"    user {u['name']} password {u['hash']}")
        bloecke.append("\n".join(z))
    return "\n\n".join(bloecke)


# ------------------------------------------------------------------ Übernehmen von Hand geschriebener Backends
def backend_finden(text, name):
    """(start, ende) der Zeilen eines Backend-Abschnitts AUSSERHALB der haproxy-ui-Blöcke, sonst None."""
    zeilen = text.split("\n")
    im_block = False
    for i, z in enumerate(zeilen):
        s = z.strip()
        if s.startswith(M_ANF):
            im_block = True
        elif s.startswith(M_END):
            im_block = False
        elif not im_block and re.match(r"^backend\s+" + re.escape(name) + r"\s*(#.*)?$", z):
            j = i + 1
            while j < len(zeilen) and (not zeilen[j].strip() or zeilen[j][:1] in " \t"):
                j += 1
            while j > i + 1 and not zeilen[j - 1].strip():
                j -= 1
            return i, j
    return None


def backend_importieren(text, name):
    """Liest einen von Hand geschriebenen Backend-Abschnitt in ein Baukasten-Backend um.
    Unbekannte Zeilen landen in 'eigene', unbekannte Server-Optionen in 'optionen' – es geht nichts verloren.
    -> (backend_def, rest_text)"""
    pos = backend_finden(text, name)
    if not pos:
        raise Fehler(f"Backend {name} steht nicht (außerhalb der Assistenten-Blöcke) in dieser Datei")
    a, e = pos
    zeilen = text.split("\n")
    b = {"modus": "durch", "server": [], "verteilung": "roundrobin", "notiz": "von Hand übernommen", "eigene": "",
         "header": []}
    eigene, timeout_server, tunnel = [], "", False
    for z in zeilen[a + 1:e]:
        s = z.strip()
        if not s or s.startswith("#"):
            continue
        w = s.split()
        k = w[0]
        if k == "mode" and len(w) == 2 and w[1] in ("http", "tcp"):
            b["modus"] = "tls" if w[1] == "http" else "durch"
        elif k == "balance" and len(w) == 2 and w[1] in VERTEILUNG:
            b["verteilung"] = w[1]
        elif s == "option forwarded proto host for":
            b["forwarded"] = True
        elif k == "option" and len(w) >= 2 and w[1] == "httpchk":
            if len(w) == 2:
                b["check_pfad"] = "/"
            elif len(w) == 4 and w[2] == "GET" and RE_PFAD.match(w[3]):
                b["check_pfad"] = w[3]
            else:
                eigene.append(s)
        elif s.startswith("http-check expect status ") and len(w) == 4:
            b["check_status"] = w[3]
        elif s in ("retries 3", "option redispatch"):
            b["redispatch"] = True
        elif s.startswith("compression "):
            b["kompression"] = True
        elif s.startswith("cookie HAPSRV insert"):
            b["sticky"] = True
        elif k == "timeout" and len(w) == 3 and w[1] == "server":
            timeout_server = w[2]
        elif k == "timeout" and len(w) == 3 and w[1] == "tunnel" and w[2] == "1h":
            tunnel = True
        elif s.startswith("http-request set-header Host ") and len(w) == 4:
            b["host_header"] = w[3].lower()
        elif s == "http-request set-header X-Forwarded-Port 443":
            b["forwarded_port"] = True
        elif re.match(r"^http-(request|response) (set|add|del)-header \S+( .*)?$", s) and " if " not in s \
                and "%[" not in s and len(w) <= 4:
            ri = "anfrage" if w[0] == "http-request" else "antwort"
            art = {"set-header": "setzen", "add-header": "hinzufuegen", "del-header": "entfernen"}[w[1]]
            wert = " ".join(w[3:]).strip('"') if art != "entfernen" else ""
            b["header"].append({"richtung": ri, "art": art, "name": w[2], "wert": wert})
        elif k == "server" and len(w) >= 3:
            adr = w[2].strip('"')
            m = re.match(r"^\[?([^\]]+?)\]?:([0-9]+)$", adr)
            if not m:
                raise Fehler(f"Server-Zeile nicht lesbar: {s}")
            srv = {"adresse": m.group(1), "port": int(m.group(2)), "https": False, "pruefen": False, "reserve": False,
                   "gewicht": None, "optionen": ""}
            rest, opts = [], w[3:]
            i = 0
            while i < len(opts):
                o = opts[i]
                if o == "check":
                    srv["pruefen"] = True
                elif o == "backup":
                    srv["reserve"] = True
                elif o == "ssl":
                    srv["https"] = True
                elif o == "verify" and i + 1 < len(opts) and opts[i + 1] == "none":
                    i += 1
                elif o == "verify" and i + 1 < len(opts) and opts[i + 1] == "required":
                    b["ziel_zert_pruefen"] = True
                    i += 1
                elif o == "ca-file" and i + 1 < len(opts) and opts[i + 1] == "@system-ca":
                    i += 1
                elif o == "sni" and i + 1 < len(opts) and opts[i + 1] == "req.hdr(host)":
                    b["sni"] = True
                    i += 1
                elif o == "send-proxy-v2":
                    b["proxy_protokoll"] = True
                elif o == "weight" and i + 1 < len(opts) and opts[i + 1].isdigit():
                    srv["gewicht"] = int(opts[i + 1])
                    i += 1
                elif o == "maxconn" and i + 1 < len(opts) and opts[i + 1].isdigit():
                    srv["_maxconn"] = int(opts[i + 1])
                    i += 1
                elif o == "inter" and i + 1 < len(opts) and RE_ZEIT.match(opts[i + 1]):
                    srv["_inter"] = opts[i + 1]
                    i += 1
                elif o == "cookie" and i + 1 < len(opts):
                    i += 1
                else:
                    rest.append(o)
                i += 1
            srv["optionen"] = " ".join(rest)
            b["server"].append(srv)
        else:
            eigene.append(s)
    if tunnel and timeout_server in ("", "1h"):
        b["lange_verbindungen"] = True
    elif timeout_server:
        if b["modus"] == "tls":
            b["timeout_server"] = timeout_server
        else:
            eigene.append(f"timeout server {timeout_server}")
        if tunnel:
            eigene.append("timeout tunnel 1h")
    # inter/maxconn: für alle Server gleich -> Backend-Option, sonst bleibt es beim einzelnen Server
    for feld, ziel, opt in (("_inter", "pruef_intervall", "inter"), ("_maxconn", "max_verbindungen", "maxconn")):
        werte = [s.get(feld) for s in b["server"]]
        if werte and werte[0] is not None and all(w == werte[0] for w in werte):
            b[ziel] = werte[0]
        else:
            for s in b["server"]:
                if s.get(feld) is not None:
                    s["optionen"] = (s["optionen"] + f" {opt} {s[feld]}").strip()
        for s in b["server"]:
            s.pop(feld, None)
    b["eigene"] = "\n".join(eigene)
    if not b["server"]:
        raise Fehler(f"Backend {name} hat keine server-Zeile – bitte im Editor bearbeiten")
    rest_text = "\n".join(zeilen[:a] + zeilen[e:])
    return b, rest_text


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
