# haproxy-ui

Weboberfläche für [haproxy-unraid](https://github.com/SysriX/haproxy_unraid): HAProxy bequem im Browser konfigurieren, Statistik ansehen und optional an Home Assistant melden.

Weitere Unraid-Pakete: [haproxy-unraid](https://github.com/SysriX/haproxy_unraid), [certwarden-unraid](https://github.com/SysriX/certwarden_unraid)

`ghcr.io/sysrix/haproxy-ui:latest`

## Was es kann

| Reiter | Inhalt |
| --- | --- |
| Übersicht | Zustand, Sitzungen, Anfragen/s, Eingänge, Backends und Server mit Status, Fehlern und Datenmenge (alle 10 s) |
| Dienste | alle Adressen als Tabelle (Zugang **nur intern / nur extern / intern + extern**, tls/durch, Anzahl Regeln) und der **Assistent „Neue Adresse“** |
| Dateien | alle Dateien in `bearbeiten/` mit Editor (Strg+S speichert), neue Listen anlegen |
| Änderungen | Unterschied zur laufenden Konfiguration, Knöpfe **Prüfen**, **Prüfen und übernehmen**, **Verwerfen**, **Zurück** |
| Zertifikate | Restlaufzeit aller Zertifikate, `certs.conf`, „Jetzt aus Cert Warden holen“ |

### Assistent „Neue Adresse“ (Baukasten)

In vier Schritten statt Konfiguration von Hand:

1. **Adresse**: Vorlage wählen (Webseite, Home Assistant, Nextcloud, Jellyfin, Authentik, Oberfläche mit https, Vaultwarden, verschlüsselt durchreichen), Adresse, Zugang (nur intern / nur extern / intern + extern), Verschlüsselung (HAProxy entschlüsselt oder durchreichen)
2. **Ziel**: neues Backend (ein oder mehrere Server, Reserve-Server, Lastverteilung, https zum Ziel, Gesundheitsprüfung, lange Verbindungen, Zeitlimit, X-Forwarded-Port, Host-Header, Sitzung am Server halten) oder ein vorhandenes Backend
3. **Regeln**: *wenn* Herkunft (von außen / innen / bestimmte IPs / Liste, auch verneint) *und* Pfad (beginnt mit / genau / beginnt nicht mit) *dann* sperren (403/404/429/503), umleiten, an anderes Backend, Header setzen oder entfernen – mit fertigen Bausteinen wie „Admin-Bereich nur intern“, „Nur bestimmte IPs“, „HSTS“
4. **Prüfen**: Zusammenfassung in Worten, To-dos (DNS, fehlendes Zertifikat), die erzeugten Zeilen und der Unterschied – dann speichern oder gleich übernehmen

Gespeichert wird in `bearbeiten/baukasten.json`. Daraus schreibt haproxy-ui die Zeile in `listen/dienste.map` und **nur** die markierten Blöcke `# >>> haproxy-ui: …` / `# <<< haproxy-ui: …` in `haproxy.cfg` und `dienste.cfg` – eigene Backends und Handarbeit außerhalb bleiben unangetastet. Eine ältere `haproxy.cfg` ohne diese Blöcke wird beim ersten Speichern automatisch ergänzt (sichtbar unter „Änderungen“). Bestehende Adressen lassen sich mit **Bearbeiten** wieder im Assistenten öffnen; gelöschte Adressen nehmen ihre Regeln und ungenutzten Backends mit.

Braucht haproxy-unraid ab dem Stand mit Zugang `extern` (Image vom 12.11.2026 oder neuer).

**Sicher:** Die Oberfläche ändert nur `bearbeiten/`. Übernommen wird immer im HAProxy-Container über `hap-uebernehmen` – also mit Prüfung, Neuladen ohne Verbindungsabbruch und automatischem Rücksprung bei Fehlern. Oben rechts zeigt „HAProxy verbunden“, ob der HAProxy-Container Aufträge annimmt.

**Nicht allein lauffähig:** braucht `haproxy-unraid` mit **demselben appdata-Ordner**.

## Installation in Unraid

1. `haproxy-unraid` installieren und einmal starten.
2. Vorlage holen (falls noch nicht geschehen) und in **Apps › Private** `haproxy-ui` installieren:
   ```bash
   mkdir -p /boot/config/plugins/community.applications/private/sysrix && curl -fsSL https://raw.githubusercontent.com/SysriX/haproxy-ui_unraid/main/templates/haproxy-ui.xml -o /boot/config/plugins/community.applications/private/sysrix/haproxy-ui.xml
   ```
3. Netzwerk `br0` (bzw. VLAN) mit **fester IP**. Diese IP muss in `listen/intern-netze.lst` von HAProxy liegen (Zugriff auf die Statistik).
4. Aufruf: `http://<IP_haproxy-ui>:8080/`

## Einstellungen

| Feld | Variable / Pfad | Pflicht | Bedeutung |
| --- | --- | --- | --- |
| HAProxy-Konfiguration | `/haproxy` | ja | **derselbe** Ordner wie „Konfiguration“ bei haproxy-unraid |
| Passwort | `UI_PASS` | ja | Anmeldung an der Oberfläche |
| HAProxy-Statistik | `HAP_URL` | ja | z. B. `http://<IP_HAProxy>:8404` |
| Statistik-Passwort | `STATS_PASS` | ja | wie bei haproxy-unraid |
| MQTT-Broker | `MQTT_HOST` | nein | leer = keine Meldung an Home Assistant |
| MQTT-Port / -Benutzer / -Passwort | `MQTT_PORT`, `MQTT_USER`, `MQTT_PASS` | nein | Zugang zum Broker |
| MQTT-Intervall | `MQTT_INTERVALL` | nein | Sekunden zwischen zwei Meldungen (Standard 60) |
| Gerätename | `HA_GERAET` | nein | bei mehreren HAProxy unterschiedlich wählen |
| Discovery-Präfix | `MQTT_PREFIX` | nein | Standard `homeassistant` |

## Home Assistant (optional)

Mit eingetragenem MQTT-Broker legt haproxy-ui per MQTT-Discovery automatisch ein Gerät **HAProxy** an:

- **Erreichbar** und **Änderungen nicht übernommen** (binary_sensor)
- je Eingang/Backend: **Status** (Attribute: Bytes, 4xx/5xx, Fehler), **Sitzungen**, **Rate**, **Verbindungen gesamt**
- je Zertifikat: **Resttage** (Attribute: Ablauf, Namen)
- **Letzter Auftrag** (OK/Fehler mit Log)

Voraussetzung: MQTT-Broker (z. B. Mosquitto) und die MQTT-Integration in Home Assistant.

## Sicherheit

- Anmeldung mit Passwort, nach 5 Fehlversuchen 5 Minuten Pause
- Zugriff nur auf die Dateien in `bearbeiten/` und `certs.conf`
- nur im internen Netz betreiben, nicht nach außen freigeben

## Updates

Neu gebaut, sobald das offizielle Python-Image aktualisiert wird; Unraid zeigt dann „Update verfügbar“.

## Hilfe

Fragen und Fehler bitte als [GitHub-Issue](https://github.com/SysriX/haproxy-ui_unraid/issues).

Lizenz: MIT – siehe [LICENSE](LICENSE). Python steht unter eigener Lizenz.
