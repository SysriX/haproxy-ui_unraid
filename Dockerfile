# haproxy-ui: Weboberfläche für haproxy-unraid (Dienste, Dateien, Prüfen/Übernehmen/Zurück,
# Statistik, Zertifikate) + optional Home Assistant über MQTT-Discovery.
# Neu gebaut, sobald das offizielle Basis-Image (python:3-alpine) sich ändert.
ARG PY_TAG=3.13-alpine
FROM python:${PY_TAG}

ARG PY_TAG
ARG BASE_DIGEST=unbekannt
ARG QUELLE=https://github.com/
LABEL org.opencontainers.image.title="haproxy-ui" \
      org.opencontainers.image.description="Weboberfläche für haproxy-unraid mit sicherem Übernehmen (Prüfung + Rücksprung) und Home-Assistant-Anbindung per MQTT" \
      org.opencontainers.image.source="${QUELLE}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/python:${PY_TAG}" \
      org.opencontainers.image.base.digest="${BASE_DIGEST}"

RUN apk add --no-cache tini openssl \
 && pip install --no-cache-dir "paho-mqtt>=2,<3"
COPY app/ /app/
RUN sed -i 's/\r$//' /app/*.py && python3 -m py_compile /app/app.py /app/baukasten.py

ENV HAPROXY_DIR=/haproxy \
    UI_PORT=8080 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Berlin
VOLUME /haproxy
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -T 4 -O /dev/null http://127.0.0.1:${UI_PORT}/gesund || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python3", "/app/app.py"]
