# NetBlock Fortress - network-wide micro & macro ad shield
#   docker run -d --name adquit --network host -v adquit-data:/opt/adquit/data \
#       -e ADQUIT_PASSWORD=choose-one ghcr.io/afzalashraf/netblock-fortress:latest
FROM python:3.12-slim

ARG VERSION=19.0
ENV PYTHONUNBUFFERED=1 ADQUIT_HOME=/opt/adquit ADQUIT_NO_PIP=1 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/adquit
COPY app.py bin/adquit ./
RUN pip install --no-cache-dir -q flask requests dnslib \
 && chmod 0755 /opt/adquit/app.py /opt/adquit/bin/adquit \
 && ln -s /opt/adquit/bin/adquit /usr/local/bin/adquit \
 && mkdir -p /opt/adquit/data/lists /opt/adquit/data/meta

EXPOSE 53/udp 53/tcp 8080/tcp 80/tcp
VOLUME ["/opt/adquit/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD curl -fsS "http://127.0.0.1:${ADQUIT_WEB_PORT:-8080}/api/health" || exit 1

ENTRYPOINT ["adquit"]
CMD ["run"]
