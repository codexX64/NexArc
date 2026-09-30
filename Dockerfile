# syntax=docker/dockerfile:1
# Sentinel 2 : Node seul, aucune dépendance d'exécution (node:sqlite, WebSocket
# et Argon2id sont dans le moteur). L'image de base est épinglée par empreinte
# (index multi-architecture amd64 + arm64) : une étiquette peut être déplacée,
# une empreinte non.
ARG NODE_IMAGE=node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
FROM ${NODE_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 sentinel && useradd -u 10001 -g sentinel -M -d /nonexistent -s /usr/sbin/nologin sentinel
WORKDIR /app
COPY package.json ./
COPY socle ./socle
COPY src ./src
COPY web ./web
# La source de l'agent, servie aux postes pendant l'inscription (jamais exécutée ici).
COPY agent ./agent
RUN mkdir -p /data && chown sentinel:sentinel /data && chmod 700 /data
USER sentinel
ENV NODE_ENV=production DATA_DIR=/data PORT=8090
EXPOSE 8090
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8090/api/health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "--disable-warning=ExperimentalWarning", "src/main.js"]
