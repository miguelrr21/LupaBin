#!/usr/bin/env bash
# Instala la web de Dissect en una Raspberry Pi con Raspberry Pi OS de 64 bits (Bookworm).
# Uso, desde la carpeta del repositorio:  sudo ./deploy/raspberry-pi/install.sh
# Guía paso a paso: docs/deploy-raspberry-pi.md
#
# Qué hace:
#  1. instala Docker y Caddy desde los repositorios de Debian;
#  2. instala uv 0.8.22 comprobando su SHA-256 publicado;
#  3. copia el código a /opt/dissect y crea su entorno (Python 3.12, extra "web");
#  4. construye la imagen aislada dissect-worker:0.6.0;
#  5. crea el usuario de servicio "dissect", la configuración /etc/dissect/web.env,
#     la unidad de systemd y el sitio de Caddy en el puerto 80 de la red local.
# Se puede volver a ejecutar: no borra la configuración existente.
set -euo pipefail

UV_VERSION="0.8.22"
APP="/opt/dissect"
STATE="/var/lib/dissect"
CONFIG="/etc/dissect"
SERVICE_USER="dissect"
IMAGE="dissect-worker:0.6.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$(cd "$HERE/../.." && pwd)"

say() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "ejecuta el script con sudo."
[ "$(uname -m)" = "aarch64" ] || die "hace falta Raspberry Pi OS de 64 bits (aarch64); este sistema es $(uname -m)."
[ -f "$SOURCE/pyproject.toml" ] && [ -d "$SOURCE/src/dissect" ] || die "no encuentro el repositorio en $SOURCE."

say "Instalando Docker, Caddy y utilidades"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io caddy curl ca-certificates rsync
systemctl enable --now docker

say "Instalando uv $UV_VERSION"
if ! /usr/local/bin/uv --version 2>/dev/null | grep -q "uv $UV_VERSION"; then
  tmp="$(mktemp -d)"
  base="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
  archive="uv-aarch64-unknown-linux-gnu.tar.gz"
  curl -fsSL -o "$tmp/$archive" "$base/$archive"
  curl -fsSL -o "$tmp/$archive.sha256" "$base/$archive.sha256"
  (cd "$tmp" && sha256sum -c "$archive.sha256") || die "el SHA-256 de uv no coincide; no se instala."
  tar -xzf "$tmp/$archive" -C "$tmp"
  install -m 0755 "$tmp/uv-aarch64-unknown-linux-gnu/uv" /usr/local/bin/uv
  rm -rf "$tmp"
fi

say "Creando el usuario de servicio \"$SERVICE_USER\""
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
# The service starts one isolated worker container per analysis, so it needs Docker.
# Membership of the docker group is equivalent to root on this machine (design of the
# web, section 2): the service only listens on 127.0.0.1, behind Caddy.
usermod -aG docker "$SERVICE_USER"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE"

say "Copiando el código a $APP"
install -d -m 0755 "$APP"
rsync -a --delete \
  --exclude ".git" --exclude ".venv" --exclude ".bootstrap" --exclude "samples" \
  --exclude ".env" --exclude "dist" --exclude "__pycache__" --exclude ".python" \
  "$SOURCE/" "$APP/"

say "Creando el entorno de Python (puede tardar unos minutos la primera vez)"
export UV_PYTHON_INSTALL_DIR="$APP/.python" UV_CACHE_DIR="/var/cache/dissect-uv" UV_LINK_MODE=copy
(cd "$APP" && uv sync --frozen --no-dev --extra web --python 3.12)
chmod -R a+rX "$APP"

say "Construyendo la imagen aislada $IMAGE (la primera vez tarda varios minutos)"
docker build -f "$APP/docker/Dockerfile" -t "$IMAGE" "$APP"

say "Configuración en $CONFIG/web.env"
install -d -m 0750 -g "$SERVICE_USER" "$CONFIG"
if [ ! -f "$CONFIG/web.env" ]; then
  install -m 0640 -g "$SERVICE_USER" "$HERE/web.env.example" "$CONFIG/web.env"
  echo "Creada. Para usar VirusTotal, escribe tu clave en VT_API_KEY."
else
  echo "Ya existía; no se cambia."
fi

say "Servicio de systemd dissect-web"
install -m 0644 "$HERE/dissect-web.service" /etc/systemd/system/dissect-web.service
systemctl daemon-reload
systemctl enable dissect-web
systemctl restart dissect-web

say "Sitio de Caddy"
if [ -f /etc/caddy/Caddyfile ] && ! grep -q "Dissect" /etc/caddy/Caddyfile; then
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.antes-de-dissect"
fi
if ! grep -q "Dissect" /etc/caddy/Caddyfile 2>/dev/null; then
  install -m 0644 "$HERE/Caddyfile" /etc/caddy/Caddyfile
fi
systemctl enable caddy
systemctl reload caddy || systemctl restart caddy

say "Comprobando"
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8080/api/health >/dev/null 2>&1; then break; fi
  sleep 1
done
if curl -fsS http://127.0.0.1:8080/api/health; then
  host="$(hostname).local"
  printf '\n\nListo. Abre http://%s (o http://%s) desde otro equipo de tu red.\n' \
    "$host" "$(hostname -I | awk '{print $1}')"
else
  die "el servicio no responde. Mira: sudo journalctl -u dissect-web -n 50"
fi
