#!/usr/bin/env bash
# Instala la web de Dissect en un servidor Linux (VPS) con Ubuntu 22.04/24.04 o Debian 12,
# en x86_64 o ARM64 (aarch64).
# Uso, desde la carpeta del repositorio:  sudo bash deploy/server/install.sh
# Guía paso a paso (Oracle Cloud Free Tier, Hetzner u otro): docs/deploy.md
#
# Qué hace:
#  1. instala Docker, Caddy y las actualizaciones automáticas de seguridad;
#  2. instala uv 0.8.22 comprobando su SHA-256 publicado;
#  3. copia el código a /opt/dissect y crea su entorno (Python 3.12, extra "web");
#  4. construye la imagen aislada dissect-worker:0.6.0;
#  5. crea el usuario de servicio "dissect", la configuración /etc/dissect/web.env,
#     la unidad de systemd y el sitio de Caddy (puerto 80; HTTPS al poner un dominio);
#  6. abre los puertos 80 y 443 si el sistema trae reglas de iptables que los bloquean
#     (las imágenes de Ubuntu de Oracle Cloud).
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
warn() { printf '\n\033[1;33mAviso:\033[0m %s\n' "$*" >&2; }
die() { printf '\n\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "ejecuta el script con sudo."
[ -f "$SOURCE/pyproject.toml" ] && [ -d "$SOURCE/src/dissect" ] || die "no encuentro el repositorio en $SOURCE."
case "$(uname -m)" in
  x86_64) UV_ARCH="x86_64" ;;
  aarch64 | arm64) UV_ARCH="aarch64" ;;
  *) die "arquitectura no soportada: $(uname -m) (hace falta x86_64 o aarch64)." ;;
esac
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04 | ubuntu:24.04 | debian:12) ;;
  *) warn "probado en Ubuntu 22.04/24.04 y Debian 12; este sistema es ${PRETTY_NAME:-desconocido}." ;;
esac
memory_mb=$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)
if [ "$memory_mb" -lt 1800 ]; then
  warn "hay ${memory_mb} MB de memoria; cada análisis puede usar 512 MiB y conviene tener 2 GB o más."
fi

say "Instalando Docker, Caddy y las actualizaciones automáticas de seguridad"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io caddy curl ca-certificates rsync unattended-upgrades
systemctl enable --now docker
systemctl enable --now unattended-upgrades || true

say "Instalando uv $UV_VERSION ($UV_ARCH)"
if ! /usr/local/bin/uv --version 2>/dev/null | grep -q "uv $UV_VERSION"; then
  tmp="$(mktemp -d)"
  base="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
  archive="uv-$UV_ARCH-unknown-linux-gnu.tar.gz"
  curl -fsSL -o "$tmp/$archive" "$base/$archive"
  curl -fsSL -o "$tmp/$archive.sha256" "$base/$archive.sha256"
  (cd "$tmp" && sha256sum -c "$archive.sha256") || die "el SHA-256 de uv no coincide; no se instala."
  tar -xzf "$tmp/$archive" -C "$tmp"
  install -m 0755 "$tmp/uv-$UV_ARCH-unknown-linux-gnu/uv" /usr/local/bin/uv
  rm -rf "$tmp"
fi

say "Creando el usuario de servicio \"$SERVICE_USER\""
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
# The service starts one isolated worker container per analysis, so it needs Docker.
# Membership of the docker group is equivalent to root on this machine (design of the
# web, section 2): the service only listens on 127.0.0.1, behind Caddy. Use a server
# that holds nothing else.
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
  cpus=$(nproc)
  concurrency=$(( memory_mb >= 7000 && cpus >= 4 ? 3 : (memory_mb >= 3500 && cpus >= 2 ? 2 : 1) ))
  sed -i "s/^DISSECT_WEB_CONCURRENCY=.*/DISSECT_WEB_CONCURRENCY=$concurrency/" "$CONFIG/web.env"
  echo "Creada (análisis a la vez: $concurrency, según $cpus CPU y ${memory_mb} MB)."
  echo "Para usar VirusTotal, escribe tu clave en VT_API_KEY."
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

say "Cortafuegos del sistema"
# Oracle Cloud's Ubuntu images reject everything but SSH in iptables, even when the
# cloud's security list allows 80 and 443. Open them just before the first REJECT rule.
if command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -q -- "-j REJECT"; then
  position=$(iptables -L INPUT --line-numbers -n | awk '$2 == "REJECT" {print $1; exit}')
  for port in 443 80; do
    if ! iptables -C INPUT -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT "$position" -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT
    fi
  done
  if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save
  fi
  echo "Abiertos los puertos 80 y 443 en iptables."
elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
  echo "Abiertos los puertos 80 y 443 en ufw."
else
  echo "No hay reglas locales que bloqueen 80 y 443."
fi

say "Comprobando"
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8080/api/health >/dev/null 2>&1; then break; fi
  sleep 1
done
if curl -fsS http://127.0.0.1:8080/api/health; then
  address="$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"
  printf '\n\nListo. Abre http://%s desde tu navegador.\n' "$address"
  printf 'Si no carga, abre los puertos 80 y 443 en el cortafuegos de tu proveedor (docs/deploy.md).\n'
else
  die "el servicio no responde. Mira: sudo journalctl -u dissect-web -n 50"
fi
