#!/usr/bin/env bash
# Actualiza una instalación existente con el código de esta carpeta.
# Uso: git pull && sudo bash deploy/server/update.sh
# Vuelve a ejecutar el instalador, que no borra /etc/lupabin/web.env ni cambia un
# Caddyfile que ya sea de LupaBin (por ejemplo, con tu dominio).
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh"
