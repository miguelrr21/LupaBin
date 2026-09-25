#!/usr/bin/env bash
# Actualiza una instalación existente con el código de esta carpeta.
# Uso: git pull && sudo ./deploy/raspberry-pi/update.sh
# Vuelve a ejecutar el instalador, que no borra /etc/dissect/web.env ni cambia un
# Caddyfile que ya sea de Dissect (por ejemplo, con tu dominio).
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh"
