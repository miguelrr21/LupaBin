# Desplegar la web de Dissect en una Raspberry Pi

Esta guía es para quien no ha desplegado nunca un servicio. Al terminar tendrás la web funcionando en tu red de casa, en `http://dissect.local`. El último apartado explica cómo publicarla en Internet cuando compres un dominio.

Qué se instala y por qué está en `docs/superpowers/specs/2026-09-25-web-design.md`. En resumen: una aplicación web (`dissect-web`) que escucha solo dentro de la Raspberry Pi, Caddy delante para recibir las visitas y Docker para abrir cada archivo en un contenedor nuevo, sin red y sin privilegios. La muestra nunca se ejecuta y no se guarda nada.

## 1. Qué necesitas

- Una Raspberry Pi 4 o 5 con **4 GB** de memoria como mínimo (8 GB mejor). Cada análisis puede usar hasta 512 MiB.
- Una tarjeta microSD de 32 GB o más (mejor aún un SSD por USB).
- **Raspberry Pi OS Lite de 64 bits** (Bookworm). Tiene que ser de 64 bits: la imagen del análisis se construye para `aarch64`.
- Cable de red, o wifi configurado.

## 2. Preparar el sistema

1. En tu PC, instala **Raspberry Pi Imager** (raspberrypi.com/software) y elige: tu modelo, *Raspberry Pi OS Lite (64-bit)* y tu tarjeta.
2. En "Editar ajustes" (el engranaje):
   - nombre del equipo: `dissect`;
   - crea tu usuario y contraseña;
   - en *Servicios*, **activa SSH**.
3. Graba la tarjeta, ponla en la Pi y enciéndela. Espera un par de minutos.
4. Desde tu PC (PowerShell o Terminal), conéctate:
   ```text
   ssh tu_usuario@dissect.local
   ```
   Si no encuentra `dissect.local`, busca la IP de la Pi en la página de tu router y usa `ssh tu_usuario@192.168.x.y`.
5. Actualiza el sistema:
   ```text
   sudo apt update && sudo apt full-upgrade -y && sudo reboot
   ```

## 3. Llevar el código a la Pi

El repositorio es privado. Elige una opción.

**A. Con git y un token de GitHub** (más cómodo para actualizar después):
1. En GitHub: *Settings → Developer settings → Personal access tokens → Fine-grained tokens*. Crea un token con acceso de **solo lectura** (*Contents: Read-only*) al repositorio `Dissect`.
2. En la Pi:
   ```text
   sudo apt install -y git
   git clone https://github.com/miguelrr21/Dissect.git
   ```
   Como usuario pon el tuyo de GitHub y, como contraseña, el token.

**B. Copiándolo desde tu PC**, en PowerShell, desde la carpeta del proyecto:
```text
git archive --format=tar.gz -o dissect.tar.gz HEAD
scp dissect.tar.gz tu_usuario@dissect.local:~
ssh tu_usuario@dissect.local "mkdir -p Dissect && tar -xzf dissect.tar.gz -C Dissect"
```

## 4. Instalar

En la Pi:
```text
cd ~/Dissect
sudo bash deploy/raspberry-pi/install.sh
```

La primera vez tarda entre 10 y 20 minutos: descarga Python 3.12 y construye la imagen del análisis. El script:
- instala Docker y Caddy;
- instala uv (el gestor de Python del proyecto), comprobando su firma SHA-256;
- copia el código a `/opt/dissect`;
- crea el usuario de servicio `dissect`;
- construye la imagen `dissect-worker:0.6.0`;
- arranca el servicio `dissect-web` y configura Caddy en el puerto 80.

Al final escribe la dirección de la web. Ábrela desde cualquier equipo de tu red: `http://dissect.local`.

## 5. VirusTotal (opcional)

Sin clave, la web analiza igual y no contacta con VirusTotal. Para activarlo:
```text
sudo nano /etc/dissect/web.env
```
Escribe tu clave en `VT_API_KEY=...`, guarda (Ctrl+O, Enter, Ctrl+X) y reinicia:
```text
sudo systemctl restart dissect-web
```

Por defecto funciona como la CLI: consulta el SHA-256 y, si VirusTotal no conoce el archivo, **lo sube**. La web lo avisa y deja desmarcar la subida. Ten en cuenta dos cosas:
- **La cuota es la de tu clave.** La pública permite 4 consultas por minuto y 500 al día, y la gastarán tus visitantes.
- **Los archivos serían de tus visitantes.** Lo que se sube puede compartirse con los clientes de pago de VirusTotal. Si prefieres no subir nunca nada, pon `DISSECT_VIRUSTOTAL_UPLOAD=off`.

## 6. Límites de la web pública

En el mismo `/etc/dissect/web.env`:

| Variable | Por defecto | Qué hace |
| --- | --- | --- |
| `DISSECT_WEB_RATE` | `6/600` | Análisis por IP: 6 cada 600 segundos. |
| `DISSECT_WEB_CONCURRENCY` | `1` | Análisis a la vez: 1 con 4 GB, 2 con 8 GB. |
| `DISSECT_WEB_QUEUE_SECONDS` | `60` | Cuánto espera una petición antes de responder "ocupado". |

El tamaño máximo de archivo es 20 MiB.

## 7. Comprobar que todo va bien

```text
systemctl status dissect-web caddy docker
curl http://127.0.0.1:8080/api/health
sudo journalctl -u dissect-web -n 50
```

`/api/health` responde `{"status":"ok",...}` si Docker y la imagen están disponibles. Los registros no guardan las IP de los visitantes ni los archivos.

## 8. Actualizar

Con la opción A:
```text
cd ~/Dissect && git pull && sudo bash deploy/raspberry-pi/update.sh
```
Con la opción B, repite la copia y ejecuta `update.sh`. La actualización conserva tu `web.env` y tu `Caddyfile`.

## 9. Publicarla en Internet con un dominio (más adelante)

1. **Compra un dominio** (por ejemplo, en Cloudflare, Namecheap o un registrador español) y crea un registro **A** con la IP pública de tu casa. Puedes verla en ifconfig.me. Si tu IP cambia a menudo, usa un servicio de DNS dinámico o la API de tu registrador.
2. **Reserva en el router una IP fija para la Pi**, en el apartado DHCP.
3. **Redirige en el router los puertos 80 y 443** (TCP) hacia la IP de la Pi.
4. **Edita Caddy**:
   ```text
   sudo nano /etc/caddy/Caddyfile
   ```
   Cambia `:80 {` por `dissect.tudominio.es {` y recarga:
   ```text
   sudo systemctl reload caddy
   ```
   Caddy pedirá y renovará solo el certificado HTTPS.
5. Si tu operador usa **CG-NAT** (la IP del router no coincide con ifconfig.me), no podrás abrir puertos. En ese caso, una alternativa es un túnel como Cloudflare Tunnel: requiere configurarlo aparte y no lo instala este script.

**Antes de abrirla a Internet:**
- Activa las actualizaciones automáticas de seguridad: `sudo apt install unattended-upgrades`.
- Revisa los límites del apartado 6.
- Recuerda que el usuario `dissect` pertenece al grupo `docker`, que en esa máquina equivale a root. El servicio solo escucha en `127.0.0.1` y systemd lo aísla, pero conviene que la Pi no guarde nada más importante.

## 10. Desinstalar

```text
sudo systemctl disable --now dissect-web
sudo rm -rf /opt/dissect /etc/dissect /var/lib/dissect /etc/systemd/system/dissect-web.service
sudo cp /etc/caddy/Caddyfile.antes-de-dissect /etc/caddy/Caddyfile 2>/dev/null; sudo systemctl reload caddy
docker rmi dissect-worker:0.6.0
```
