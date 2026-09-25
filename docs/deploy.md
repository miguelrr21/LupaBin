# Desplegar la web de Dissect en un servidor

Esta guía es para quien no ha desplegado nunca un servicio. Al terminar tendrás la web pública en la IP de tu servidor y, si quieres, en un dominio con HTTPS.

Qué se instala y por qué está en `docs/superpowers/specs/2026-09-25-web-design.md`. En resumen:
- una aplicación web (`dissect-web`) que solo escucha dentro del servidor;
- Caddy delante, que recibe las visitas y gestiona el HTTPS;
- Docker, que abre cada archivo en un contenedor nuevo, sin red y sin privilegios.

La muestra nunca se ejecuta y no se guarda nada.

**Usa un servidor dedicado, no una máquina de tu casa.** La web recibe archivos de desconocidos. Aunque cada análisis está aislado, el servicio controla Docker, y eso equivale a administrador en esa máquina. Si algo fallara, el daño debe quedarse en un servidor que no guarda nada más y que no está en tu red.

## 1. Elegir servidor

Hace falta una **máquina virtual (VPS) con Linux**. Servicios como Render, Railway, Fly o Vercel no valen, porque no permiten lanzar contenedores Docker desde la aplicación.

| Opción | Coste | Máquina | Comentario |
| --- | --- | --- | --- |
| **Oracle Cloud Free Tier** | Gratis, sin fecha de fin | ARM (Ampere A1), hasta 4 núcleos y 24 GB en total | Recomendada si quieres gasto cero. El alta pide tarjeta para verificar, pero no cobra. A veces no hay capacidad ARM libre en la región (ver 2.1). |
| **Hetzner Cloud CAX11** | Unos 4 €/mes | ARM, 2 núcleos y 4 GB | La más sencilla, en la UE. Hay equivalentes x86 (CX22) por un precio parecido. |
| Cualquier otro VPS | Varía | x86_64 o ARM64, 2 GB como mínimo | DigitalOcean, OVH, Contabo… El instalador funciona igual. |

Sistemas soportados: **Ubuntu 24.04 o 22.04, o Debian 12**, en x86_64 o ARM64.

## 2. Crear el servidor

### 2.1 Oracle Cloud Free Tier

1. Date de alta en cloud.oracle.com ("Start for free"). Elige una región cercana; en la cuenta gratuita no se puede cambiar después.
2. En la consola: *Compute → Instances → Create instance*.
   - **Image:** Canonical Ubuntu 24.04.
   - **Shape:** *Ampere*, `VM.Standard.A1.Flex`, con 2 OCPU y 12 GB. Entra en lo gratuito, y aún te sobra para otra máquina.
   - **SSH keys:** "Generate a key pair" y **descarga la clave privada**. Sin ella no podrás entrar.
   - Si sale *Out of capacity*, prueba otro *Availability domain* o inténtalo más tarde. Es habitual con las máquinas ARM gratuitas.
3. Abre los puertos web en la red de Oracle: en la instancia, entra en la *Subnet* y luego en su *Security List*, y pulsa *Add Ingress Rules*:
   - Source CIDR `0.0.0.0/0`, protocolo TCP, puerto de destino `80`;
   - otra regla igual con el puerto `443`.
4. Apunta la **Public IP address** de la instancia.
5. Oracle puede recuperar las instancias gratuitas que pasen mucho tiempo casi sin uso. Si te pasa, convertir la cuenta a *Pay As You Go* lo evita y sigue sin cobrar lo que esté dentro de lo gratuito. Pon una alerta de presupuesto por si acaso.

Las imágenes de Ubuntu de Oracle bloquean con iptables todo salvo SSH, aunque abras los puertos en la consola. El instalador lo detecta y abre el 80 y el 443.

### 2.2 Hetzner Cloud

1. Date de alta en hetzner.com/cloud y crea un proyecto.
2. *Add Server*: una ubicación en la UE, **Ubuntu 24.04** y el tipo **CAX11**. En *SSH keys*, añade tu clave pública (si no tienes, créala con `ssh-keygen -t ed25519`).
3. En *Firewalls*, crea uno con reglas de entrada para TCP 22, 80 y 443, y aplícalo al servidor.
4. Apunta la IPv4 pública.

## 3. Entrar al servidor

Desde tu PC (PowerShell o Terminal):
```text
ssh -i ruta/a/tu_clave ubuntu@IP_DEL_SERVIDOR      # Oracle (usuario ubuntu)
ssh root@IP_DEL_SERVIDOR                            # Hetzner (usuario root)
```

Actualiza el sistema y reinicia:
```text
sudo apt update && sudo apt full-upgrade -y && sudo reboot
```

## 4. Llevar el código

Si el repositorio ya es público:
```text
sudo apt install -y git
git clone https://github.com/miguelrr21/Dissect.git
```

Si todavía es privado, usa como contraseña un token de GitHub de **solo lectura** (*Settings → Developer settings → Fine-grained tokens*, *Contents: Read-only*). También puedes copiarlo desde tu PC:
```text
git archive --format=tar.gz -o dissect.tar.gz HEAD
scp dissect.tar.gz ubuntu@IP_DEL_SERVIDOR:~
ssh ubuntu@IP_DEL_SERVIDOR "mkdir -p Dissect && tar -xzf dissect.tar.gz -C Dissect"
```

## 5. Instalar

```text
cd ~/Dissect
sudo bash deploy/server/install.sh
```

La primera vez tarda entre 10 y 20 minutos. El script:
- instala Docker, Caddy y las actualizaciones automáticas de seguridad;
- instala uv (el gestor de Python del proyecto), comprobando su SHA-256;
- copia el código a `/opt/dissect` y construye la imagen del análisis;
- crea el usuario de servicio `dissect` y ajusta cuántos análisis a la vez caben en la máquina;
- arranca el servicio y Caddy, y abre los puertos si el sistema los bloquea.

Al final escribe la dirección: abre `http://IP_DEL_SERVIDOR`.

## 6. VirusTotal (opcional)

```text
sudo nano /etc/dissect/web.env
```
Escribe tu clave en `VT_API_KEY=...`, guarda (Ctrl+O, Enter, Ctrl+X) y reinicia:
```text
sudo systemctl restart dissect-web
```

La web funciona como la CLI: consulta el SHA-256 y, si VirusTotal no conoce el archivo, lo sube y sigue su análisis. Antes de activarlo:
- **La cuota se comparte entre todos los visitantes.** El servidor reparte la de tu clave: con la API pública, 4 peticiones por minuto y 500 al día (`DISSECT_VT_PER_MINUTE` y `DISSECT_VT_PER_DAY`). Si se agota, la web lo dice y el análisis de Dissect sigue igual. Si consigues una clave con más cuota, sube esos valores.
- **Los archivos subidos son de tus visitantes**, y VirusTotal puede compartirlos con sus clientes de pago. La web lo avisa junto a la casilla. Para no subir nunca nada: `DISSECT_VIRUSTOTAL_UPLOAD=off`.

## 7. Dominio y HTTPS (gratis con DuckDNS)

Sin dominio, la web funciona por HTTP en la IP. Para tener HTTPS:
1. **Dominio gratuito:** entra en duckdns.org con tu cuenta de GitHub o Google, crea un subdominio (por ejemplo `dissect-tutor`) y pon la IP de tu servidor. También vale un dominio comprado, con un registro **A** hacia esa IP.
2. **Edita Caddy:**
   ```text
   sudo nano /etc/caddy/Caddyfile
   ```
   Cambia `:80 {` por `dissect-tutor.duckdns.org {` (o tu dominio) y recarga:
   ```text
   sudo systemctl reload caddy
   ```
   Caddy pedirá y renovará solo el certificado, y redirigirá HTTP a HTTPS.

## 8. Límites de uso

En `/etc/dissect/web.env`:

| Variable | Por defecto | Qué hace |
| --- | --- | --- |
| `DISSECT_WEB_RATE` | `6/600` | Análisis por IP: 6 cada 600 segundos. |
| `DISSECT_WEB_CONCURRENCY` | según la máquina (1 a 3) | Análisis a la vez; cada uno usa hasta 512 MiB y 1 CPU. |
| `DISSECT_WEB_QUEUE_SECONDS` | `60` | Cuánto espera una petición antes de responder "ocupado". |
| `DISSECT_VT_PER_MINUTE`, `DISSECT_VT_PER_DAY` | `4`, `500` | Peticiones a VirusTotal para todo el servidor. |

El tamaño máximo de archivo es 20 MiB.

## 9. Comprobar que todo va bien

```text
systemctl status dissect-web caddy docker
curl http://127.0.0.1:8080/api/health
sudo journalctl -u dissect-web -n 50
```
`/api/health` responde `{"status":"ok",...}` si Docker y la imagen están disponibles. Los registros no guardan las IP de los visitantes ni los archivos.

## 10. Actualizar

```text
cd ~/Dissect && git pull && sudo bash deploy/server/update.sh
```
La actualización conserva tu `web.env` y un `Caddyfile` con tu dominio.

## 11. Seguridad del servidor

- **Entra solo con clave SSH.** Oracle y Hetzner lo configuran así por defecto; no actives contraseñas.
- **No guardes nada más en ese servidor** y no lo conectes a otras redes tuyas.
- **Las actualizaciones de seguridad están activadas** (`unattended-upgrades`). Reinicia de vez en cuando para aplicar las del kernel: `sudo reboot`.
- **El servicio está aislado.** Escucha solo en `127.0.0.1`, systemd lo encierra, y cada análisis corre en un contenedor sin red, de solo lectura y con límites.
- **Si te molestan los intentos de acceso por SSH**, `sudo apt install fail2ban` los frena.

## 12. Desinstalar

```text
sudo systemctl disable --now dissect-web
sudo rm -rf /opt/dissect /etc/dissect /var/lib/dissect /etc/systemd/system/dissect-web.service
sudo cp /etc/caddy/Caddyfile.antes-de-dissect /etc/caddy/Caddyfile 2>/dev/null; sudo systemctl reload caddy
sudo docker rmi dissect-worker:0.6.0
```
