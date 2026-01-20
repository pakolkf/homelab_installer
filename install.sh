#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# Configuración global
# -----------------------
INSTALL_LOG="/var/log/homelab-install.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PATH="/opt/homelab"

# Flags globales
RUN=false
ALL_PRIVACY=false
ADGUARD=false
UNBOUND=false
DRY_RUN=false

# Flags Traefik
TRAEFIK_PROVIDER="cloudflare"
TRAEFIK_CF_API_TOKEN=""
TRAEFIK_EMAIL=""
TRAEFIK_DOMAIN=""
TRAEFIK_USER=""
TRAEFIK_PASSWORD=""
DASHBOARD_AUTH=false
DASHBOARD_LAN_ONLY=false

# Flags arcane agent
ENVIRONMENT="production"
INSTALL_AGENT_ARCANE="false"
AGENT_TOKEN=""
ARCANE_MAIN_IP=""
ARCANE_MAIN_PORT=""

DOCKER_BASE=""
MACHINE_IP=$(hostname -I | awk '{print $1}')

show_help() {
    cat <<EOF
Uso: $0 [opciones]

===========================================================
  MODO SERVIDOR (por defecto)
===========================================================
Si NO usas --install-agent-arcane, este instalador desplegará:

  ✔ Traefik (obligatorio)
  ✔ Arcane Server (obligatorio)
  ✔ Opcionalmente: AdGuard, Unbound o el stack completo

IMPORTANTE:
  Traefik SIEMPRE usa Cloudflare como provider.
  Por tanto, todos los parámetros de Cloudflare son obligatorios
  en modo servidor.

===========================================================
  OPCIONES GLOBALES
===========================================================
  --run                                     Ejecuta la instalación (modo root)
  --env <production|development|test>       Entorno del homelab (por defecto: production)
  --install-agent-arcane                    Instala un agente Arcane en lugar del servidor principal
  --agent-token <token>                     Token del agente generado por el manager Arcane
  --arcane-main-ip <ip>                     IP del servidor manager Arcane
  --arcane-main-port <puerto>               Puerto del servidor manager Arcane
  --all-privacy                             Instala AdGuard + Unbound
  --adguard                                 Instala solo AdGuard
  --unbound                                 Instala solo Unbound
  --install-path <ruta>                     Ruta base de instalación (por defecto: /opt/homelab)
  -h, --help                                Muestra esta ayuda

Restricciones:
  --all-privacy no puede combinarse con --adguard ni --unbound

===========================================================
  OPCIONES TRAEFIK (OBLIGATORIAS EN MODO SERVIDOR)
===========================================================
  --traefik-cf-token <token cloudflare>     Token API de Cloudflare
  --traefik-email <email>                   Email para certificados ACME
  --traefik-domain <dominio>                Dominio base para Traefik
  --traefik-user <usuario>                  Usuario para dashboard
  --traefik-password <password>             Password para dashboard
  --dashboard-auth                          Habilita autenticación básica en el dashboard
  --dashboard-lan-only                      Restringe acceso al dashboard solo a la LAN

===========================================================
  EJEMPLOS DE USO
===========================================================

# 1. Instalar el stack completo de privacidad (AdGuard + Unbound)
sudo $0 --run --all-privacy \\
    --traefik-cf-token ABC123 \\
    --traefik-email admin@dominio.com \\
    --traefik-domain midominio.com

# 2. Instalar solo AdGuard
sudo $0 --run --adguard \\
    --traefik-cf-token ABC123 \\
    --traefik-email admin@dominio.com \\
    --traefik-domain midominio.com

# 3. Instalar solo Unbound
sudo $0 --run --unbound \\
    --traefik-cf-token ABC123 \\
    --traefik-email admin@dominio.com \\
    --traefik-domain midominio.com

# 4. Instalar Traefik (siempre requerido en modo servidor)
sudo $0 --run \\
    --traefik-cf-token ABC123 \\
    --traefik-email admin@dominio.com \\
    --traefik-domain midominio.com

# 5. Traefik con autenticación en dashboard
sudo $0 --run \\
    --traefik-cf-token ABC123 \\
    --traefik-email admin@dominio.com \\
    --traefik-domain midominio.com \\
    --traefik-user admin --traefik-password 1234 \\
    --dashboard-auth

# 6. Traefik con restricción LAN-only
sudo $0 --run \\
    --traefik-cf-token ABC123 \\
    --traefik-email admin@dominio.com \\
    --traefik-domain midominio.com \\
    --dashboard-lan-only

# 7. Instalar un agente Arcane (NO instala Traefik ni Arcane Server)
sudo $0 --run --install-agent-arcane \\
    --agent-token TOKEN123 \\
    --arcane-main-ip 192.168.1.10 \\
    --arcane-main-port 8080

EOF
}

print_header() {
    clear
    echo "== Instalador homelab =="
}

ensure_install_log() {
    INSTALL_LOG="/var/log/homelab-install.log"
    rm -f "$INSTALL_LOG" 2>/dev/null || true
    touch "$INSTALL_LOG" 2>/dev/null || true
    chmod 0644 "$INSTALL_LOG" 2>/dev/null || true
}

maybe_reexec_as_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo
    echo "Se necesitan privilegios de administrador. Re-ejecutando con sudo..."
    sudo INSTALL_PATH="$INSTALL_PATH" bash "$0" --run
    exit $?
  fi
}

is_container() {
  if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container >/dev/null 2>&1; then
    return 0
  fi
  if grep -E -i 'docker|lxc|container' /proc/1/cgroup >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

update_system() {
  echo
  echo "Actualizando índices de paquetes..."

  if [ -f /etc/needrestart/needrestart.conf ]; then
    sed -i 's/^\$nrconf{restart}.*/$nrconf{restart} = "a";/' /etc/needrestart/needrestart.conf || true
    sed -i 's/^\$nrconf{kernelhints}.*/$nrconf{kernelhints} = 0;/' /etc/needrestart/needrestart.conf || true
    sed -i 's/^\$nrconf{ui}.*/$nrconf{ui} = "noninteractive";/' /etc/needrestart/needrestart.conf || true
  fi

  export NEEDRESTART_MODE=a
  export DEBIAN_FRONTEND=noninteractive

  if ! apt update >>"${INSTALL_LOG}" 2>&1; then
    echo "⚠️  Aviso: 'apt update' falló. Revisa ${INSTALL_LOG}"
  fi

  if ! apt upgrade -y >>"${INSTALL_LOG}" 2>&1; then
    echo "⚠️  Aviso: 'apt upgrade' falló. Revisa ${INSTALL_LOG}"
  fi

  echo "Actualización del sistema completada."
}

purge_system() {
    clear
    echo "⚠️  Atención:"
    echo "Se va a eliminar la carpeta de instalación:"
    echo "  ${INSTALL_PATH}"
    echo
    echo "Pulsa Ctrl+C para cancelar."
    echo
    echo "La eliminación comenzará en 5 segundos..."
    echo
    sleep 5

    rm -rf "${INSTALL_PATH}"
    echo "Carpeta eliminada."
    sleep 5
}

config_cron_auto_update() {
  echo
  echo "-> Configurando tarea automática de actualización (cron)..."

  local cron_line='0 3 * * * echo "===== Inicio actualización: $(date) =====" >> /var/log/auto-update.log && /usr/bin/apt update >> /var/log/auto-update.log 2>&1 && /usr/bin/apt -y upgrade >> /var/log/auto-update.log 2>&1 && echo "===== Fin actualización: $(date) =====" >> /var/log/auto-update.log'

  # Obtener crontab actual (si no existe, usar vacío)
  local current_cron
  current_cron="$(crontab -l 2>/dev/null || true)"

  if ! echo "$current_cron" | grep -Fq "$cron_line"; then
    {
      echo "$current_cron"
      echo "$cron_line"
    } | crontab -
    echo "Tarea añadida al crontab."
  else
    echo "La tarea ya existe en el crontab."
  fi

  touch /etc/logrotate.d/auto-update || true
  chmod 755 /var/log || true
  chown root:root /var/log || true
}

config_cron_fix_permissions() {
  echo
  echo "-> Configurando corrección automática de permisos (${INSTALL_PATH})..."

  DOCKER_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
  local cron_line="0 3 * * * /bin/chown ${DOCKER_USER}:${DOCKER_USER} -R ${INSTALL_PATH} >> ${INSTALL_LOG} 2>&1"

  # Obtener crontab actual
  local current_cron
  current_cron="$(crontab -l 2>/dev/null || true)"

  if ! echo "$current_cron" | grep -Fq "$cron_line"; then
    {
      echo "$current_cron"
      echo "$cron_line"
    } | crontab -
    echo "Tarea de permisos añadida al crontab."
  else
    echo "La tarea de permisos ya existe en el crontab."
  fi

  # Ejecutar inmediatamente al final de la instalación
  echo "Aplicando permisos ahora mismo..."
  chown "${DOCKER_USER}:${DOCKER_USER}" -R "${INSTALL_PATH}"
}

disable_ip_v6() {
  echo
  echo "-> Deshabilitando IPv6 a nivel de sistema..."
  local sysctl_file="/etc/sysctl.d/99-disable-ipv6.conf"

  cat > "$sysctl_file" <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

  sysctl --system >>"${INSTALL_LOG}" 2>&1 || true

  if [ -f /etc/default/grub ]; then
    if ! grep -q "ipv6.disable=1" /etc/default/grub; then
      sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' /etc/default/grub || true
      if command -v update-grub >/dev/null 2>&1; then
        update-grub || true
      fi
      echo "Parámetro ipv6.disable=1 añadido en GRUB."
    fi
  elif [ -f /boot/cmdline.txt ]; then
    if ! grep -q "ipv6.disable=1" /boot/cmdline.txt; then
      sed -i 's/$/ ipv6.disable=1/' /boot/cmdline.txt || true
      echo "Parámetro ipv6.disable=1 añadido en cmdline.txt."
    fi
  else
    echo "No se encontró ni GRUB ni cmdline.txt."
  fi

  echo "IPv6 deshabilitado."
}

get_ram_mb() {
  awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo
}

recommend_swap_mb() {
  local ram_mb=$1

  if [ "$ram_mb" -le 2048 ]; then
    echo "$ram_mb"
  elif [ "$ram_mb" -le 8192 ]; then
    echo $(( ram_mb / 2 ))
  else
    echo 4096
  fi
}

create_swapfile() {
  local swapfile=$1
  local size=$2
  local mb=$3
  local available_mb=$(df --output=avail / | tail -1)
  local available_mb=$(( available_mb / 1024 ))

  if [ "$available_mb" -lt "$mb" ]; then
      echo "Error: espacio insuficiente en disco. Disponible: ${available_mb} MB, requerido: ${mb} MB"
      return 1
  fi

  if [ -f "$swapfile" ]; then
    echo "Swapfile $swapfile ya existe."
    return 0
  fi

  echo "Creando swapfile de $size en $swapfile..."

  if ! fallocate -l "$size" "$swapfile" 2>/dev/null; then
    echo "fallocate falló; usando dd..."
    if ! dd if=/dev/zero of="$swapfile" bs=1M count="$mb" status=progress; then
        echo "Error: no hay suficiente espacio en disco."
        rm -f "$swapfile"
        return 1
    fi
  fi

  chmod 600 "$swapfile"
  mkswap "$swapfile"
}

activate_swap() {
  local swapfile=$1

  swapon "$swapfile" || return 1

  if ! grep -q "^$swapfile " /etc/fstab; then
    echo "$swapfile none swap sw 0 0" >> /etc/fstab
  fi

  sysctl vm.swappiness=10 >/dev/null
  if ! grep -q "^vm.swappiness=10" /etc/sysctl.conf; then
    echo "vm.swappiness=10" >> /etc/sysctl.conf
  fi
}

create_mem_swap() {
  local SWAPFILE="/swapfile"

  if is_container; then
    echo
    echo "Aviso: ejecución dentro de un contenedor. Operación omitida."
    return 0
  fi

  if swapon --show | awk '{print $1}' | grep -qx "$SWAPFILE"; then
    echo
    echo "Swapfile ya activo."
    return 0
  fi

  local ram_mb
  local max_mb
  local rec_mb
  local mb
  local size

  ram_mb=$(get_ram_mb)
  max_mb=$(( ram_mb / 2 ))
  rec_mb=$(recommend_swap_mb "$ram_mb")

  # Asegurar límites
  if [ "$rec_mb" -gt "$max_mb" ]; then
    rec_mb="$max_mb"
  fi

  if [ "$rec_mb" -le 0 ]; then
    echo
    echo "Tamaño de swap inválido."
    return 1
  fi

  mb="$rec_mb"
  size="${mb}M"

  echo
  echo "RAM detectada: ${ram_mb} MB"
  echo "Creando swap automático: ${mb} MB (máx ${max_mb} MB)"
  echo

  create_swapfile "$SWAPFILE" "$size" "$mb" || return 1
  activate_swap "$SWAPFILE" || return 1

  echo "Swap configurado correctamente."
}

check_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --run) RUN=true ;;
            --dry-run) DRY_RUN=true ;;
            --env)
                ENVIRONMENT="$2"
                shift
                ;;
            --install-agent-arcane)
                INSTALL_AGENT_ARCANE="true"
                ;;
            --agent-token)
                AGENT_TOKEN="$2"
                shift
                ;;
            --arcane-main-ip)
                ARCANE_MAIN_IP="$2"
                shift
                ;;
            --arcane-main-port)
                ARCANE_MAIN_PORT="$2"
                shift
                ;;
            --all-privacy)
                if [[ "$ADGUARD" == "true" || "$UNBOUND" == "true" ]]; then
                    echo "Error: --all-privacy no puede usarse junto con --adguard o --unbound"
                    exit 1
                fi
                ALL_PRIVACY=true
                ;;
            --adguard)
                if [[ "$ALL_PRIVACY" == "true" ]]; then
                    echo "Error: --adguard no puede usarse junto con --all-privacy"
                    exit 1
                fi
                ADGUARD=true
                ;;
            --unbound)
                if [[ "$ALL_PRIVACY" == "true" ]]; then
                    echo "Error: --unbound no puede usarse junto con --all-privacy"
                    exit 1
                fi
                UNBOUND=true
                ;;
            --install-path)
                INSTALL_PATH="${2:-}"
                if [[ -z "$INSTALL_PATH" ]]; then
                    echo "Error: --install-path requiere un valor"
                    exit 1
                fi
                shift
                ;;
            --traefik-cf-token)
                TRAEFIK_CF_API_TOKEN="${2:-}"
                if [[ -z "$TRAEFIK_CF_API_TOKEN" ]]; then
                    echo "Error: --traefik-cf-token requiere un valor"
                    exit 1
                fi
                shift
                ;;
            --traefik-email)
                TRAEFIK_EMAIL="${2:-}"
                if [[ -z "$TRAEFIK_EMAIL" ]]; then
                    echo "Error: --traefik-email requiere un valor"
                    exit 1
                fi
                shift
                ;;
            --traefik-domain)
                TRAEFIK_DOMAIN="${2:-}"
                if [[ -z "$TRAEFIK_DOMAIN" ]]; then
                    echo "Error: --traefik-domain requiere un valor"
                    exit 1
                fi
                shift
                ;;
            --traefik-user)
                TRAEFIK_USER="${2:-}"
                if [[ -z "$TRAEFIK_USER" ]]; then
                    echo "Error: --traefik-user requiere un valor"
                    exit 1
                fi
                shift
                ;;
            --traefik-password)
                TRAEFIK_PASSWORD="${2:-}"
                if [[ -z "$TRAEFIK_PASSWORD" ]]; then
                    echo "Error: --traefik-password requiere un valor"
                    exit 1
                fi
                shift
                ;;
            --dashboard-auth) DASHBOARD_AUTH=true ;;
            --dashboard-lan-only) DASHBOARD_LAN_ONLY=true ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Opción desconocida: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done

    # Validaciones
    if [[ ! "$INSTALL_PATH" =~ ^/ ]]; then
        echo "Error: INSTALL_PATH debe ser una ruta absoluta"
        exit 1
    fi

    if [[ -n "$ENVIRONMENT" ]]; then
        case "$ENVIRONMENT" in
            production|development|test) ;;
            *)
                echo "Error: valor inválido para --env. Debe ser: production, development o test"
                exit 1
                ;;
        esac
    fi

    if [[ "$INSTALL_AGENT_ARCANE" == "true" ]]; then
        if [[ -z "$AGENT_TOKEN" || -z "$ARCANE_MAIN_IP" || -z "$ARCANE_MAIN_PORT" ]]; then
            echo "ERROR: Para instalar un agente de Arcane debes especificar:"
            echo "  --agent-token <token>"
            echo "  --arcane-main-ip <ip>"
            echo "  --arcane-main-port <puerto>"
            exit 1
        fi
        return
    fi

    if [[ "$ALL_PRIVACY" == "false" && "$ADGUARD" == "false" && "$UNBOUND" == "false" ]]; then
        echo "Error: debes indicar al menos una opción de instalación"
        show_help
        exit 1
    fi

    # Validar dominio
    if [[ -z "$TRAEFIK_DOMAIN" ]]; then
        echo "Error: --traefik-domain es obligatorio"
        exit 1
    fi

    # Validar email
    if [[ -z "$TRAEFIK_EMAIL" ]]; then
        echo "Error: --traefik-email es obligatorio"
        exit 1
    fi

    # Validar token Cloudflare
    if [[ -z "$TRAEFIK_CF_API_TOKEN" ]]; then
        echo "Error: --traefik-cf-token es obligatorio"
        exit 1
    fi

    # Validar formato email
    if ! [[ "$TRAEFIK_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
        echo "Error: email inválido"
        exit 1
    fi

}

purge_docker() {
  clear
  if ! command -v docker &> /dev/null; then
    echo "Docker no está instalado."
    sleep 5
    return 0
  fi

  echo "⚠️  ATENCIÓN: Se eliminarán todos los contenedores, imágenes, volúmenes y redes."
  echo "   La limpieza comenzará en 5 segundos."
  
  echo
  echo "Presiona Ctrl+C para cancelar."
  echo
  sleep 5

  echo "Deteniendo y eliminando todos los contenedores..."
  docker stop $(docker ps -aq) 2>/dev/null >>"${INSTALL_LOG}" 2>&1 || true
  docker rm $(docker ps -aq) 2>/dev/null >>"${INSTALL_LOG}" 2>&1 || true

  echo "Eliminando imágenes, redes y volúmenes no utilizados..."
  docker system prune -a --volumes -f >>"${INSTALL_LOG}" 2>&1 || true

  echo "Eliminando paquetes relacionados..."
  apt remove -y docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc >>"${INSTALL_LOG}" 2>&1 || true
  echo

  echo "✅ Limpieza completa de Docker finalizada."
  sleep 5
}

install_docker() {
  echo
  echo "-> Instalando Docker..."
  echo

  echo "Instalando dependencias requeridas..."
  apt install -y ca-certificates curl >>"${INSTALL_LOG}" 2>&1 || true

  echo "Preparando keyring apt..."
  install -m 0755 -d /etc/apt/keyrings >>"${INSTALL_LOG}" 2>&1 || true
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc >>"${INSTALL_LOG}" 2>&1 || true
  chmod a+r /etc/apt/keyrings/docker.asc >>"${INSTALL_LOG}" 2>&1 || true

  echo "Añadiendo repositorio oficial de Docker..."
  tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  echo "Actualizando índices..."
  apt update >>"${INSTALL_LOG}" 2>&1 || true

  echo "Instalando Docker Engine..."
  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >>"${INSTALL_LOG}" 2>&1 || true

  echo "Configurando grupo 'docker'..."
  groupadd docker >>"${INSTALL_LOG}" 2>&1 || true

  DOCKER_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
  usermod -aG docker "$DOCKER_USER" >>"${INSTALL_LOG}" 2>&1 || true

  echo "Verificando instalación de Docker..."
  docker --version >>"${INSTALL_LOG}" 2>&1 || echo "Docker no se instaló correctamente."

  echo "Asegurando que la interfaz docker0 esté activa..."
  ip link set docker0 up

  echo "Verificando si Docker está corriendo..."
  if systemctl is-active --quiet docker; then
    echo "Docker ya está corriendo."
  else
    echo "Iniciando Docker..."
    systemctl start docker >>"${INSTALL_LOG}" 2>&1 || echo "Error al intentar iniciar Docker."
  fi

  echo
  echo "-> Instalación de Docker finalizada."
}

create_docker_networks() {
  echo
  echo "Creando redes necesarias..."
  echo

  if [[ "$INSTALL_AGENT_ARCANE" == "true" ]]; then
      # Crear red 'socket-proxy'
      if ! docker network ls --format '{{.Name}}' | grep -q "^socket-proxy$"; then
        docker network create socket-proxy >>"${INSTALL_LOG}" 2>&1 || true
        echo "Red 'socket-proxy' creada."
      else
        echo "Red 'socket-proxy' ya existe."
      fi
      return
  fi

  # Crear red 'socket-proxy'
  if ! docker network ls --format '{{.Name}}' | grep -q "^socket-proxy$"; then
    docker network create socket-proxy >>"${INSTALL_LOG}" 2>&1 || true
    echo "Red 'socket-proxy' creada."
  else
    echo "Red 'socket-proxy' ya existe."
  fi

  # Crear red 'traefik'
  if ! docker network ls --format '{{.Name}}' | grep -q "^traefik$"; then
    docker network create traefik >>"${INSTALL_LOG}" 2>&1 || true
    echo "Red 'traefik' creada."
  else
    echo "Red 'traefik' ya existe."
  fi

  # Crear red 'dns_net' solo si $ALL_PRIVACY es verdadero
  if [[ "$ALL_PRIVACY" == "true" ]]; then
    if ! docker network ls --format '{{.Name}}' | grep -q "^dns_net$"; then
      docker network create dns_net >>"${INSTALL_LOG}" 2>&1 || true
      echo "Red 'dns_net' creada."
    else
      echo "Red 'dns_net' ya existe."
    fi
  else
    echo "Red 'dns_net' omitida: ALL_PRIVACY no está activado."
  fi
}

create_adguard_resolved_conf() {
  echo "-> Creando configuración para systemd-resolved hacia AdGuardHome..."
  local dest_dir="/etc/systemd/resolved.conf.d"
  local dest_file="$dest_dir/adguardhome.conf"
  local resolv_target="/run/systemd/resolve/resolv.conf"
  local tmp_file="$(mktemp)"

  mkdir -p "$dest_dir"
  if [ -f "$dest_file" ]; then
    cp --preserve=mode,timestamps "$dest_file" "$dest_file".bak."$(date +%s)" || true
  fi

  cat > "$tmp_file" <<'EOF'
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
EOF

  install -m 0644 "$tmp_file" "$dest_file"
  rm -f "$tmp_file"
  echo "Guardado en $dest_file"

  if [ -e /etc/resolv.conf ] || [ -L /etc/resolv.conf ]; then
    if [ -L /etc/resolv.conf ]; then
      local current_target="$(readlink -f /etc/resolv.conf)"
      if [ "$current_target" = "$resolv_target" ]; then
        echo "/etc/resolv.conf ya apunta a $resolv_target"
      else
        mv /etc/resolv.conf /etc/resolv.conf.backup."$(date +%s)" || true
        ln -sf "$resolv_target" /etc/resolv.conf
        echo "Replaced /etc/resolv.conf symlink -> $resolv_target"
      fi
    else
      mv /etc/resolv.conf /etc/resolv.conf.backup."$(date +%s)" || true
      ln -sf "$resolv_target" /etc/resolv.conf
      echo "Backed up /etc/resolv.conf and created symlink -> $resolv_target"
    fi
  else
    ln -sf "$resolv_target" /etc/resolv.conf || true
    echo "Created symlink /etc/resolv.conf -> $resolv_target"
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all | grep -q "systemd-resolved"; then
    systemctl reload-or-restart systemd-resolved || true
    echo "systemd-resolved reloaded or restarted"
  fi
}

generate_adguard_files() {
  echo
  echo "-> Generando ficheros para Adguard-home..."
  local out_work="${DOCKER_BASE}/adguard-home/work"
  local out_config="${DOCKER_BASE}/adguard-home/config"

  mkdir -p "$out_work" "$out_config" "${DOCKER_BASE}/traefik/dynamic"

  install -m 0644 ./docker_files/traefik/dynamic/adguard-home.yaml "${DOCKER_BASE}/traefik/dynamic/adguard-home.yaml"
  traefik_update_adguard_home_fqdn

  if [[ "$ALL_PRIVACY" == "true" || ("$ADGUARD" == "true" && "$UNBOUND" == "true") ]]; then
    mkdir -p "${DOCKER_BASE}/arcane/projects/network-privacy"
    install -m 0644 ./docker_files/adguard/docker-compose.unbound.yaml "${DOCKER_BASE}/arcane/projects/network-privacy/docker-compose.yaml"
  else
    mkdir -p "${DOCKER_BASE}/arcane/projects/adguard-home"
    install -m 0644 ./docker_files/adguard/docker-compose.yaml "${DOCKER_BASE}/arcane/projects/adguard-home/docker-compose.yaml"
  fi  

  echo "Adguard-home: rutas preparadas en ${DOCKER_BASE}/adguard-home"
}

set_unbound_sysctl() {
  echo
  echo "-> Aplicando ajustes sysctl para Unbound..."
  local dest_file="/etc/sysctl.d/unbound.conf"
  local dir="$(dirname "$dest_file")"
  local timestamp="$(date +%s)"

  mkdir -p "$dir"
  if [ -f "$dest_file" ]; then
    cp --preserve=mode,timestamps "$dest_file" "$dest_file".bak."$timestamp" || true
    echo "Backup creado: $dest_file.bak.$timestamp"
  fi

  local curr_rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
  local curr_wmem=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)
  local desired=1048576

  if [ "$curr_rmem" -lt "$desired" ]; then
    set_rmem=$desired
  else
    set_rmem=$curr_rmem
  fi
  if [ "$curr_wmem" -lt "$desired" ]; then
    set_wmem=$desired
  else
    set_wmem=$curr_wmem
  fi

  declare -A KV
  KV[net.core.rmem_max]=$set_rmem
  KV[net.core.wmem_max]=$set_wmem

  touch "$dest_file"
  for key in "${!KV[@]}"; do
    line="$key=${KV[$key]}"
    if grep -Eq "^${key}=" "$dest_file" 2>/dev/null; then
      sed -i "s|^${key}=.*|${line}|" "$dest_file" || true
      echo "Reemplazado: $line"
    else
      echo "$line" >> "$dest_file"
      echo "Añadido: $line"
    fi
  done

  sysctl --system >>"${INSTALL_LOG}" 2>&1 || true
  echo "Fichero actualizado: $dest_file"
}

generate_unbound_files() {
  echo
  echo "-> Generando ficheros para Unbound..."
  local out_custom="${DOCKER_BASE}/unbound/custom.conf.d"
  local out_root="${DOCKER_BASE}/unbound/root"
  local out_run="${DOCKER_BASE}/unbound/run"
  local out_logs="${DOCKER_BASE}/unbound/logs"
  local hints="$out_root/root.hints"
  local key="$out_root/root.key"
  local logfile="$out_logs/unbound.log"

  echo "Instalando dependencias requeridas..."
  apt install -y dnsutils >>"${INSTALL_LOG}" 2>&1 || true

  mkdir -p "$out_custom" "$out_root" "$out_run" "$out_logs"

  echo "Descargando root hints a: $hints"
  if command -v curl >/dev/null 2>&1; then
    curl -sSL https://www.internic.net/domain/named.root -o "$hints" || true
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$hints" https://www.internic.net/domain/named.root || true
  else
    echo "Aviso: no se ha encontrado 'curl' ni 'wget'." >&2
  fi

  touch "$key" || true
  touch "$logfile" || true
  chmod 0644 "$logfile" || true

  install -m 0644 ./docker_files/unbound/custom.conf.d/* "${DOCKER_BASE}/unbound/custom.conf.d/"
  if [[ "$ALL_PRIVACY" == "true" || ("$ADGUARD" == "true" && "$UNBOUND" == "true") ]]; then
    mkdir -p "${DOCKER_BASE}/arcane/projects/network-privacy"
    install -m 0644 ./docker_files/unbound/docker-compose.adguard.yaml "${DOCKER_BASE}/arcane/projects/network-privacy/docker-compose.yaml"
  else
    mkdir -p "${DOCKER_BASE}/arcane/projects/unbound"
    install -m 0644 ./docker_files/unbound/docker-compose.yaml "${DOCKER_BASE}/arcane/projects/unbound/docker-compose.yaml"
  fi  

  echo "Unbound: rutas preparadas en ${DOCKER_BASE}/unbound"
}

traefik_generate_basic_auth_user() {
  local user="$1"
  local password="$2"
  local basic_hash=""

  if [[ -z "$user" || -z "$password" ]]; then
    echo "Error: TRAEFIK_USER y TRAEFIK_PASSWORD deben estar definidos"
    exit 1
  fi

  # Generar hash bcrypt (-B) sin interacción
  basic_hash=$(htpasswd -B -i -n "$user" <<< "$password")

  traefik_update_auth_middleware "$basic_hash"
}

traefik_update_auth_middleware() {
  local basic_auth_entry="$1"
  local file="${DOCKER_BASE}/traefik/dynamic/middlewares.yaml"

  # Si no existe el bloque auth:, lo añadimos
  if ! grep -q "auth:" "$file"; then
    cat >> "$file" <<EOF

    auth:
      basicAuth:
        users:
          - "$basic_auth_entry"
EOF
    echo "Añadido middleware auth."
    return
  fi

  # Si existe, lo actualizamos
  sed -i '/auth:/,/^[^ ]/ { /users:/,/^[^ ]/d }' "$file"
  sed -i "/basicAuth:/a\        users:\n          - \"${basic_auth_entry}\"" "$file"

  echo "Middleware auth actualizado."
}

traefik_attach_auth_to_dashboard() {
  local traefik_conf="${DOCKER_BASE}/traefik/dynamic/traefik.yaml"

  if ! grep -q "middlewares:" "$traefik_conf"; then
    sed -i "/service:/a\      middlewares:\n        - auth" "$traefik_conf"
  else
    sed -i "/middlewares:/a\        - auth" "$traefik_conf"
  fi

  echo "Middleware de autenticación añadido al dashboard de Traefik."
  echo
}

traefik_update_dashboard_fqdn_generic() {
  echo
  local file="$1"
  local fqdn="$2"
  local machine_ip="$3"

  if [ ! -f "$file" ]; then
    echo "No se encontró $file, no se puede actualizar el FQDN."
    return
  fi

  echo "Actualizando FQDN en $file → $fqdn"
  sed -i "s|Host(\`.*\`)|Host(\`${fqdn}\`)|" "$file"

  if [ -n "$machine_ip" ]; then
    sed -i -E "s|(url: \"http://)[^\":]+(:[0-9]+\")|\1${machine_ip}\2|" "$file"
  fi
}

traefik_update_adguard_home_fqdn() {
  local file="${INSTALL_PATH}/docker/traefik/dynamic/adguard-home.yaml"
  local fqdn="adguard-home.${TRAEFIK_DOMAIN:-local}"
  traefik_update_dashboard_fqdn_generic "$file" "$fqdn" "$MACHINE_IP"
}

traefik_update_dashboard_fqdn() {
  local file="${INSTALL_PATH}/docker/traefik/dynamic/traefik.yaml"
  local fqdn="traefik.${TRAEFIK_DOMAIN:-local}"
  traefik_update_dashboard_fqdn_generic "$file" "$fqdn" ""
}

traefik_update_arcane_fqdn() {
  local file="${INSTALL_PATH}/docker/traefik/dynamic/arcane.yaml"
  local fqdn="arcane.${TRAEFIK_DOMAIN:-local}"
  traefik_update_dashboard_fqdn_generic "$file" "$fqdn" "$MACHINE_IP"
}

traefik_update_lan_middleware() {
  local file="${DOCKER_BASE}/traefik/dynamic/middlewares.yaml"
  local iface=$(ip route show default | awk '{print $5}')
  local local_net=$(ip -o -f inet route show dev "$iface" | awk '/src/ {print $1; exit}')

  if [ -z "$local_net" ]; then
    echo "No se pudo detectar la red LAN."
    return
  fi

  # Si no existe el bloque lanOnly:, lo añadimos
  if ! grep -q "lanOnly:" "$file"; then
    cat >> "$file" <<EOF

    lanOnly:
      ipWhiteList:
        sourceRange:
          - 172.16.0.0/16
          - $local_net
EOF
    echo "Añadido middleware lanOnly."
    return
  fi

  # Si existe, añadimos la red si no está
  if ! grep -q "$local_net" "$file"; then
    sed -i "/sourceRange:/a\          - ${local_net}" "$file"
    echo "Añadido rango LAN $local_net."
  else
    echo "La red LAN ya estaba incluida."
  fi
}

traefik_attach_lan_only() {
  local traefik_conf="${INSTALL_PATH}/docker/traefik/dynamic/traefik.yaml"

  if ! grep -q "middlewares:" "$traefik_conf"; then
    sed -i "/service:/a\      middlewares:\n        - lanOnly" "$traefik_conf"
  else
    sed -i "/middlewares:/a\        - lanOnly" "$traefik_conf"
  fi

  echo "Middleware de red local añadido al dashboard de Traefik."
}

install_traefik() {
    echo
    echo "Instalando Traefik..."

    local provider=""
    local token=""
    local domain=""
    local email=""
    local user=""
    local password=""
    local dashboard_auth=false
    local dashboard_lan_only=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --provider) provider="$2"; shift ;;
            --token) token="$2"; shift ;;
            --domain) domain="$2"; shift ;;
            --email) email="$2"; shift ;;
            --user) user="$2"; shift ;;
            --password) password="$2"; shift ;;
            --dashboard-auth) dashboard_auth=true ;;
            --dashboard-lan-only) dashboard_lan_only=true ;;
            *) echo "Opción desconocida en install_traefik: $1"; exit 1 ;;
        esac
        shift
    done

    echo
    echo "-> Configurando Traefik..."
    echo
    echo "Provider: $provider"
    echo "Dominio: $domain"
    [[ -n "$email" ]] && echo "Email: $email"
    echo

    # Crear directorios necesarios
    mkdir -p \
        "${DOCKER_BASE}/traefik/dynamic" \
        "${DOCKER_BASE}/traefik/ssl/staging" \
        "${DOCKER_BASE}/traefik/ssl/prod" \
        "${DOCKER_BASE}/traefik/logs"

    for file in "${DOCKER_BASE}/traefik/ssl/prod/acme.json" "${DOCKER_BASE}/traefik/ssl/staging/acme.json"; do
        if [ ! -f "$file" ]; then
            touch "$file"
        fi
        chmod 600 "$file" || true
    done

    install -m 0644 ./docker_files/traefik/dynamic/serversTransports.yaml "${DOCKER_BASE}/traefik/dynamic/serversTransports.yaml"

    install -m 0644 ./docker_files/traefik/dynamic/middlewares.yaml "${DOCKER_BASE}/traefik/dynamic/middlewares.yaml"

    install -m 0644 ./docker_files/traefik/dynamic/traefik.yaml "${DOCKER_BASE}/traefik/dynamic/traefik.yaml"
    install -m 0644 ./docker_files/traefik/dynamic/wildcard.yaml "${DOCKER_BASE}/traefik/dynamic/wildcard.yaml"
    install -m 0644 ./docker_files/traefik/dynamic/_app-template.txt "${DOCKER_BASE}/traefik/dynamic/_app-template.txt"

    mkdir -p "${DOCKER_BASE}/arcane/projects/traefik"
    install -m 0644 ./docker_files/traefik/docker-compose.yaml "${DOCKER_BASE}/arcane/projects/traefik/docker-compose.yaml"

        cat > "${DOCKER_BASE}/arcane/projects/traefik/.env" <<EOF
CF_DNS_API_TOKEN=${token}
EOF

    for line in "$@"; do
        echo "$line" >> "$file"
    done

    # Configurar provider
    if [[ "$provider" == "cloudflare" ]]; then
        install -m 0644 ./docker_files/traefik/config/traefik.cloudflare.yaml "${DOCKER_BASE}/traefik/traefik.yaml"
        echo "Configuración de Traefik para Cloudflare aplicada."
    fi

    sed -i "s|email: admin@mi-dominio.es|email: ${email}|" "${DOCKER_BASE}/traefik/traefik.yaml"
    sed -i "s|mi-dominio.es|${domain}|g" "${DOCKER_BASE}/traefik/traefik.yaml"

    # Configurar middlewares dashboard
    if $dashboard_auth; then
        echo
        echo "-> Aplicando middleware Auth al dashboard..."
        traefik_generate_basic_auth_user "$user" "$password"
        traefik_attach_auth_to_dashboard
        echo "Middleware: Auth activado"
        # Aquí se generaría archivo de usuarios/password o config en YAML
    fi

    if $dashboard_lan_only; then
        echo
        echo "-> Aplicando middleware LAN-only al dashboard..."
        traefik_update_lan_middleware
        traefik_attach_lan_only
        echo "Middleware: LAN-only activado"
        # Aquí se generaría la restricción de red local en YAML
    fi

    traefik_update_dashboard_fqdn
    echo "-> Traefik preparado en ${DOCKER_BASE}/traefik"
}

show_access_traefik_info() {
  if [ "${DASHBOARD_AUTH}" = true ]; then
    echo "========================================================================"
    echo " Traefik protegido con autenticación básica"
    echo "========================================================================"
    echo "Credenciales:"
    echo "  Usuario: ${TRAEFIK_USER}"
    echo "  Contraseña: ${TRAEFIK_PASSWORD}"
    echo "========================================================================"
  fi
}

arcane_start() {
    ARCANE_DIR="${INSTALL_PATH}/docker/arcane"
    echo

    if [ ! -f "${ARCANE_DIR}/docker-compose.yaml" ]; then
        echo "ERROR: No se encuentra docker-compose.yaml en ${ARCANE_DIR}"
        echo "No se puede levantar Arcane."
        return
    fi

    echo "Levantando Arcane..."
    docker compose -f "${ARCANE_DIR}/docker-compose.yaml" up -d >>"${INSTALL_LOG}" 2>&1 || true

    echo "Arcane iniciado correctamente."
    show_access_arcane_info
}

show_access_arcane_info() {
    echo
    echo "========================================================================"
    echo " Acceso a Arcane"
    echo "========================================================================"
    echo "Arcane se ha instalado correctamente."
    echo
    echo "Dominio configurado:"
    echo " → https://arcane.${TRAEFIK_DOMAIN:-local}"
    echo "Este dominio ya está creado, pero NO será accesible hasta que habilites"
    echo "Traefik manualmente desde Arcane."
    echo
    echo "Requisitos para usar el dominio:"
    echo "  1. Habilitar Traefik desde el panel de Arcane."
    echo "  2. Redirigir los puertos 80 y 443 del router hacia la máquina donde"
    echo "     se ejecutará Traefik."
    echo
    echo "Acceso directo sin dominio:"
    echo " - http://${MACHINE_IP}:3552"
    echo
    echo "Credenciales por defecto:"
    echo "  Usuario: arcane"
    echo "  Contraseña: arcane-admin"
    echo "  (Se recomienda cambiarlas tras el primer acceso)"
}

install_arcane() {
    echo
    echo "Instalando Arcane..."
    
    local domain=""
    local machine_ip=""
    local env="${DOCKER_BASE}/arcane/.env"
    local env_global="${DOCKER_BASE}/arcane/projects/.env.global"
    local user_uid=$(id -u "$USER")
    local user_gid=$(id -g "$USER")
    local encryption_key=$(openssl rand -hex 32)
    local jwt_secret=$(openssl rand -hex 32)

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain) domain="$2"; shift ;;
            --ip) machine_ip="$2"; shift ;;
            *) echo "Opción desconocida en install_arcane: $1"; exit 1 ;;
        esac
        shift
    done

    echo "-> Configurando instalación limpia para Arcane..."
    echo

    mkdir -p "${DOCKER_BASE}/arcane/projects"
    install -m 0644 ./docker_files/arcane/docker-compose.yaml "${DOCKER_BASE}/arcane/docker-compose.yaml"

    arcane_create_env_file "$env" \
        "ENVIRONMENT=${ENVIRONMENT}" \
        "HOSTNAME=arcane.${domain}" \
        "APP_URL=http://${machine_ip}:3552" \
        "ENCRYPTION_KEY=${encryption_key}" \
        "JWT_SECRET=${jwt_secret}"
    echo "Archivo .env generado correctamente."

    arcane_create_env_file "$env_global"

    echo "Archivo .env.global generado correctamente."

    install -m 0644 ./docker_files/traefik/dynamic/arcane.yaml "${DOCKER_BASE}/traefik/dynamic/arcane.yaml"
    traefik_update_arcane_fqdn

    echo "-> Arcane preparado en ${DOCKER_BASE}/arcane"
}

install_arcane_agent() {
    local env="${DOCKER_BASE}/arcane-agent/.env"
    local user_uid=$(id -u "$USER")
    local user_gid=$(id -g "$USER")

    mkdir -p "${DOCKER_BASE}/arcane-agent"
    install -m 0644 ./docker_files/arcane/docker-compose.agent.yaml "${DOCKER_BASE}/arcane-agent/docker-compose.yaml"

    arcane_create_env_file "$env" \
        "ENVIRONMENT=${ENVIRONMENT}" \
        "AGENT_TOKEN=${AGENT_TOKEN}" \
        "ARCANE_MAIN_IP=${ARCANE_MAIN_IP}" \
        "ARCANE_MAIN_PORT=${ARCANE_MAIN_PORT}"
    echo
    echo "Archivo .env generado correctamente."
}

arcane_agent_start() {
    ARCANE_AGENT_DIR="${DOCKER_BASE}/arcane-agent"
    echo

    if [ ! -f "${ARCANE_AGENT_DIR}/docker-compose.yaml" ]; then
        echo "ERROR: No se encuentra docker-compose.yaml en ${ARCANE_AGENT_DIR}"
        echo "No se puede levantar el agente de Arcane."
        return
    fi

    echo "Levantando el agente de Arcane..."
    docker compose -f "${ARCANE_AGENT_DIR}/docker-compose.yaml" up -d >>"${INSTALL_LOG}" 2>&1 || true

    echo "Agente de Arcane iniciado correctamente."
}

arcane_update_env_var() {
    local file="$1"
    local key="$2"
    local value="$3"

    if grep -q "^${key}=" "$file" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

arcane_create_env_file() {
    local file="$1"
    shift
    mkdir -p "$(dirname "$file")"

    cat > "$file" <<EOF
TZ=Europe/Madrid
PUID=${user_uid}
PGID=${user_gid}
DOCKER_BASE=${DOCKER_BASE}
EOF
    for line in "$@"; do
        echo "$line" >> "$file"
    done
}

maybe_reexec_as_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Se necesitan privilegios de administrador. Re-ejecutando con sudo..."
    sudo INSTALL_PATH="$INSTALL_PATH" bash "$0" "$@"
    exit $?
  fi
}

main() {
    clear

    maybe_reexec_as_root "$@" 
    check_args "$@"

    DOCKER_BASE="${INSTALL_PATH}/docker"

    if [[ "$RUN" == "true" ]]; then
        echo "Ejecutando en modo root con: Ruta=${INSTALL_PATH}"
    fi

    sleep 5

    ensure_install_log
    echo "== Inicio instalación: $(date) ==" >> "${INSTALL_LOG}"

    purge_docker
    
    purge_system

    print_header

    update_system

    if ! create_mem_swap; then
        echo "Advertencia: no se pudo crear swap, continuando..."
    fi

    install_docker

    if [[ "$INSTALL_AGENT_ARCANE" == "true" ]]; then
        echo
        echo "== Instalando agente de Arcane =="
        install_arcane_agent
        create_docker_networks
        arcane_agent_start
        exit 0
    fi

    # --- Lógica de instalación ---
    if [[ "$ALL_PRIVACY" == "true" ]]; then
        echo
        echo "Instalando stack completo de privacidad (AdGuard + Unbound)..."
        echo
        create_adguard_resolved_conf
        generate_adguard_files
        set_unbound_sysctl
        generate_unbound_files
    fi

    if [[ "$ADGUARD" == "true" ]]; then
        echo
        echo "Instalando AdGuard..."
        echo
        create_adguard_resolved_conf
        generate_adguard_files
    fi

    if [[ "$UNBOUND" == "true" ]]; then
        echo
        echo "Instalando Unbound..."
        echo
        set_unbound_sysctl
        generate_unbound_files
    fi

    create_docker_networks

    install_traefik \
        --provider "$TRAEFIK_PROVIDER" \
        --domain "$TRAEFIK_DOMAIN" \
        $( [[ -n "$TRAEFIK_CF_API_TOKEN" ]] && echo "--token $TRAEFIK_CF_API_TOKEN" ) \
        $( [[ -n "$TRAEFIK_EMAIL" ]] && echo "--email $TRAEFIK_EMAIL" ) \
        $( [[ "$DASHBOARD_AUTH" == "true" ]] && echo "--dashboard-auth" ) \
        $( [[ "$DASHBOARD_LAN_ONLY" == "true" ]] && echo "--dashboard-lan-only" ) \
        $( [[ -n "$TRAEFIK_USER" ]] && echo "--user $TRAEFIK_USER" ) \
        $( [[ -n "$TRAEFIK_PASSWORD" ]] && echo "--password $TRAEFIK_PASSWORD" )

    install_arcane --domain "$TRAEFIK_DOMAIN" --ip "$MACHINE_IP"

    config_cron_auto_update

    config_cron_fix_permissions

    arcane_start
    
    show_access_traefik_info
}

main "$@"

# --- Auto-borrado del instalador ---

# Ruta completa del script
SELF_PATH="${BASH_SOURCE[0]}"

# Carpeta donde está el script
SELF_DIR="$(cd "$(dirname "$SELF_PATH")" && pwd)"

echo
echo "-> Instalación completada. Borrando carpeta del instalador: $SELF_DIR"

# Mover al HOME del usuario para evitar quedarse en un directorio borrado
cd ~ || exit 1

# Borrar la carpeta completa del instalador
rm -rf "$SELF_DIR"

echo
echo "El servidor se reiniciará en 10 segundos..."

sleep 10 

sudo systemctl --no-wall reboot