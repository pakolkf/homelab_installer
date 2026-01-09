# Homelab Installer

Instalador automatizado para desplegar un entorno homelab completo basado en Docker, Traefik, Arcane, AdGuard Home y Unbound.  
El objetivo es ofrecer una instalación reproducible, segura y totalmente automatizada tanto para un **servidor principal** como para un **agente Arcane**.

---

## 🚀 Características principales

### 🖥️ Modo Servidor (por defecto)
Si NO se usa `--install-agent-arcane`, el instalador desplegará automáticamente:

- **Traefik (obligatorio, Cloudflare)**
- **Arcane Server**
- Opcionalmente:
  - AdGuard Home
  - Unbound
  - Stack completo de privacidad (AdGuard + Unbound)

> **Importante:**  
> Traefik está configurado exclusivamente para funcionar con **Cloudflare**.  
> Por tanto, todos los parámetros de Cloudflare son **obligatorios** en modo servidor.

---

### 🛰️ Modo Agente Arcane
Si se usa `--install-agent-arcane`, el instalador desplegará:

- Solo el **agente Arcane**
- **NO** instalará Traefik
- **NO** instalará Arcane Server
- **NO** requiere parámetros de Traefik

---

## 📦 Requisitos

- Ubuntu/Debian
- Acceso root (`sudo`)
- Token API de Cloudflare (modo servidor)
- Dominio gestionado por Cloudflare

---

## 🧩 Opciones del instalador

### Opciones globales

| Flag | Descripción |
|------|-------------|
| `--run` | Ejecuta la instalación |
| `--env` <production|development|test>` | Entorno del homelab |
| `--install-agent-arcane` | Instala un agente Arcane |
| `--agent-token <token>` | Token del agente Arcane |
| `--arcane-main-ip <ip>` | IP del servidor Arcane |
| `--arcane-main-port <puerto>` | Puerto del servidor Arcane |
| `--all-privacy` | Instala AdGuard + Unbound |
| `--adguard` | Instala solo AdGuard |
| `--unbound` | Instala solo Unbound |
| `--install-path <ruta>` | Ruta base de instalación |
| `-h`, `--help` | Muestra la ayuda |

### Opciones Traefik (OBLIGATORIAS en modo servidor)

| Flag | Descripción |
|------|-------------|
| `--traefik-cf-token <token>` | Token API de Cloudflare |
| `--traefik-email <email>` | Email para certificados ACME |
| `--traefik-domain <dominio>` | Dominio base para Traefik |
| `--traefik-user <usuario>` | Usuario del dashboard |
| `--traefik-password <password>` | Password del dashboard |
| `--dashboard-auth` | Habilita autenticación básica |
| `--dashboard-lan-only` | Restringe acceso a la LAN |

---

## ⚠️ Restricciones

- `--all-privacy` **no puede combinarse** con `--adguard` ni `--unbound`.
- En modo servidor, **Traefik es obligatorio** y requiere Cloudflare.
- En modo agente, **NO** se permiten parámetros de Traefik.

---

## 🛠️ Ejemplos de uso

### 1. Stack completo de privacidad

```bash
sudo ./install.sh --run --all-privacy \
    --traefik-cf-token ABC123 \
    --traefik-email admin@dominio.com \
    --traefik-domain midominio.com \
    --traefik-user admin --traefik-password 1234
```

### 2. Solo AdGuard

```bash
sudo ./install.sh --run --adguard \
    --traefik-cf-token ABC123 \
    --traefik-email admin@dominio.com \
    --traefik-domain midominio.com \
    --traefik-user admin --traefik-password 1234
```

### 3. Solo Unbound

```bash
sudo ./install.sh --run --unbound \
    --traefik-cf-token ABC123 \
    --traefik-email admin@dominio.com \
    --traefik-domain midominio.com \
    --traefik-user admin --traefik-password 1234
```

### 4. Solo Traefik + Arcane Server

```bash
sudo ./install.sh --run \
    --traefik-cf-token ABC123 \
    --traefik-email admin@dominio.com \
    --traefik-domain midominio.com \
    --traefik-user admin --traefik-password 1234
```

### 5. Agente Arcane

```bash
sudo ./install.sh --run --install-agent-arcane \
    --agent-token TOKEN123 \
    --arcane-main-ip 192.168.1.10 \
    --arcane-main-port 8080
```
