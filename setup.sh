#!/bin/bash
# setup.sh - Fresh install of KineticLull with Nginx + Gunicorn (default)
#
# WARNING: KineticLull is designed for internal/private network use only.
#          Do not expose it directly to the internet.
#
# Usage: sudo bash setup.sh
#   OR:  bash setup.sh  (will prompt for sudo when needed)

set -e

# Configuration
PROJECT_NAME="kineticlull"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PATH="${PROJECT_DIR}/venv"
GUNICORN_WORKERS=3
LOGFILE="${PROJECT_DIR}/setup.log"
DEPLOY_DIR="${PROJECT_DIR}/deploy"
CERT_DIR="${PROJECT_DIR}/ssl"
SERVICE_FILE="/etc/systemd/system/${PROJECT_NAME}.service"

# Initialize log
echo "Setup started at $(date)" > "${LOGFILE}"

log() {
    echo -e "[i]\t$1" | tee -a "${LOGFILE}"
}

warn() {
    echo -e "[!]\t$1" | tee -a "${LOGFILE}"
}

ok() {
    echo -e "[+]\t$1" | tee -a "${LOGFILE}"
}

ask() {
    echo -e "[?]\t$1"
}

# ─── Detect OS ───────────────────────────────────────────────────────────────

detect_os() {
    if [ -f /etc/debian_version ]; then
        OS_FAMILY="debian"
        NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
        NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
        NGINX_CONF_METHOD="sites"
    elif [ -f /etc/redhat-release ]; then
        OS_FAMILY="rhel"
        NGINX_CONF_DIR="/etc/nginx/conf.d"
        NGINX_CONF_METHOD="confdir"
    else
        warn "Unsupported OS. This script supports Debian/Ubuntu and RHEL/CentOS/Rocky."
        exit 1
    fi
    log "Detected OS family: ${OS_FAMILY}"
}

# ─── Install System Packages ─────────────────────────────────────────────────

install_packages() {
    log "Installing system packages..."

    # Detect Python version for venv package
    local PY_VERSION
    PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "3")

    if [ "$OS_FAMILY" = "debian" ]; then
        sudo apt-get update -qq
        sudo apt-get install -y nginx openssl "python${PY_VERSION}-venv"
    else
        if command -v dnf &>/dev/null; then
            sudo dnf install -y nginx openssl python3-virtualenv
        else
            sudo yum install -y nginx openssl python3-virtualenv
        fi
    fi
    ok "System packages installed."
}

# ─── Firewall ─────────────────────────────────────────────────────────────────

configure_firewall() {
    if command -v firewall-cmd &>/dev/null; then
        log "Configuring firewall (firewalld)..."
        sudo firewall-cmd --permanent --add-service=https 2>/dev/null || true
        sudo firewall-cmd --permanent --add-service=http 2>/dev/null || true
        sudo firewall-cmd --reload 2>/dev/null || true
        ok "Firewall configured."
    elif command -v ufw &>/dev/null; then
        log "Configuring firewall (ufw)..."
        sudo ufw allow 'Nginx Full' 2>/dev/null || true
        ok "Firewall configured."
    else
        log "No recognized firewall found. Ensure ports 80/443 are open."
    fi
}

# ─── Nginx Permissions ────────────────────────────────────────────────────────

ensure_nginx_traversal() {
    log "Ensuring Nginx can traverse path to project directory..."
    local DIR="${PROJECT_DIR}"
    while [ "$DIR" != "/" ]; do
        if [ -d "$DIR" ] && ! stat -c '%A' "$DIR" 2>/dev/null | grep -q '...x$'; then
            sudo chmod o+x "$DIR"
            log "  chmod o+x $DIR"
        fi
        DIR=$(dirname "$DIR")
    done
    ok "Directory traversal permissions verified."
}

# ─── SSL Certificate ─────────────────────────────────────────────────────────

generate_ssl_cert() {
    mkdir -p "${CERT_DIR}"

    if [ -f "${CERT_DIR}/cert.pem" ] && [ -f "${CERT_DIR}/key.pem" ]; then
        log "SSL certificate already exists in ${CERT_DIR}. Skipping generation."
        return
    fi

    # Check for legacy cert location (pre-nginx migration)
    if [ -f "${PROJECT_DIR}/cert.pem" ] && [ -f "${PROJECT_DIR}/key.pem" ]; then
        log "Found existing certs in project root. Moving to ${CERT_DIR}..."
        cp "${PROJECT_DIR}/cert.pem" "${CERT_DIR}/cert.pem"
        cp "${PROJECT_DIR}/key.pem" "${CERT_DIR}/key.pem"
        ok "Certs moved to ${CERT_DIR}."
        return
    fi

    if ! command -v openssl &>/dev/null; then
        warn "OpenSSL is not installed. Cannot generate SSL certificate."
        exit 1
    fi

    log "Generating self-signed SSL certificate (valid 5 years)..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        -days 1825 -nodes \
        -subj "/CN=${SERVER_NAME}/O=KineticLull/OU=Self-Signed" \
        2>>"${LOGFILE}"
    chmod 600 "${CERT_DIR}/key.pem"
    chmod 644 "${CERT_DIR}/cert.pem"
    ok "SSL certificate generated."
}

# ─── Python Virtual Environment ──────────────────────────────────────────────

setup_python() {
    log "Creating virtual environment..."
    python3 -m venv "${VENV_PATH}"
    source "${VENV_PATH}/bin/activate"

    log "Upgrading pip..."
    pip install --upgrade pip -q

    log "Installing Python dependencies..."
    pip install -r "${PROJECT_DIR}/requirements.txt" -q

    ok "Python environment ready."
}

# ─── Django Setup ─────────────────────────────────────────────────────────────

setup_django() {
    local PYTHON="${VENV_PATH}/bin/python"

    log "Running database migrations..."
    ${PYTHON} "${PROJECT_DIR}/manage.py" migrate --noinput 2>>"${LOGFILE}"

    log "Collecting static files..."
    ${PYTHON} "${PROJECT_DIR}/manage.py" collectstatic --noinput 2>>"${LOGFILE}"

    # Set deployment mode in AppSettings
    ${PYTHON} "${PROJECT_DIR}/manage.py" shell -c "
from app.models import AppSettings
s = AppSettings.load()
s.deployment_mode = 'nginx_gunicorn'
s.save()
" 2>>"${LOGFILE}"

    ok "Django configured."
}

# ─── Nginx Configuration ─────────────────────────────────────────────────────

configure_nginx() {
    log "Configuring Nginx..."
    local STATIC_ROOT="${PROJECT_DIR}/staticfiles"
    local TEMPLATE="${DEPLOY_DIR}/nginx_kineticlull.conf.template"

    if [ ! -f "${TEMPLATE}" ]; then
        warn "Nginx template not found at ${TEMPLATE}."
        exit 1
    fi

    # Render template
    local RENDERED
    RENDERED=$(sed \
        -e "s|{{SERVER_NAME}}|${SERVER_NAME}|g" \
        -e "s|{{CERT_PATH}}|${CERT_DIR}/cert.pem|g" \
        -e "s|{{KEY_PATH}}|${CERT_DIR}/key.pem|g" \
        -e "s|{{STATIC_ROOT}}|${STATIC_ROOT}|g" \
        "${TEMPLATE}")

    if [ "$NGINX_CONF_METHOD" = "sites" ]; then
        echo "${RENDERED}" | sudo tee "${NGINX_SITES_AVAILABLE}/${PROJECT_NAME}" > /dev/null
        sudo ln -sf "${NGINX_SITES_AVAILABLE}/${PROJECT_NAME}" "${NGINX_SITES_ENABLED}/${PROJECT_NAME}"
        # Remove default site if it exists
        sudo rm -f "${NGINX_SITES_ENABLED}/default" 2>/dev/null || true
    else
        echo "${RENDERED}" | sudo tee "${NGINX_CONF_DIR}/${PROJECT_NAME}.conf" > /dev/null
    fi

    ensure_nginx_traversal

    # Test config
    if ! sudo nginx -t 2>>"${LOGFILE}"; then
        warn "Nginx configuration test failed. Check ${LOGFILE} for details."
        exit 1
    fi

    ok "Nginx configured and tested."
}

# ─── Gunicorn Systemd Service ─────────────────────────────────────────────────

configure_gunicorn_service() {
    log "Creating systemd service for Gunicorn..."
    local TEMPLATE="${DEPLOY_DIR}/kineticlull.service.template"
    local CURRENT_USER
    CURRENT_USER=$(whoami)

    if [ ! -f "${TEMPLATE}" ]; then
        warn "Service template not found at ${TEMPLATE}."
        exit 1
    fi

    local RENDERED
    RENDERED=$(sed \
        -e "s|{{USER}}|${CURRENT_USER}|g" \
        -e "s|{{PROJECT_DIR}}|${PROJECT_DIR}|g" \
        -e "s|{{VENV_PATH}}|${VENV_PATH}|g" \
        -e "s|{{WORKERS}}|${GUNICORN_WORKERS}|g" \
        "${TEMPLATE}")

    echo "${RENDERED}" | sudo tee "${SERVICE_FILE}" > /dev/null
    ok "Systemd service created."
}

# ─── Start Services ──────────────────────────────────────────────────────────

start_services() {
    log "Starting services..."
    sudo systemctl daemon-reload

    sudo systemctl enable "${PROJECT_NAME}" 2>>"${LOGFILE}"
    sudo systemctl start "${PROJECT_NAME}"
    ok "Gunicorn service started."

    sudo systemctl enable nginx 2>>"${LOGFILE}"
    sudo systemctl restart nginx
    ok "Nginx started."

    # Health check
    sleep 2
    local HTTP_CODE
    HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost/" 2>/dev/null || echo "000")
    if [ "${HTTP_CODE}" = "200" ] || [ "${HTTP_CODE}" = "302" ]; then
        ok "Health check passed (HTTP ${HTTP_CODE})."
    else
        warn "Health check returned HTTP ${HTTP_CODE}. Check logs."
        warn "  Gunicorn: sudo journalctl -u ${PROJECT_NAME} --no-pager -n 20"
        warn "  Nginx:    sudo tail -20 /var/log/nginx/error.log"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

echo ""
echo "========================================="
echo "  KineticLull Setup"
echo "========================================="
echo ""
echo "  WARNING: This application is designed"
echo "  for internal/private network use only."
echo "  Do not expose it to the internet."
echo ""
echo "========================================="
echo ""

# Get server name
ask "What is the IP or FQDN this will be accessible at?"
read -p "[?]	(e.g., 10.1.1.1 or edl.internal.com): " SERVER_NAME_INPUT

# Strip protocol if provided
SERVER_NAME=$(echo "${SERVER_NAME_INPUT}" | sed -e 's|^https://||' -e 's|^http://||' -e 's|/$||')

if [ -z "${SERVER_NAME}" ]; then
    warn "Server name cannot be empty."
    exit 1
fi

# Ask about workers
ask "Gunicorn workers (default: 3, recommended: 2x CPU cores + 1):"
read -p "[?]	Workers [3]: " WORKERS_INPUT
if [ -n "${WORKERS_INPUT}" ]; then
    GUNICORN_WORKERS="${WORKERS_INPUT}"
fi

log "Server name: ${SERVER_NAME}"
log "Workers: ${GUNICORN_WORKERS}"
log "Project dir: ${PROJECT_DIR}"

detect_os
install_packages
generate_ssl_cert
setup_python
setup_django
configure_nginx
configure_gunicorn_service
configure_firewall
start_services

echo ""
echo "========================================="
echo "  Setup Complete"
echo "========================================="
echo ""
ok "KineticLull is running at https://${SERVER_NAME}"
ok "Deployment: Nginx + Gunicorn"
ok "SSL: Self-signed certificate in ${CERT_DIR}"
ok "Service: sudo systemctl status ${PROJECT_NAME}"
ok "Logs: ${PROJECT_DIR}/logs/kineticlull.log"
echo ""
log "Default login: support@kineticlull.com / Password!"
log "Change the default password immediately after first login."
echo ""
