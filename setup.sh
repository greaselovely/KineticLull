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

# ─── Ensure Python 3.13 ──────────────────────────────────────────────────────

ensure_python313() {
    # Self-contained install of Python 3.13 + matching venv module. We
    # deliberately do not delegate to install_python.sh because that script
    # is version-generic (currently installs 3.12) and only installs the
    # system-default python3-venv, not the version-matched python3.13-venv
    # that 'python3.13 -m venv' actually needs.
    if command -v python3.13 &>/dev/null && python3.13 -m venv --help &>/dev/null; then
        log "python3.13 with venv support already installed."
        return 0
    fi

    if [ "$OS_FAMILY" = "debian" ]; then
        log "Installing Python 3.13 from deadsnakes PPA..."
        sudo apt-get update -qq 2>>"${LOGFILE}"
        sudo apt-get install -y software-properties-common 2>>"${LOGFILE}"
        sudo add-apt-repository -y ppa:deadsnakes/ppa 2>>"${LOGFILE}"
        sudo apt-get update -qq 2>>"${LOGFILE}"
        sudo apt-get install -y python3.13 python3.13-venv python3.13-dev 2>>"${LOGFILE}"
    else
        log "Installing Python 3.13 via package manager..."
        if command -v dnf &>/dev/null; then
            sudo dnf install -y python3.13 python3.13-devel 2>>"${LOGFILE}" || true
        else
            sudo yum install -y python3.13 python3.13-devel 2>>"${LOGFILE}" || true
        fi
    fi

    if ! command -v python3.13 &>/dev/null; then
        warn "Python 3.13 still not available after install attempt."
        warn "Install Python 3.13 manually (with venv support) and re-run setup.sh."
        exit 1
    fi
    if ! python3.13 -m venv --help &>/dev/null; then
        warn "python3.13 found, but 'python3.13 -m venv' is unavailable."
        warn "Install the matching venv package (e.g. apt install python3.13-venv) and re-run setup.sh."
        exit 1
    fi
    ok "Python 3.13 installed."
}

# ─── Install System Packages ─────────────────────────────────────────────────

install_packages() {
    log "Installing system packages..."

    if [ "$OS_FAMILY" = "debian" ]; then
        sudo apt-get update -qq
        sudo apt-get install -y nginx openssl python3.13-venv
    else
        if command -v dnf &>/dev/null; then
            sudo dnf install -y nginx openssl
        else
            sudo yum install -y nginx openssl
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

setup_ssl() {
    if [ "$SSL_MODE" = "letsencrypt" ]; then
        setup_letsencrypt
    else
        generate_self_signed_cert
    fi
}

generate_self_signed_cert() {
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
    ok "Self-signed SSL certificate generated."
}

setup_letsencrypt() {
    # Check if LE cert already exists
    if [ -f "/etc/letsencrypt/live/${SERVER_NAME}/fullchain.pem" ]; then
        log "Let's Encrypt certificate already exists for ${SERVER_NAME}."
        CERT_DIR="/etc/letsencrypt/live/${SERVER_NAME}"
        CERT_PATH="${CERT_DIR}/fullchain.pem"
        KEY_PATH="${CERT_DIR}/privkey.pem"
        return
    fi

    log "Setting up Let's Encrypt certificate..."

    # Install certbot
    if ! command -v certbot &>/dev/null; then
        log "Installing certbot..."
        if [ "$OS_FAMILY" = "debian" ]; then
            sudo apt-get install -y certbot python3-certbot-nginx 2>>"${LOGFILE}"
        else
            if command -v dnf &>/dev/null; then
                sudo dnf install -y certbot python3-certbot-nginx 2>>"${LOGFILE}"
            else
                sudo yum install -y certbot python3-certbot-nginx 2>>"${LOGFILE}"
            fi
        fi
    fi
    ok "Certbot installed."

    # Nginx must be running on port 80 for the HTTP-01 challenge.
    # Write a minimal temporary config so certbot can verify.
    local TEMP_CONF
    if [ -d "/etc/nginx/sites-available" ]; then
        TEMP_CONF="/etc/nginx/sites-available/${PROJECT_NAME}"
        sudo tee "$TEMP_CONF" > /dev/null <<TMPEOF
server {
    listen 80;
    server_name ${SERVER_NAME};
    location / { return 200 'ok'; }
}
TMPEOF
        sudo ln -sf "$TEMP_CONF" "/etc/nginx/sites-enabled/${PROJECT_NAME}"
        sudo rm -f "/etc/nginx/sites-enabled/default" 2>/dev/null || true
    else
        TEMP_CONF="/etc/nginx/conf.d/${PROJECT_NAME}.conf"
        sudo tee "$TEMP_CONF" > /dev/null <<TMPEOF
server {
    listen 80;
    server_name ${SERVER_NAME};
    location / { return 200 'ok'; }
}
TMPEOF
    fi

    sudo nginx -t 2>>"${LOGFILE}" && sudo systemctl restart nginx

    # Request the certificate (retry once — first attempt can fail with
    # "No such authorization" if the account was just registered)
    log "Requesting certificate for ${SERVER_NAME}..."
    local LE_SUCCESS=false
    for attempt in 1 2; do
        if sudo certbot certonly --nginx -d "${SERVER_NAME}" --non-interactive --agree-tos \
            --register-unsafely-without-email 2>>"${LOGFILE}"; then
            LE_SUCCESS=true
            break
        fi
        if [ "$attempt" -eq 1 ]; then
            log "First attempt failed. Retrying in 5 seconds..."
            sleep 5
        fi
    done

    if [ "$LE_SUCCESS" = false ]; then
        warn "Let's Encrypt certificate request failed."
        warn "Common causes: DNS not pointing to this server, port 80 not reachable from internet."
        ask "Fall back to self-signed certificate? [Y/n]"
        read -p "[?]	: " LE_FALLBACK
        if [ -z "$LE_FALLBACK" ] || [ "$LE_FALLBACK" = "Y" ] || [ "$LE_FALLBACK" = "y" ]; then
            SSL_MODE="selfsigned"
            generate_self_signed_cert
            return
        else
            warn "Cannot continue without SSL. Aborting."
            exit 1
        fi
    fi

    # Point cert paths to Let's Encrypt locations
    CERT_DIR="/etc/letsencrypt/live/${SERVER_NAME}"
    CERT_PATH="${CERT_DIR}/fullchain.pem"
    KEY_PATH="${CERT_DIR}/privkey.pem"

    # Enable auto-renewal timer
    if systemctl list-unit-files | grep -q certbot.timer; then
        sudo systemctl enable certbot.timer 2>>"${LOGFILE}"
        sudo systemctl start certbot.timer 2>>"${LOGFILE}"
        ok "Certbot auto-renewal timer enabled."
    else
        # Add a cron job as fallback
        (sudo crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'") | sudo crontab -
        ok "Certbot renewal cron job added (daily at 3am)."
    fi

    ok "Let's Encrypt certificate issued for ${SERVER_NAME}."
}

# ─── Python Virtual Environment ──────────────────────────────────────────────

setup_python() {
    log "Creating virtual environment on Python 3.13..."
    python3.13 -m venv "${VENV_PATH}"
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

    # Create default superuser if no users exist
    ${PYTHON} "${PROJECT_DIR}/manage.py" shell -c "
from users.models import CustomUser
if not CustomUser.objects.exists():
    CustomUser.objects.create_superuser(email='support@kineticlull.com', password='Password!')
    print('Default superuser created.')
" 2>>"${LOGFILE}"

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
        -e "s|{{CERT_PATH}}|${CERT_PATH}|g" \
        -e "s|{{KEY_PATH}}|${KEY_PATH}|g" \
        -e "s|{{STATIC_ROOT}}|${STATIC_ROOT}|g" \
        -e "s|{{PROJECT_DIR}}|${PROJECT_DIR}|g" \
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

    # Allow the app user to reload Nginx without a password (for IP blocklist updates)
    local CURRENT_USER
    CURRENT_USER=$(whoami)
    local SUDOERS_FILE="/etc/sudoers.d/kineticlull"
    cat <<SUDOEOF | sudo tee "${SUDOERS_FILE}" > /dev/null
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/nginx -s reload
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart kineticlull
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/sed -i *
SUDOEOF
    sudo chmod 440 "${SUDOERS_FILE}"
    log "Sudoers rules added for service management."

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

# ─── Cron Jobs ────────────────────────────────────────────────────────────────

setup_cron() {
    log "Setting up cron jobs..."
    local CRON_CMD="*/5 * * * * cd ${PROJECT_DIR} && ${VENV_PATH}/bin/python manage.py parse_nginx_rejections >> /dev/null 2>&1"
    # Add cron job if not already present
    (crontab -l 2>/dev/null | grep -v "parse_nginx_rejections"; echo "${CRON_CMD}") | crontab -
    ok "Nginx rejection parser cron installed (every 5 minutes)."
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

# Ask about SSL
SSL_MODE="selfsigned"
echo ""
ask "SSL certificate options:"
echo "	  1) Self-signed (default, for internal/private networks)"
echo "	  2) Let's Encrypt (requires public DNS and port 80 access)"
read -p "[?]	Choose [1]: " SSL_CHOICE
if [ "$SSL_CHOICE" = "2" ]; then
    SSL_MODE="letsencrypt"
    # Validate: Let's Encrypt won't work with an IP address
    if echo "$SERVER_NAME" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
        warn "Let's Encrypt requires a domain name, not an IP address."
        warn "Falling back to self-signed certificate."
        SSL_MODE="selfsigned"
    fi
fi

# Ask about workers
ask "Gunicorn workers (default: 3, recommended: 2x CPU cores + 1):"
read -p "[?]	Workers [3]: " WORKERS_INPUT
if [ -n "${WORKERS_INPUT}" ]; then
    GUNICORN_WORKERS="${WORKERS_INPUT}"
fi

# Initialize cert paths (may be overridden by setup_letsencrypt)
CERT_PATH="${CERT_DIR}/cert.pem"
KEY_PATH="${CERT_DIR}/key.pem"

log "Server name: ${SERVER_NAME}"
log "SSL mode: ${SSL_MODE}"
log "Workers: ${GUNICORN_WORKERS}"
log "Project dir: ${PROJECT_DIR}"

# Create .env before Django setup (settings.py blocks on input() if missing)
create_env() {
    local ENV_FILE="${PROJECT_DIR}/project/.env"
    if [ -f "${ENV_FILE}" ]; then
        log "project/.env already exists. Skipping."
        return
    fi

    log "Creating project/.env..."
    local SECRET_KEY
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(65))" 2>/dev/null || openssl rand -base64 48)

    cat > "${ENV_FILE}" <<ENVEOF
KINETICLULL_URL = 'https://${SERVER_NAME}'
SECRET_KEY = '${SECRET_KEY}'
DEBUG = 'False'
ENVEOF
    chmod 600 "${ENV_FILE}"
    ok "project/.env created."
}

detect_os
ensure_python313
install_packages
setup_ssl
setup_python
create_env
setup_django
configure_nginx
configure_gunicorn_service
configure_firewall
start_services
setup_cron

echo ""
echo "========================================="
echo "  Setup Complete"
echo "========================================="
echo ""
ok "KineticLull is running at https://${SERVER_NAME}"
ok "Deployment: Nginx + Gunicorn"
if [ "$SSL_MODE" = "letsencrypt" ]; then
    ok "SSL: Let's Encrypt (auto-renewing)"
else
    ok "SSL: Self-signed certificate in ${CERT_DIR}"
fi
ok "Service: sudo systemctl status ${PROJECT_NAME}"
ok "Logs: ${PROJECT_DIR}/logs/kineticlull.log"
echo ""
log "Default login: support@kineticlull.com / Password!"
log "Change the default password immediately after first login."
echo ""
