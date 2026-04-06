#!/bin/bash
# upgrade.sh - Upgrade an existing KineticLull installation
#
# Handles: git pull, pip install, migrate, collectstatic, service restart
# Detects legacy Gunicorn+SSL deployments and offers Nginx migration.
#
# Usage: bash upgrade.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PROJECT_NAME="kineticlull"
PROJECT_DIR="$SCRIPT_DIR"
VENV_PATH="${PROJECT_DIR}/venv"
DEPLOY_DIR="${PROJECT_DIR}/deploy"
CERT_DIR="${PROJECT_DIR}/ssl"
SERVICE_FILE="/etc/systemd/system/${PROJECT_NAME}.service"
LOGFILE="${PROJECT_DIR}/upgrade.log"

echo "Upgrade started at $(date)" > "${LOGFILE}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "[*]\t$1" | tee -a "${LOGFILE}"; }
ok()   { echo -e "[+]\t$1" | tee -a "${LOGFILE}"; }
warn() { echo -e "[!]\t$1" | tee -a "${LOGFILE}"; }
ask()  { echo -e "[?]\t$1"; }

# ─── Rollback ─────────────────────────────────────────────────────────────────

rollback_migration() {
    local BACKUP_DIR="$1"
    echo ""
    warn "Rolling back to previous configuration..."

    # Restore original service file
    if [ -f "${BACKUP_DIR}/kineticlull.service" ]; then
        sudo cp "${BACKUP_DIR}/kineticlull.service" "$SERVICE_FILE"
        log "Restored original systemd service."
    fi

    # Restore authbind if it was backed up
    if [ -f "${BACKUP_DIR}/authbind_443" ]; then
        sudo cp "${BACKUP_DIR}/authbind_443" "/etc/authbind/byport/443"
        log "Restored authbind config."
    fi

    # Remove nginx config
    sudo rm -f "/etc/nginx/sites-enabled/${PROJECT_NAME}" 2>/dev/null
    sudo rm -f "/etc/nginx/sites-available/${PROJECT_NAME}" 2>/dev/null
    sudo rm -f "/etc/nginx/conf.d/${PROJECT_NAME}.conf" 2>/dev/null

    # Stop nginx, restart old gunicorn
    sudo systemctl stop nginx 2>/dev/null || true
    sudo systemctl daemon-reload
    sudo systemctl restart "${PROJECT_NAME}" 2>/dev/null || true

    # Reset AppSettings
    $PYTHON manage.py shell -c "
from app.models import AppSettings
s = AppSettings.load()
s.deployment_mode = 'gunicorn_ssl'
s.save()
" 2>>"${LOGFILE}" || true

    ok "Rollback complete. Running on previous Gunicorn + SSL config."
    ok "Backup preserved at: ${BACKUP_DIR}"
}

# ─── Nginx Permissions ────────────────────────────────────────────────────────

ensure_nginx_traversal() {
    # Nginx (www-data/nginx) needs o+x on every directory in the path
    # to PROJECT_DIR so it can reach staticfiles/ for serving static files.
    log "Ensuring Nginx can traverse path to project directory..."
    local DIR="${PROJECT_DIR}"
    while [ "$DIR" != "/" ]; do
        # Only fix directories that are missing o+x
        if [ -d "$DIR" ] && ! stat -c '%A' "$DIR" 2>/dev/null | grep -q '...x$'; then
            sudo chmod o+x "$DIR"
            log "  chmod o+x $DIR"
        fi
        DIR=$(dirname "$DIR")
    done
    ok "Directory traversal permissions verified."
}

# ─── Service Restart Helpers ──────────────────────────────────────────────────

restart_legacy_service() {
    if systemctl is-active --quiet "$PROJECT_NAME" 2>/dev/null; then
        log "Restarting ${PROJECT_NAME} service..."
        sudo systemctl restart "$PROJECT_NAME"
        ok "Service restarted."
    elif systemctl list-unit-files 2>/dev/null | grep -q "$PROJECT_NAME"; then
        log "Service found but not running. Starting..."
        sudo systemctl start "$PROJECT_NAME"
        ok "Service started."
    else
        log "No systemd service found. Restart the application manually."
    fi
}

restart_nginx_services() {
    ensure_nginx_traversal
    log "Restarting services..."
    if systemctl is-active --quiet "$PROJECT_NAME" 2>/dev/null; then
        sudo systemctl restart "$PROJECT_NAME"
        ok "Gunicorn restarted."
    fi
    if systemctl is-active --quiet "nginx" 2>/dev/null; then
        sudo systemctl restart nginx
        ok "Nginx restarted."
    fi
}

# ─── Nginx Migration ─────────────────────────────────────────────────────────

migrate_to_nginx() {
    echo ""
    log "Beginning Nginx migration..."

    # Detect OS
    local NGINX_CONF_METHOD
    if [ -f /etc/debian_version ]; then
        NGINX_CONF_METHOD="sites"
    elif [ -f /etc/redhat-release ]; then
        NGINX_CONF_METHOD="confdir"
    else
        warn "Unsupported OS for automatic migration."
        return 1
    fi

    # Get server name from .env
    local SERVER_NAME
    SERVER_NAME=$($PYTHON -c "
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
load_dotenv('project/.env')
url = os.getenv('KINETICLULL_URL', '')
parsed = urlparse(url)
print(parsed.hostname or url.replace('https://','').replace('http://','').strip('/'))
" 2>/dev/null)

    if [ -z "$SERVER_NAME" ]; then
        ask "Could not detect server name. Enter the IP or FQDN:"
        read -p "[?]	: " SERVER_NAME
    fi
    log "Server name: ${SERVER_NAME}"

    # Ask about workers
    ask "Gunicorn workers (default: 3):"
    read -p "[?]	Workers [3]: " WORKERS_INPUT
    local GUNICORN_WORKERS="${WORKERS_INPUT:-3}"

    # ── Step 0: Backup ──
    local BACKUP_DIR="${PROJECT_DIR}/.migration_backup_$(date +%Y%m%d%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    log "Backing up current config to ${BACKUP_DIR}..."

    if [ -f "$SERVICE_FILE" ]; then
        sudo cp "$SERVICE_FILE" "${BACKUP_DIR}/kineticlull.service"
    fi
    if [ -f "/etc/authbind/byport/443" ]; then
        sudo cp "/etc/authbind/byport/443" "${BACKUP_DIR}/authbind_443" 2>/dev/null || true
    fi
    ok "Backup created."

    # ── Step 1: Install Nginx ──
    log "Installing Nginx..."
    if [ -f /etc/debian_version ]; then
        sudo apt-get update -qq
        sudo apt-get install -y nginx openssl 2>>"${LOGFILE}"
    else
        if command -v dnf &>/dev/null; then
            sudo dnf install -y nginx openssl 2>>"${LOGFILE}"
        else
            sudo yum install -y nginx openssl 2>>"${LOGFILE}"
        fi
    fi
    ok "Nginx installed."

    # ── Step 2: SSL Certs ──
    mkdir -p "${CERT_DIR}"
    if [ -f "${CERT_DIR}/cert.pem" ] && [ -f "${CERT_DIR}/key.pem" ]; then
        log "SSL certs already in ${CERT_DIR}."
    elif [ -f "${PROJECT_DIR}/cert.pem" ] && [ -f "${PROJECT_DIR}/key.pem" ]; then
        log "Moving existing certs from project root to ${CERT_DIR}..."
        cp "${PROJECT_DIR}/cert.pem" "${CERT_DIR}/cert.pem"
        cp "${PROJECT_DIR}/key.pem" "${CERT_DIR}/key.pem"
        chmod 600 "${CERT_DIR}/key.pem"
        chmod 644 "${CERT_DIR}/cert.pem"
        ok "Certs moved."
    else
        log "Generating self-signed SSL certificate..."
        openssl req -x509 -newkey rsa:4096 \
            -keyout "${CERT_DIR}/key.pem" \
            -out "${CERT_DIR}/cert.pem" \
            -days 1825 -nodes \
            -subj "/CN=${SERVER_NAME}/O=KineticLull/OU=Self-Signed" \
            2>>"${LOGFILE}"
        chmod 600 "${CERT_DIR}/key.pem"
        chmod 644 "${CERT_DIR}/cert.pem"
        ok "SSL cert generated."
    fi

    # ── Step 3: Write Nginx config ──
    log "Writing Nginx configuration..."
    local STATIC_ROOT="${PROJECT_DIR}/staticfiles"
    local TEMPLATE="${DEPLOY_DIR}/nginx_kineticlull.conf.template"

    if [ ! -f "${TEMPLATE}" ]; then
        warn "Nginx template not found at ${TEMPLATE}. Rolling back..."
        rollback_migration "$BACKUP_DIR"
        return 1
    fi

    local RENDERED
    RENDERED=$(sed \
        -e "s|{{SERVER_NAME}}|${SERVER_NAME}|g" \
        -e "s|{{CERT_PATH}}|${CERT_DIR}/cert.pem|g" \
        -e "s|{{KEY_PATH}}|${CERT_DIR}/key.pem|g" \
        -e "s|{{STATIC_ROOT}}|${STATIC_ROOT}|g" \
        -e "s|{{PROJECT_DIR}}|${PROJECT_DIR}|g" \
        "${TEMPLATE}")

    if [ "$NGINX_CONF_METHOD" = "sites" ]; then
        echo "${RENDERED}" | sudo tee "/etc/nginx/sites-available/${PROJECT_NAME}" > /dev/null
        sudo ln -sf "/etc/nginx/sites-available/${PROJECT_NAME}" "/etc/nginx/sites-enabled/${PROJECT_NAME}"
        sudo rm -f "/etc/nginx/sites-enabled/default" 2>/dev/null || true
    else
        echo "${RENDERED}" | sudo tee "/etc/nginx/conf.d/${PROJECT_NAME}.conf" > /dev/null
    fi

    ensure_nginx_traversal

    # ── Step 4: Test Nginx config ──
    if ! sudo nginx -t 2>>"${LOGFILE}"; then
        warn "Nginx config test failed. Rolling back..."
        rollback_migration "$BACKUP_DIR"
        return 1
    fi
    ok "Nginx config tested OK."

    # ── Step 5: Update systemd service ──
    log "Updating Gunicorn systemd service..."
    local CURRENT_USER
    CURRENT_USER=$(whoami)
    local SVC_TEMPLATE="${DEPLOY_DIR}/kineticlull.service.template"

    if [ -f "$SVC_TEMPLATE" ]; then
        local SVC_RENDERED
        SVC_RENDERED=$(sed \
            -e "s|{{USER}}|${CURRENT_USER}|g" \
            -e "s|{{PROJECT_DIR}}|${PROJECT_DIR}|g" \
            -e "s|{{VENV_PATH}}|${VENV_PATH}|g" \
            -e "s|{{WORKERS}}|${GUNICORN_WORKERS}|g" \
            "${SVC_TEMPLATE}")
        echo "${SVC_RENDERED}" | sudo tee "${SERVICE_FILE}" > /dev/null
    else
        sudo tee "${SERVICE_FILE}" > /dev/null <<SVCEOF
[Unit]
Description=Gunicorn instance to serve KineticLull
After=network.target

[Service]
User=${CURRENT_USER}
Group=${CURRENT_USER}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${VENV_PATH}/bin/gunicorn --workers ${GUNICORN_WORKERS} --bind 127.0.0.1:8000 project.wsgi:application

[Install]
WantedBy=multi-user.target
SVCEOF
    fi
    ok "Systemd service updated (Gunicorn on 127.0.0.1:8000)."

    # Allow the app user to reload Nginx without a password (for IP blocklist updates)
    local SUDOERS_FILE="/etc/sudoers.d/kineticlull"
    local CURRENT_USER
    CURRENT_USER=$(whoami)
    # Remove old file if it exists under the previous name
    sudo rm -f "/etc/sudoers.d/kineticlull-nginx" 2>/dev/null || true
    cat <<SUDOEOF | sudo tee "${SUDOERS_FILE}" > /dev/null
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/nginx -s reload
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart kineticlull
${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
SUDOEOF
    sudo chmod 440 "${SUDOERS_FILE}"
    log "Sudoers rules updated for service management."

    # ── Step 6: Restart services ──
    log "Restarting services..."
    sudo systemctl daemon-reload
    sudo systemctl restart "${PROJECT_NAME}"
    sudo systemctl enable nginx 2>>"${LOGFILE}"
    sudo systemctl restart nginx

    # ── Step 7: Health check ──
    sleep 2
    local HTTP_CODE
    HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost/" 2>/dev/null || echo "000")

    if [ "${HTTP_CODE}" != "200" ] && [ "${HTTP_CODE}" != "302" ]; then
        warn "Health check failed (HTTP ${HTTP_CODE}). Rolling back..."
        rollback_migration "$BACKUP_DIR"
        return 1
    fi
    ok "Health check passed (HTTP ${HTTP_CODE})."

    # ── Step 8: Update AppSettings ──
    $PYTHON manage.py shell -c "
from app.models import AppSettings
s = AppSettings.load()
s.deployment_mode = 'nginx_gunicorn'
s.save()
" 2>>"${LOGFILE}"
    ok "AppSettings updated to nginx_gunicorn."

    # ── Step 9: Cleanup legacy authbind ──
    if [ -f "/etc/authbind/byport/443" ]; then
        sudo rm -f "/etc/authbind/byport/443"
        log "Removed legacy authbind config for port 443."
    fi

    # Configure firewall
    if command -v firewall-cmd &>/dev/null; then
        sudo firewall-cmd --permanent --add-service=https 2>/dev/null || true
        sudo firewall-cmd --permanent --add-service=http 2>/dev/null || true
        sudo firewall-cmd --reload 2>/dev/null || true
    elif command -v ufw &>/dev/null; then
        sudo ufw allow 'Nginx Full' 2>/dev/null || true
    fi

    echo ""
    ok "Migration to Nginx + Gunicorn complete!"
    ok "Backup saved at: ${BACKUP_DIR}"
    log "Old certs in project root can be removed manually if desired."
}

# ─── Detect Deployment Mode ──────────────────────────────────────────────────

detect_deployment_mode() {
    if [ -f "$SERVICE_FILE" ]; then
        if grep -q "authbind" "$SERVICE_FILE" 2>/dev/null || grep -q "\-\-certfile" "$SERVICE_FILE" 2>/dev/null; then
            echo "gunicorn_ssl"
            return
        fi
        if grep -q "127.0.0.1:8000" "$SERVICE_FILE" 2>/dev/null; then
            if [ -f "/etc/nginx/sites-available/${PROJECT_NAME}" ] || [ -f "/etc/nginx/conf.d/${PROJECT_NAME}.conf" ]; then
                echo "nginx_gunicorn"
                return
            fi
        fi
    fi

    # Fallback: check DB
    local DB_MODE
    DB_MODE=$($PYTHON -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')
django.setup()
from app.models import AppSettings
print(AppSettings.load().deployment_mode)
" 2>/dev/null || echo "unknown")
    echo "$DB_MODE"
}

# ─── Detect Python ────────────────────────────────────────────────────────────

if [ -d "venv" ]; then
    PYTHON="venv/bin/python"
    PIP="venv/bin/pip"
elif command -v python3.12 &>/dev/null; then
    PYTHON="python3.12"
    PIP="pip3.12"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
    PIP="pip3"
else
    warn "Could not find venv or python3. Aborting."
    exit 1
fi

# ─── Main ─────────────────────────────────────────────────────────────────────

echo ""
echo "========================================="
echo "  KineticLull Upgrade"
echo "========================================="
echo ""
log "Using Python: $PYTHON"

# Check for .env
if [ ! -f "project/.env" ]; then
    if [ -f "db.sqlite3" ]; then
        warn "project/.env is missing but database exists."
        warn "A new SECRET_KEY will be generated. Existing sessions will be invalidated."
        ask "What is the IP or FQDN this will be accessible at? (include https://)"
        read -p "[?]	: " KL_URL
        SECRET_KEY=$($PYTHON -c "import secrets; print(secrets.token_urlsafe(65))")
        cat > project/.env << ENVEOF
KINETICLULL_URL = '${KL_URL}'
SECRET_KEY = '${SECRET_KEY}'
DEBUG = 'False'
ENVEOF
        ok "project/.env created with new SECRET_KEY."
    else
        warn "No project/.env or database found."
        warn "This looks like a fresh install. Run 'bash setup.sh' instead."
        exit 1
    fi
fi

# Step 1: Pull latest code
log "Pulling latest code..."
if ! git pull 2>>"${LOGFILE}"; then
    warn "git pull failed. Resolve conflicts and try again."
    exit 1
fi

# Step 2: Install/update dependencies
log "Installing dependencies..."
if ! $PIP install -r requirements.txt 2>>"${LOGFILE}"; then
    warn "pip install failed. Check requirements.txt."
    exit 1
fi

# Step 3: Back up database before migrations
if [ -f "db.sqlite3" ]; then
    DB_BACKUP_DIR="${PROJECT_DIR}/backups"
    mkdir -p "${DB_BACKUP_DIR}"
    DB_BACKUP_FILE="${DB_BACKUP_DIR}/db.sqlite3.$(date +%Y%m%d%H%M%S).bak"
    cp "db.sqlite3" "${DB_BACKUP_FILE}"
    ok "Database backed up to ${DB_BACKUP_FILE}"

    # Prune backups older than 30 days
    find "${DB_BACKUP_DIR}" -name "db.sqlite3.*.bak" -mtime +30 -delete 2>/dev/null || true
fi

# Step 4: Run migrations
log "Running database migrations..."
$PYTHON manage.py migrate --noinput 2>>"${LOGFILE}"

# Step 4: Collect static files
log "Collecting static files..."
$PYTHON manage.py collectstatic --noinput 2>>"${LOGFILE}"

# Step 5: Detect deployment mode & offer Nginx migration
CURRENT_MODE=$(detect_deployment_mode)
log "Current deployment mode: ${CURRENT_MODE}"

if [ "$CURRENT_MODE" = "gunicorn_ssl" ] || [ "$CURRENT_MODE" = "unknown" ]; then
    echo ""
    echo "========================================="
    echo "  Nginx Migration Available"
    echo "========================================="
    echo ""
    echo "  Your installation is using the legacy"
    echo "  Gunicorn + direct SSL + authbind setup."
    echo ""
    echo "  Migrating to Nginx + Gunicorn provides:"
    echo "    - SSL termination at Nginx"
    echo "    - Static file serving by Nginx"
    echo "    - Security headers"
    echo "    - Rate limiting on API endpoints"
    echo "    - No more authbind / setcap"
    echo ""
    echo "  This is HIGHLY RECOMMENDED."
    echo ""
    read -p "[?]	Migrate to Nginx + Gunicorn now? [Y/n]: " MIGRATE_CHOICE

    if [ -z "$MIGRATE_CHOICE" ] || [ "$MIGRATE_CHOICE" = "Y" ] || [ "$MIGRATE_CHOICE" = "y" ]; then
        migrate_to_nginx
    else
        log "Skipping Nginx migration."
        restart_legacy_service
    fi
else
    restart_nginx_services
fi

echo ""
if [ -f "VERSION" ]; then
    ok "Upgrade complete. Version: $(cat VERSION)"
else
    ok "Upgrade complete."
fi
