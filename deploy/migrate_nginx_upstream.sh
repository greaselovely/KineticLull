#!/bin/bash
# migrate_nginx_upstream.sh - Move Nginx from the distro package to nginx.org builds.
#
# WHY THIS EXISTS
#   Ubuntu occasionally ships an nginx build with a security fix deliberately
#   withheld (e.g. 1.24.0-2ubuntu7.15 disabled the CVE-2026-42533 patch over an
#   ABI regression, LP #2161362). When that happens there is no distro version
#   to upgrade to. This script moves the host to nginx.org's own packages, which
#   track upstream releases directly.
#
# THIS IS NOT PART OF upgrade.sh, ON PURPOSE.
#   Adding a third-party APT repository changes the trust boundary of the host.
#   That is an operator decision, not a side effect of upgrading the app.
#
# Usage:
#   bash deploy/migrate_nginx_upstream.sh              # interactive
#   bash deploy/migrate_nginx_upstream.sh --yes        # non-interactive
#   bash deploy/migrate_nginx_upstream.sh --mainline   # mainline instead of stable
#   bash deploy/migrate_nginx_upstream.sh --rollback   # undo, back to distro nginx

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOGFILE="${PROJECT_DIR}/nginx_migration.log"
STATE_DIR="/var/lib/kineticlull"
STATE_FILE="${STATE_DIR}/nginx_upstream_migration"

KEYRING="/usr/share/keyrings/nginx-archive-keyring.gpg"
SOURCES="/etc/apt/sources.list.d/nginx.list"
PREFS="/etc/apt/preferences.d/nginx"
UNATTENDED="/etc/apt/apt.conf.d/51kineticlull-nginx-origin"

ASSUME_YES=false
BRANCH="packages"          # stable; --mainline switches to packages/mainline
DO_ROLLBACK=false

for arg in "$@"; do
    case "$arg" in
        --yes|-y)     ASSUME_YES=true ;;
        --mainline)   BRANCH="packages/mainline" ;;
        --rollback)   DO_ROLLBACK=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

echo "Nginx upstream migration started at $(date)" > "${LOGFILE}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo -e "[*]\t$1" | tee -a "${LOGFILE}"; }
ok()   { echo -e "[+]\t$1" | tee -a "${LOGFILE}"; }
warn() { echo -e "[!]\t$1" | tee -a "${LOGFILE}"; }
ask()  { echo -e "[?]\t$1"; }
die()  { echo -e "[x]\t$1" | tee -a "${LOGFILE}"; exit 1; }

confirm() {
    # $1 = prompt. Returns 0 for yes.
    if [ "$ASSUME_YES" = true ]; then return 0; fi
    local reply
    read -p "[?]	$1 [y/N]: " reply
    [ "$reply" = "y" ] || [ "$reply" = "Y" ]
}

# ─── Preflight ────────────────────────────────────────────────────────────────

preflight() {
    [ -f /etc/debian_version ] || die "This script supports Debian/Ubuntu only."
    command -v apt-get >/dev/null 2>&1 || die "apt-get not found."
    sudo -n true 2>/dev/null || log "sudo will prompt for a password."

    . /etc/os-release
    DISTRO_ID="${ID}"
    CODENAME="${VERSION_CODENAME}"
    [ -n "$CODENAME" ] || die "Could not determine distro codename from /etc/os-release."
    case "$DISTRO_ID" in
        ubuntu|debian) ;;
        *) die "nginx.org publishes packages for ubuntu and debian only (found: ${DISTRO_ID})." ;;
    esac
    log "Detected ${DISTRO_ID} ${CODENAME}"
}

# ─── Rollback ─────────────────────────────────────────────────────────────────

rollback() {
    local BACKUP_DIR="$1"
    echo ""
    warn "Rolling back to the distro nginx package..."

    sudo rm -f "${SOURCES}" "${PREFS}" "${UNATTENDED}" "${KEYRING}" 2>/dev/null || true
    sudo apt-get update -qq 2>>"${LOGFILE}" || warn "apt-get update failed during rollback."

    if [ -n "${OLD_NGINX_VER}" ]; then
        log "Reinstalling nginx=${OLD_NGINX_VER}..."
        sudo apt-get install -y --allow-downgrades \
            "nginx=${OLD_NGINX_VER}" 2>>"${LOGFILE}" \
            || warn "Could not pin the exact old version; trying plain reinstall."
        sudo apt-get install -y --reinstall nginx 2>>"${LOGFILE}" || true
    fi

    if [ -n "${BACKUP_DIR}" ] && [ -d "${BACKUP_DIR}/nginx" ]; then
        log "Restoring /etc/nginx from ${BACKUP_DIR}..."
        sudo rm -rf /etc/nginx
        sudo cp -a "${BACKUP_DIR}/nginx" /etc/nginx
    fi

    if sudo nginx -t 2>>"${LOGFILE}"; then
        sudo systemctl restart nginx 2>>"${LOGFILE}" || true
        ok "Rollback complete. Distro nginx restored."
    else
        warn "Rollback restored files but 'nginx -t' still fails. Inspect ${LOGFILE} and /etc/nginx."
    fi
    sudo rm -f "${STATE_FILE}" 2>/dev/null || true
}

# ─── Explicit rollback mode ───────────────────────────────────────────────────

if [ "$DO_ROLLBACK" = true ]; then
    preflight
    [ -f "${STATE_FILE}" ] || die "No migration state found at ${STATE_FILE}. Nothing to roll back."
    # shellcheck disable=SC1090
    . "${STATE_FILE}"
    log "Rolling back migration recorded at ${MIGRATED_AT}"
    rollback "${BACKUP_DIR}"
    exit 0
fi

# ─── Main ─────────────────────────────────────────────────────────────────────

preflight

OLD_NGINX_VER="$(dpkg-query -W -f='${Version}' nginx 2>/dev/null || true)"
[ -n "$OLD_NGINX_VER" ] || die "Nginx is not installed via dpkg. Nothing to migrate."

if [ -f "${SOURCES}" ]; then
    ok "nginx.org repository is already configured. Nothing to do."
    log "To reverse: bash deploy/migrate_nginx_upstream.sh --rollback"
    exit 0
fi

# Record the worker user so static-file and log ownership survive the swap.
OLD_USER="$(awk '/^[[:space:]]*user[[:space:]]/{gsub(/;/,""); print $2; exit}' /etc/nginx/nginx.conf 2>/dev/null || true)"
OLD_USER="${OLD_USER:-www-data}"
log "Current nginx worker user: ${OLD_USER}"
log "Current nginx version: ${OLD_NGINX_VER}"

echo ""
echo "  This will:"
echo "    - add the nginx.org APT repository and pin it above the distro"
echo "    - replace the distro nginx package with nginx.org's build"
echo "    - keep nginx.org in unattended-upgrades so security updates still apply"
echo "    - preserve your worker user (${OLD_USER}) and sites-enabled layout"
echo ""
echo "  Trade-off: you leave Ubuntu's backport cadence and track upstream releases."
echo "  Reversible with: bash deploy/migrate_nginx_upstream.sh --rollback"
echo ""

confirm "Proceed with the migration?" || { log "Aborted by operator."; exit 0; }

# ── Step 1: Backup ──
BACKUP_DIR="${PROJECT_DIR}/.nginx_migration_backup_$(date +%Y%m%d%H%M%S)"
mkdir -p "${BACKUP_DIR}"
log "Backing up /etc/nginx to ${BACKUP_DIR}..."
sudo cp -a /etc/nginx "${BACKUP_DIR}/nginx"
ok "Backup created."

# ── Step 2: Signing key ──
log "Fetching the nginx.org signing key..."
TMPKEY="$(mktemp)"
curl -fsSL https://nginx.org/keys/nginx_signing.key -o "${TMPKEY}" \
    || die "Could not download the nginx.org signing key."

echo ""
echo "  Signing key fingerprint:"
gpg --show-keys --with-fingerprint "${TMPKEY}" 2>/dev/null | sed 's/^/    /' || true
echo ""
echo "  Verify this against the fingerprint published at https://nginx.org/en/pgp_keys.html"
echo ""
if [ "$ASSUME_YES" = true ]; then
    warn "--yes given: accepting the key without interactive verification."
else
    confirm "Does the fingerprint match?" || { rm -f "${TMPKEY}"; die "Key not verified. Aborted."; }
fi

sudo gpg --dearmor -o "${KEYRING}" < "${TMPKEY}"
rm -f "${TMPKEY}"
sudo chmod 644 "${KEYRING}"
ok "Signing key installed."

# ── Step 3: Repository + pin ──
log "Adding the nginx.org repository (${BRANCH})..."
echo "deb [signed-by=${KEYRING}] http://nginx.org/${BRANCH}/${DISTRO_ID} ${CODENAME} nginx" \
    | sudo tee "${SOURCES}" > /dev/null
printf 'Package: nginx*\nPin: origin nginx.org\nPin-Priority: 900\n' \
    | sudo tee "${PREFS}" > /dev/null
ok "Repository configured."

# ── Step 4: Keep unattended-upgrades working ──
# Without this, nginx.org packages fall outside the default Allowed-Origins and
# would silently stop receiving automatic security updates.
log "Registering nginx.org with unattended-upgrades..."
sudo tee "${UNATTENDED}" > /dev/null <<'UAEOF'
// Added by KineticLull migrate_nginx_upstream.sh
// nginx.org packages are outside the distro origins that unattended-upgrades
// allows by default. Without this entry, nginx would stop auto-updating.
Unattended-Upgrade::Allowed-Origins {
    "nginx:stable";
};
UAEOF
ok "unattended-upgrades origin registered."

# ── Step 5: Install ──
log "Updating package lists..."
sudo apt-get update -qq 2>>"${LOGFILE}" || { rollback "${BACKUP_DIR}"; die "apt-get update failed."; }

NEW_CANDIDATE="$(apt-cache policy nginx | awk '/Candidate:/{print $2}')"
log "nginx.org candidate: ${NEW_CANDIDATE}"

log "Installing nginx from nginx.org..."
if ! sudo apt-get install -y nginx 2>>"${LOGFILE}"; then
    rollback "${BACKUP_DIR}"
    die "Install failed. Rolled back."
fi
ok "Installed nginx ${NEW_CANDIDATE}."

# ── Step 6: Reconcile config layout ──
# nginx.org's nginx.conf includes only conf.d/*.conf. Debian-style deployments
# keep the site in sites-enabled, which would otherwise be silently unserved:
# `nginx -t` passes because the file is valid, it is just never included.
if [ -d /etc/nginx/sites-enabled ] && [ -n "$(ls -A /etc/nginx/sites-enabled 2>/dev/null)" ]; then
    if ! grep -qE '^[[:space:]]*include[[:space:]]+/etc/nginx/sites-enabled/' /etc/nginx/nginx.conf; then
        log "Re-adding the sites-enabled include to nginx.conf..."
        sudo sed -i '/include[[:space:]]\+\/etc\/nginx\/conf\.d\/\*\.conf;/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
        grep -qE '^[[:space:]]*include[[:space:]]+/etc/nginx/sites-enabled/' /etc/nginx/nginx.conf \
            || { rollback "${BACKUP_DIR}"; die "Could not add the sites-enabled include. Rolled back."; }
        ok "sites-enabled include restored."
    fi
fi

# ── Step 7: Preserve worker user ──
# nginx.org defaults to user `nginx`; the distro used `www-data`. Static file
# and log ownership were set up for the old user.
CUR_USER="$(awk '/^[[:space:]]*user[[:space:]]/{gsub(/;/,""); print $2; exit}' /etc/nginx/nginx.conf 2>/dev/null || true)"
if [ -n "$OLD_USER" ] && [ "$CUR_USER" != "$OLD_USER" ]; then
    if id "$OLD_USER" >/dev/null 2>&1; then
        log "Restoring worker user to ${OLD_USER} (was ${CUR_USER})..."
        sudo sed -i "s/^\s*user\s\+[^;]*;/user ${OLD_USER};/" /etc/nginx/nginx.conf
        ok "Worker user preserved."
    else
        warn "Previous worker user ${OLD_USER} no longer exists; leaving ${CUR_USER}."
    fi
fi

# ── Step 8: Preserve log readability ──
# KineticLull's rejection parser reads /var/log/nginx/access.log via group adm.
# The distro logrotate config (create 0640 www-data adm) is removed with the
# distro package, so re-assert it or the parser silently stops counting.
if [ -d /var/log/nginx ]; then
    log "Re-asserting log group ownership for the rejection parser..."
    sudo chgrp -R adm /var/log/nginx 2>/dev/null || warn "Could not chgrp /var/log/nginx to adm."
    sudo chmod -R g+r /var/log/nginx 2>/dev/null || true
    sudo chmod g+rx /var/log/nginx 2>/dev/null || true
fi
if [ -f /etc/logrotate.d/nginx ] && ! grep -q 'adm' /etc/logrotate.d/nginx; then
    sudo sed -i "s/^\(\s*create\s\+[0-7]\+\s\+\S\+\)\s\+\S\+/\1 adm/" /etc/logrotate.d/nginx \
        || warn "Could not patch /etc/logrotate.d/nginx; check its create line manually."
    log "Patched logrotate create line to keep group adm."
fi

# ── Step 9: Validate and start ──
log "Testing configuration..."
if ! sudo nginx -t 2>>"${LOGFILE}"; then
    rollback "${BACKUP_DIR}"
    die "nginx -t failed after migration. Rolled back."
fi

sudo systemctl enable nginx 2>>"${LOGFILE}" || true
if ! sudo systemctl restart nginx 2>>"${LOGFILE}"; then
    rollback "${BACKUP_DIR}"
    die "nginx failed to restart. Rolled back."
fi
ok "Nginx restarted."

# ── Step 10: Verify the site is actually served ──
# nginx -t passing is not proof the site is reachable; the include could be missing.
sleep 1
if curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/ 2>/dev/null | grep -qE '^(200|301|302|403)$'; then
    ok "Site responds over HTTPS."
else
    warn "Could not confirm an HTTPS response from 127.0.0.1."
    warn "If the site is down, roll back: bash deploy/migrate_nginx_upstream.sh --rollback"
fi

# ── Step 11: Record state for rollback ──
sudo mkdir -p "${STATE_DIR}"
sudo tee "${STATE_FILE}" > /dev/null <<EOF
# Written by migrate_nginx_upstream.sh
MIGRATED_AT="$(date -Iseconds)"
OLD_NGINX_VER="${OLD_NGINX_VER}"
NEW_NGINX_VER="${NEW_CANDIDATE}"
OLD_USER="${OLD_USER}"
BACKUP_DIR="${BACKUP_DIR}"
EOF

echo ""
ok "Migration complete: ${OLD_NGINX_VER} -> ${NEW_CANDIDATE}"
log "Backup:   ${BACKUP_DIR}"
log "Rollback: bash deploy/migrate_nginx_upstream.sh --rollback"
log "Log:      ${LOGFILE}"
echo ""
warn "Verify the running version and that your site serves correctly:"
echo "        nginx -v"
echo "        curl -skI https://localhost/ | head -3"
