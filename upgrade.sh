#!/bin/bash
# upgrade.sh - Upgrade an existing KineticLull installation
# Run this from the KineticLull project directory:
#   bash upgrade.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] KineticLull Upgrade"
echo "========================"

# Detect Python and venv
if [ -d "venv" ]; then
    PYTHON="venv/bin/python"
    PIP="venv/bin/pip"
elif [ -f "$(which python3.12)" ]; then
    PYTHON="python3.12"
    PIP="pip3.12"
else
    echo "[!] Could not find venv or python3.12. Aborting."
    exit 1
fi

echo "[*] Using Python: $PYTHON"

# Check for .env
if [ ! -f "project/.env" ]; then
    if [ -f "db.sqlite3" ]; then
        echo "[!] project/.env is missing but database exists."
        echo "[!] A new SECRET_KEY will be generated. Existing sessions will be"
        echo "[!] invalidated and users will need to log in again."
        read -p "[?] What is the IP or FQDN this will be accessible at? (include https://) : " KL_URL
        SECRET_KEY=$($PYTHON -c "import secrets; print(secrets.token_urlsafe(65))")
        cat > project/.env << ENVEOF
KINETICLULL_URL = '${KL_URL}'
SECRET_KEY = '${SECRET_KEY}'
DEBUG = 'False'
ENVEOF
        echo "[+] project/.env created with new SECRET_KEY."
    else
        echo "[!] No project/.env or database found."
        echo "[!] This looks like a fresh install. Run 'bash setup.sh' instead."
        exit 1
    fi
fi

# Step 1: Pull latest code
echo "[*] Pulling latest code..."
git pull
if [ $? -ne 0 ]; then
    echo "[!] git pull failed. Resolve conflicts and try again."
    exit 1
fi

# Step 2: Install/update dependencies
echo "[*] Installing dependencies..."
$PIP install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "[!] pip install failed. Check requirements.txt."
    exit 1
fi

# Step 3: Run migrations
echo "[*] Running database migrations..."
$PYTHON manage.py migrate --noinput

# Step 4: Collect static files
echo "[*] Collecting static files..."
$PYTHON manage.py collectstatic --noinput

# Step 5: Restart service if running under systemd
SERVICE_NAME="kineticlull"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo "[*] Restarting $SERVICE_NAME service..."
    sudo systemctl restart "$SERVICE_NAME"
    echo "[+] Service restarted."
elif systemctl list-unit-files | grep -q "$SERVICE_NAME" 2>/dev/null; then
    echo "[*] Service found but not running. Starting $SERVICE_NAME..."
    sudo systemctl start "$SERVICE_NAME"
    echo "[+] Service started."
else
    echo "[i] No systemd service found. Restart the application manually."
fi

# Show version
if [ -f "VERSION" ]; then
    echo ""
    echo "[+] Upgrade complete. Version: $(cat VERSION)"
else
    echo ""
    echo "[+] Upgrade complete."
fi
