#!/bin/bash
# setup.sh

# Stop on error
set -e

# Configuration variables
PROJECT_NAME="kineticlull"
PROJECT_DIR=$(pwd)
VENV_PATH="${PROJECT_DIR}/venv"
GUNICORN_WORKERS=3  # Adjust based on your server's capacity
GUNICORN_BIND="0.0.0.0:443"  # Change to your desired IP and port
LOGFILE="${PROJECT_DIR}/setup.log"

# Initialize log file
echo "Setup script started at $(date)" > "${LOGFILE}"

check_openssl_and_generate_cert() {
  if ! command -v openssl &>/dev/null; then
    echo -e "[!]\tOpenSSL is not installed." | tee -a "${LOGFILE}"
    echo -e "[!]\tPlease install OpenSSL to generate an SSL certificate." | tee -a "${LOGFILE}"
    echo -e "[>]\tsudo dnf install openssl -y" | tee -a "${LOGFILE}"
    exit 1
  elif [ -f "${PROJECT_DIR}/key.pem" ] && [ -f "${PROJECT_DIR}/cert.pem" ]; then
    echo -e "[i]\tSSL certificate and key already exist. Skipping certificate generation." | tee -a "${LOGFILE}"
  else
    echo -e "[i]\tOpenSSL is installed." | tee -a "${LOGFILE}"
    echo -e "[i]\tGenerating a self-signed SSL certificate for 5 years..." | tee -a "${LOGFILE}"
    openssl req -x509 -newkey rsa:4096 -keyout "${PROJECT_DIR}/key.pem" -out "${PROJECT_DIR}/cert.pem" -days 1825 -nodes
  fi
}


# Detect package manager and install dependencies
install_packages() {
    if [ -f /etc/debian_version ]; then
        echo -e "[i]\tDetected Debian-based system. Installing with apt-get."
        sudo apt-get update
        sudo apt-get install authbind -y
    elif [ -f /etc/redhat-release ]; then
        echo -e "[i]\tDetected RHEL-based system. Installing with yum or dnf."
        if command -v dnf &>/dev/null; then
            sudo dnf install authbind -y
            echo -e "[i]\tAllowing TCP/443 Inbound"
            sudo firewall-cmd --permanent --add-port=443/tcp
            sudo firewall-cmd --reload
        else
            sudo yum update
            sudo yum install authbind -y
            echo -e "[i]\tAllowing TCP/443 Inbound"
            sudo firewall-cmd --permanent --add-port=443/tcp
            sudo firewall-cmd --reload            
        fi
    else
        echo -e "[i]\tYour system is not supported by this script."
        exit 1
    fi

    sudo touch /etc/authbind/byport/443
    sudo chown $(whoami) /etc/authbind/byport/443
    sudo chmod 500 /etc/authbind/byport/443


}

# Install Python, PIP, venv, and Authbind
install_packages

echo -e "[i]\tCreating virtual environment..." | tee -a "${LOGFILE}"
python3.12 -m venv "${VENV_PATH}"
source "${VENV_PATH}/bin/activate"

echo -e "[i]\tUpgrade PIP..." | tee -a "${LOGFILE}"
pip install --upgrade pip

echo -e "[i]\tInstalling dependencies..." | tee -a "${LOGFILE}"
pip install -r requirements.txt

echo -e "[i]\tAllow binding to port 443..." | tee -a "${LOGFILE}"
sudo setcap 'cap_net_bind_service=+ep' "${VENV_PATH}/bin/gunicorn"

echo -e "[i]\tCollecting static files...\n\n" | tee -a "${LOGFILE}"
python manage.py collectstatic --noinput

# Check for OpenSSL and generate a certificate
check_openssl_and_generate_cert

# Create a systemd service file for the project
SERVICE_FILE="/etc/systemd/system/${PROJECT_NAME}.service"
echo -e "[i]\tCreating systemd service file at ${SERVICE_FILE}..." | tee -a "${LOGFILE}"

sudo tee "${SERVICE_FILE}" > /dev/null <<EOF &>> "${LOGFILE}"
[Unit]
Description=Gunicorn instance to serve ${PROJECT_NAME}
After=network.target

[Service]
User=$(whoami)
Group=$(whoami)
WorkingDirectory=${PROJECT_DIR}
ExecStart=/usr/bin/authbind --deep ${VENV_PATH}/bin/gunicorn --workers ${GUNICORN_WORKERS} --bind 0.0.0.0:443 --certfile ${PROJECT_DIR}/cert.pem --keyfile ${PROJECT_DIR}/key.pem project.wsgi:application

[Install]
WantedBy=multi-user.target
EOF

echo -e "[i]\tEnabling and starting ${PROJECT_NAME} service..." | tee -a "${LOGFILE}"
sudo systemctl enable "${PROJECT_NAME}" &>> "${LOGFILE}"
sudo systemctl start "${PROJECT_NAME}" &>> "${LOGFILE}"
sudo systemctl daemon-reload
sudo systemctl restart "${PROJECT_NAME}"
service=$(sudo systemctl status kineticlull.service | grep -i 'active:')
trimmed="${service#"${service%%[![:space:]]*}"}"
echo -e "[i]\t${PROJECT_NAME} Service: $trimmed"

echo -e "[i]\tSetup completed.\n" | tee -a "${LOGFILE}"
