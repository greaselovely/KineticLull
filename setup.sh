#!/bin/bash

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

# Function to check for Python 3.12
check_python_version() {
  if ! python3 --version | grep 'Python 3.12' &>/dev/null; then
    echo -e "[!]\tCompatible Python version is not installed." | tee -a "${LOGFILE}"
    echo -e "[!]\tAttempting with 'python' command..." | tee -a "${LOGFILE}"
    if ! python --version | grep 'Python 3.12' &>/dev/null; then
      echo -e "[!]\tPython 3.12 is not installed." | tee -a "${LOGFILE}"
      echo -e "[!]\tPlease install Python 3.12 and try again." | tee -a "${LOGFILE}"
      exit 1
    else
      echo -e "[i]\tPython 3.12 is installed (using 'python')." | tee -a "${LOGFILE}"
    fi
  else
    echo -e "[i]\tPython 3.12 is installed (using 'python3')." | tee -a "${LOGFILE}"
  fi
}

# Function to check for OpenSSL and generate a certificate if found
check_openssl_and_generate_cert() {
  if ! command -v openssl &>/dev/null; then
    echo -e "[!]\tOpenSSL is not installed." | tee -a "${LOGFILE}"
    echo -e "[!]\tPlease install OpenSSL to generate an SSL certificate." | tee -a "${LOGFILE}"
    exit 1
  else
    echo -e "[i]\tOpenSSL is installed." | tee -a "${LOGFILE}"
    echo -e "[i]\tGenerating a self-signed SSL certificate for 5 years..." | tee -a "${LOGFILE}"
    openssl req -x509 -newkey rsa:4096 -keyout "${PROJECT_DIR}/key.pem" -out "${PROJECT_DIR}/cert.pem" -days 1825 -nodes
  fi
}

sudo apt-get install authbind -y
sudo touch /etc/authbind/byport/443
sudo chown $(whoami) /etc/authbind/byport/443
sudo chmod 500 /etc/authbind/byport/443


# Check for Python 3.12
check_python_version

echo -e "[i]\tCreating virtual environment..." | tee -a "${LOGFILE}"
python3.12 -m venv "${VENV_PATH}"
source "${VENV_PATH}/bin/activate"

echo -e "[i]\tUpgrade PIP..." | tee -a "${LOGFILE}"
pip install --upgrade pip

echo -e "[i]\tInstalling dependencies..." | tee -a "${LOGFILE}"
pip install -r requirements.txt

echo -e "[i]\tAllow binding to 443..." | tee -a "${LOGFILE}"
sudo setcap 'cap_net_bind_service=+ep' "${VENV_PATH}/bin/gunicorn"


echo -e "[i]\tCollecting static files...\n\n" | tee -a "${LOGFILE}"
python manage.py collectstatic --noinput

# Check for OpenSSL and generate a certificate
check_openssl_and_generate_cert

# Create a systemd service file for the project
SERVICE_FILE="/etc/systemd/system/${PROJECT_NAME}.service"
echo -e "[i]\tCreating systemd service file at ${SERVICE_FILE}..." | tee -a "${LOGFILE}"

# ExecStart=${VENV_PATH}/bin/gunicorn --workers ${GUNICORN_WORKERS} --bind ${GUNICORN_BIND} --certfile ${PROJECT_DIR}/cert.pem --keyfile ${PROJECT_DIR}/key.pem ${PROJECT_NAME}.wsgi:application

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
sudo systemctl status "${PROJECT_NAME}" | cat

echo -e "[i]\tSetup completed.\n" | tee -a "${LOGFILE}"
