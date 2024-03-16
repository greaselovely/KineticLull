#!/bin/bash

# Stop on error
set -e

# Configuration variables
PROJECT_NAME="kineticlull"
PROJECT_DIR=$(pwd)
VENV_PATH="${PROJECT_DIR}/venv"
GUNICORN_WORKERS=3  # Adjust based on your server's capacity
GUNICORN_BIND="0.0.0.0:443"  # Change to your desired IP and port

# Function to print the Python version not found message and exit
check_python_version() {
  if ! python3 --version | grep 'Python 3.12' &>/dev/null; then
    echo -e "[!]\tCompatible Python version is not installed."
    echo -e "[!]\tAttempting with 'python' command..."
    if ! python --version | grep 'Python 3.12' &>/dev/null; then
      echo -e "[!]\tPython 3.12 is not installed."
      echo -e "[!]\tPlease install Python 3.12 and try again."
      exit 1
    else
      echo -e "[i]\tPython 3.12 is installed (using 'python')."
    fi
  else
    echo -e "[i]\tPython 3.12 is installed (using 'python3')."
  fi
}

# Function to check for OpenSSL and generate a certificate if found
check_openssl_and_generate_cert() {
  if ! command -v openssl &>/dev/null; then
    echo -e "[!]\tOpenSSL is not installed."
    echo -e "[!]\tPlease install OpenSSL to generate an SSL certificate."
    exit 1
  else
    echo -e "[i]\tOpenSSL is installed."
    echo -e "[i]\tGenerating a self-signed SSL certificate for 5 years..."
    openssl req -x509 -newkey rsa:4096 -keyout "${PROJECT_DIR}/key.pem" -out "${PROJECT_DIR}/cert.pem" -days 1825 -nodes
  fi
}

# Check for Python 3.12
check_python_version

echo -e "[i]\tCreating virtual environment..."
python3.12 -m venv "${VENV_PATH}"
source "${VENV_PATH}/bin/activate"

echo -e "[i]\tInstalling dependencies..."
pip install -r requirements.txt

echo -e "[i]\tRunning migrations..."
python manage.py migrate

echo -e "[i]\tCollecting static files..."
python manage.py collectstatic --noinput

# Check for OpenSSL and generate a certificate
check_openssl_and_generate_cert

# Create a systemd service file for the project
SERVICE_FILE="/etc/systemd/system/${PROJECT_NAME}.service"
echo -e "[i]\tCreating systemd service file at ${SERVICE_FILE}..."

sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
[Unit]
Description=Gunicorn instance to serve ${PROJECT_NAME}
After=network.target

[Service]
User=$(whoami)
Group=$(whoami)
WorkingDirectory=${PROJECT_DIR}
ExecStart=${VENV_PATH}/bin/gunicorn --workers ${GUNICORN_WORKERS} --bind ${GUNICORN_BIND} --certfile ${PROJECT_DIR}/cert.pem --keyfile ${PROJECT_DIR}/key.pem ${PROJECT_NAME}.wsgi:application

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
echo -e "[i]\tEnabling and starting ${PROJECT_NAME} service..."
sudo systemctl enable "${PROJECT_NAME}"
sudo systemctl start "${PROJECT_NAME}"

echo -e "[i]\tSetup completed.\n"
