#!/bin/bash

# Stop on error
set -e

# Function to print the Python version not found message and exit
python_version_not_found() {
  echo -e "[!]\tPython 3.12 is not installed."
  echo -e "[!]\tPlease install Python 3.12 and try again."
  exit 1
}

# Check for Python 3.12
if python3 --version | grep 'Python 3.12' &>/dev/null; then
    echo -e "[i]\tPython 3.12 is installed."
elif python --version | grep 'Python 3.12' &>/dev/null; then
    echo  -e "[i]\tPython 3.12 is installed."
else
    python_version_not_found
fi

echo -e "[i]\tCreating virtual environment..."
python3.12 -m venv venv
source venv/bin/activate

echo -e "[i]\tInstalling dependencies..."
pip install -r requirements.txt

echo -e "[i]\tRunning migrations..."
python manage.py migrate

echo -e "[i]\tCollecting static files..."
python manage.py collectstatic --noinput

echo -e "[i]\tSetup completed."
