#!/bin/bash
# install_python.sh

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "[!]\t$1 could not be found"
        return 1
    else
        echo -e "[✓]\t$1 is installed"
        return 0
    fi
}

install_debian() {
    echo -e "[i]\tUpdating system package list..."
    sudo apt-get update || { echo -e "[!]\tFailed to update package list"; exit 1; }

    echo -e "[i]\tInstalling prerequisites..."
    sudo apt-get install -y software-properties-common || { echo -e "[!]\tFailed to install software-properties-common"; exit 1; }

    echo -e "[i]\tAdding the Deadsnakes PPA..."
    sudo add-apt-repository ppa:deadsnakes/ppa -y || { echo -e "[!]\tFailed to add Deadsnakes PPA"; exit 1; }

    echo -e "[i]\tUpdating system package list again..."
    sudo apt-get update || { echo -e "[!]\tFailed to update package list"; exit 1; }

    echo -e "[i]\tInstalling Python 3.12..."
    sudo apt-get install -y python3.12 || { echo -e "[!]\tFailed to install Python 3.12"; exit 1; }
    check_command python3.12

    echo -e "[i]\tInstalling python3-pip..."
    sudo apt-get install -y python3-pip || { echo -e "[!]\tFailed to install python3-pip"; exit 1; }
    check_command pip3

    echo -e "[i]\tInstalling python3-venv..."
    sudo apt-get install -y python3-venv || { echo -e "[!]\tFailed to install python3-venv"; exit 1; }

    echo -e "[i]\tInstalling python3-setuptools..."
    sudo apt-get install -y python3-setuptools || { echo -e "[!]\tFailed to install python3-setuptools"; exit 1; }

    echo -e "\n\n[i]\tPython 3.12, pip, venv, and setuptools have been installed.\n"
}

install_rhel() {
    echo -e "[i]\tUpdating system package list..."
    sudo yum update -y || { echo -e "[!]\tFailed to update package list"; exit 1; }

    echo -e "[i]\tInstalling required tools..."
    sudo yum groupinstall -y "Development Tools" || { echo -e "[!]\tFailed to install development tools"; exit 1; }

    echo -e "[i]\tInstalling Python 3.12..."
    sudo yum install -y python3.12 || { echo -e "[!]\tFailed to install Python 3.12"; exit 1; }
    check_command python3.12

    echo -e "[i]\tInstalling pip for Python 3.12..."
    sudo yum install -y python3-pip || { echo -e "[!]\tFailed to install python3-pip"; exit 1; }
    check_command pip3.12

    echo -e "[i]\tUpdating pip to the latest version..."
    sudo python3.12 -m pip install --upgrade pip || { echo -e "[!]\tFailed to upgrade pip"; exit 1; }

    echo -e "[i]\tInstalling virtualenv..."
    sudo python3.12 -m pip install virtualenv || { echo -e "[!]\tFailed to install virtualenv"; exit 1; }
    check_command virtualenv

    echo -e "\n\n[i]\tPython 3.12, pip, and virtualenv have been installed.\n\n"
}

# Detect system type and run appropriate function
if [ -f /etc/debian_version ]; then
    echo -e "[i]\tDetected Debian-based system."
    install_debian
elif [ -f /etc/redhat-release ]; then
    echo -e "[i]\tDetected RHEL-based system."
    install_rhel
else
    echo -e "[!]\tYour system is not supported by this script."
    exit 1
fi

# Final checks
echo -e "[i]\tPerforming final checks..."
check_command python3.12
check_command pip3.12
python3.12 -m venv test_venv && echo -e "[✓]\tvenv test is successful" && rm -rf test_venv || echo -e "[!]\tvenv test failed"
