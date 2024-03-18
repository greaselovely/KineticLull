#!/bin/bash

install_debian() {
    echo -e "[i]\tUpdating system package list..."
    sudo apt-get update

    echo -e "[i]\tInstalling prerequisites for managing repositories..."
    sudo apt-get install -y software-properties-common

    echo -e "[i]\tAdding the Deadsnakes PPA..."
    sudo add-apt-repository ppa:deadsnakes/ppa

    echo -e "[i]\tUpdating system package list again..."
    sudo apt-get update

    echo -e "[i]\tInstalling Python 3.12..."
    sudo apt-get install -y python3.12
    
    echo -e "[i]\tInstalling Python 3.12 distutils..."
    sudo apt-get install python3-distutils

    echo -e "[i]\tInstalling pip for Python 3.12..."
    wget -q https://bootstrap.pypa.io/get-pip.py
    python3.12 get-pip.py

    echo -e "[i]\tUpdating pip to the latest version..."
    python3.12 -m pip install --upgrade pip

    echo -e "[i]\tInstalling python3.12-venv..."
    sudo apt-get install -y python3.12-venv

    echo -e "\n\n[i]\tPython 3.12, pip, and python3.12-venv have been successfully installed.\n\n"
}

install_rhel() {
    echo -e "[i]\tUpdating system package list..."
    sudo yum update

    echo -e "[i]\tInstalling required tools..."
    sudo yum install -y @development

    echo -e "[i]\tInstalling Python 3.12..."
    sudo yum install -y python3.12

    echo -e "[i]\tInstalling pip for Python 3.12..."
    sudo yum install -y python3-pip

    echo -e "[i]\tUpdating pip to the latest version..."
    python3.12 -m pip install --upgrade pip

    echo -e "[i]\tInstalling virtualenv..."
    python3.12 -m pip install virtualenv

    echo -e "\n\n[i]\tPython 3.12, pip, and virtualenv have been successfully installed.\n\n"
}

# Detect system type and run appropriate function
if [ -f /etc/debian_version ]; then
    echo -e "[i]\tDetected Debian-based system."
    install_debian
elif [ -f /etc/redhat-release ]; then
    echo -e "[i]\tDetected RHEL-based system."
    install_rhel
else
    echo -e "[i]\tYour system is not supported by this script."
fi
