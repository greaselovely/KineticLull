#!/bin/bash

# For ubuntu / debian use this script to automate / help you install Python3.12, PIP and venv.

# Update system package list
echo -e "[i]\tUpdating system package list..."
sudo apt-get update

# Install prerequisites for adding a new repository over HTTPS
echo -e "[i]\tInstalling prerequisites for managing repositories..."
sudo apt-get install -y software-properties-common

# Add the Deadsnakes PPA
echo -e "[i]\tAdding the Deadsnakes PPA..."
sudo add-apt-repository ppa:deadsnakes/ppa

# Update package list after adding new repository
echo -e "[i]\tUpdating package list after adding Deadsnakes PPA..."
sudo apt-get update

# Install Python 3.12
echo -e "[i]\tInstalling Python 3.12..."
sudo apt-get install -y python3.12

# Install pip for Python 3.12
echo -e "[i]\tInstalling pip for Python 3.12..."
sudo apt-get install -y python3-pip

# Update pip to the latest version
echo -e "[i]\tUpdating pip to the latest version..."
python3.12 -m pip install --upgrade pip

# Install python3.12-venv for creating virtual environments
echo -e "[i]\tInstalling python3.12-venv..."
sudo apt-get install -y python3.12-venv

echo -e "\n\n[i]\tPython 3.12, pip, and python3.12-venv have been successfully installed.\n\n"
