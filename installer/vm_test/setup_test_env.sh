#!/bin/bash
# WineShield - Test Environment Setup Script
# Sets up VM for testing WineShield in isolated environment

set -e

echo "Setting up WineShield test environment..."
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root"
    exit 1
fi

# Install required packages
echo "Installing dependencies..."
apt-get update
apt-get install -y \
    python3 python3-pip \
    wine wine32 wine64 \
    apparmor apparmor-utils \
    libseccomp-dev \
    build-essential \
    git \
    xephyr

echo "Installing Python dependencies..."
pip3 install -r ../../requirements.txt

echo "Test environment setup complete!"
