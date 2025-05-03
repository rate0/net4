#!/bin/bash
# Unified launcher script for Net4
# This script handles both normal and root execution with proper environment setup

# Get the absolute path to the current directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if the virtual environment exists, create if needed
if [ ! -d "$DIR/venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$DIR/venv"
    
    echo "Installing dependencies..."
    "$DIR/venv/bin/pip" install -r "$DIR/requirements.txt"
    
    # Automatically set up HTTP/HTTPS support during initial installation
    echo "Setting up HTTP/HTTPS support..."
    if [ "$(id -u)" -ne 0 ]; then
        echo "Setting up HTTP/HTTPS support (requires root privileges)..."
        sudo "$DIR/venv/bin/python" "$DIR/setup_scapy_http.py"
    else
        # Already running as root
        "$DIR/venv/bin/python" "$DIR/setup_scapy_http.py"
    fi
fi

# Check if running as root is needed for live capture
if [ "$(id -u)" -ne 0 ]; then
    echo "Launching Net4 with root privileges (for live capture capabilities)..."
    sudo "$DIR/venv/bin/python" "$DIR/main.py" "$@"
else
    # Already running as root
    echo "Launching Net4..."
    "$DIR/venv/bin/python" "$DIR/main.py" "$@"
fi

exit 0