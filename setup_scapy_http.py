#!/usr/bin/env python3
"""
Helper script to set up Scapy with HTTP/HTTPS support.
This script installs necessary dependencies and configures Scapy.
Run this script before using Net4 with HTTP/HTTPS traffic analysis.
"""

import os
import sys
import subprocess
import site
import importlib
import shutil

def get_python_lib_path():
    """Get the path to Python's site-packages directory"""
    site_packages = site.getsitepackages()
    if not site_packages:
        return None
    
    # Return the first site-packages directory
    return site_packages[0]

def install_package(package_name):
    """Install a Python package using pip"""
    print(f"Installing {package_name}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"Successfully installed {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package_name}: {e}")
        return False

def setup_scapy_http():
    """Set up Scapy HTTP support"""
    print("Setting up Scapy with HTTP/HTTPS support...")
    
    # Check if Scapy is installed
    try:
        import scapy
        print(f"Found Scapy version {scapy.__version__}")
    except ImportError:
        print("Scapy is not installed. Installing...")
        if not install_package("scapy>=2.5.0"):
            print("Failed to install Scapy. Aborting.")
            return False
        
        # Try to import again
        try:
            import scapy
            print(f"Successfully installed Scapy version {scapy.__version__}")
        except ImportError:
            print("Failed to import Scapy even after installation. Aborting.")
            return False
    
    # Install dependencies for HTTP/HTTPS parsing
    dependencies = ["cryptography>=39.0.0"]
    for dep in dependencies:
        if not install_package(dep):
            print(f"Warning: Failed to install {dep}, HTTP/HTTPS parsing may be limited.")
    
    # Try to load HTTP layer
    try:
        from scapy.contrib import http
        print("Scapy HTTP layer is already available.")
        http_available = True
    except ImportError:
        http_available = False
        print("Scapy HTTP layer not found, will attempt to install it.")
    
    if not http_available:
        # Get site-packages directory
        site_packages = get_python_lib_path()
        if not site_packages:
            print("Could not determine site-packages directory. Aborting.")
            return False
        
        # Create contrib directory if it doesn't exist
        scapy_path = os.path.join(site_packages, "scapy")
        contrib_path = os.path.join(scapy_path, "contrib")
        
        if not os.path.exists(contrib_path):
            print(f"Creating Scapy contrib directory: {contrib_path}")
            os.makedirs(contrib_path, exist_ok=True)
        
        # Download HTTP layer
        http_url = "https://raw.githubusercontent.com/secdev/scapy/master/scapy/contrib/http.py"
        print(f"Downloading HTTP layer from {http_url}")
        
        try:
            import requests
            response = requests.get(http_url)
            
            if response.status_code == 200:
                http_path = os.path.join(contrib_path, "http.py")
                with open(http_path, "wb") as f:
                    f.write(response.content)
                print(f"Successfully downloaded HTTP layer to {http_path}")
                
                # Create/update __init__.py
                init_path = os.path.join(contrib_path, "__init__.py")
                if not os.path.exists(init_path):
                    with open(init_path, "w") as f:
                        f.write("# Scapy contrib modules\n")
                
                print("Reloading Scapy modules to enable HTTP layer...")
                if "scapy.contrib.http" in sys.modules:
                    del sys.modules["scapy.contrib.http"]
                if "scapy.contrib" in sys.modules:
                    del sys.modules["scapy.contrib"]
                
                # Try to import again
                try:
                    from scapy.contrib import http
                    print("Successfully loaded Scapy HTTP layer.")
                except ImportError:
                    print("Warning: Failed to load Scapy HTTP layer, HTTP parsing may be limited.")
            else:
                print(f"Failed to download HTTP layer: HTTP error {response.status_code}")
        except Exception as e:
            print(f"Error setting up HTTP layer: {str(e)}")
            print("Attempting alternative method...")
            
            # Alternative: Install using git
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "git+https://github.com/secdev/scapy.git"])
                print("Successfully installed Scapy from git, which includes HTTP layer.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install Scapy from git: {e}")
                return False
    
    print("\nScapy HTTP/HTTPS support setup complete.")
    print("You should now be able to analyze HTTP/HTTPS traffic in Net4.")
    print("Please restart Net4 to apply these changes.")
    return True

if __name__ == "__main__":
    print("Net4 - Scapy HTTP/HTTPS Setup")
    print("==============================")
    
    if os.geteuid() == 0:
        # Check if running from virtual environment
        in_venv = sys.prefix != sys.base_prefix
        if not in_venv:
            print("WARNING: Not running in a virtual environment.")
            print("It's recommended to use the run_http_setup.sh script instead.")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                print("Aborted. Please use run_http_setup.sh instead.")
                sys.exit(0)
                
        print("Running with administrator privileges.")
        if setup_scapy_http():
            print("\nSetup completed successfully.")
            sys.exit(0)
        else:
            print("\nSetup failed. Please check the error messages above.")
            sys.exit(1)
    else:
        print("This script requires administrator privileges to install packages.")
        print("Please run using: sudo ./run_http_setup.sh")
        sys.exit(1)