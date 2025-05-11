# Net4 - Network Forensic Analysis Tool

A desktop application for network forensic analysis with a focus on packet capture and analysis capabilities.

## Features

### 1. Data Ingestion & Processing
- Support for PCAP files and network capture formats
- Basic packet processing using Scapy
- Live network capture capability
- HTTP/HTTPS traffic analysis

### 2. Data Visualization & Exploration
- Basic dashboards for network flow analysis
- Simple metrics display
- Timeline views for event tracking
- HTTP traffic inspection

### 3. Threat Intelligence Integration
- Basic VirusTotal integration for IP and domain lookups
- Simple risk classification
- Threat information display

## Installation

### Prerequisites
- Python 3.8 or higher
- PyQt6

### Installing Dependencies
```bash
pip install -r requirements.txt
```

### Running the Application

#### On Windows:
```cmd
run.bat
```

#### On Linux/Mac:
```bash
chmod +x run.sh
./run.sh
```

## Configuration

The application uses a YAML configuration file located at `config.yaml`. You can modify this file directly or use the Settings dialog within the application.

### Key Configuration Options

```yaml
# API Keys
api:
  virustotal:
    api_key: ""  # For threat intelligence

# Dashboard Settings
dashboards:
  default: "overview"
  refresh_interval: 30
```

## Project Structure

- **src/** — Main application source code
  - **core/** — Core functionality
  - **models/** — Data models
  - **ui/** — User interface components
  - **utils/** — Utility functions
- **assets/** — Application assets
- **config.yaml** — Configuration file
- **requirements.txt** — Python dependencies
- **run.sh / run.bat** — Platform-specific launchers

## Development Status

This project is currently in active development. Some features may be incomplete or under construction. We welcome contributions and feedback.

## License
This software is provided as-is under the MIT license. Use at your own risk.