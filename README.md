# Net4 - Network Forensic Analysis Tool

A desktop application for network forensic analysis with a focus on packet capture and analysis capabilities.

## Features

### 1. Data Ingestion & Processing
- Support for PCAP files and network capture formats
- Scapy-based packet processing
- Live network capture capability
- HTTP/HTTPS traffic analysis with TLS support
- Automatic packet parsing and indexing
- Connection tracking and analysis

### 2. Data Visualization & Exploration
- Overview dashboard with session metrics and traffic patterns
- Network flow analysis with connection filtering
- HTTP/HTTPS traffic inspection with request/response details
- Timeline view for chronological event tracking
- Graph-based visualization of network relationships
- Event analysis dashboard for detailed packet inspection
- Interactive charts and graphs using PyQtGraph

### 3. AI-Powered Analysis
- OpenAI API integration for network traffic analysis
- Interactive chat interface for asking questions about network data
- Automatic session analysis with key findings
- Support for multiple AI models with fallback options:
  - gpt-4o 
  - o1 
  - gpt-4.1-mini
  - gpt-4o-mini
  - o3-mini
  - gpt-4.1-nano
- Structured data extraction from AI responses
- Chat history tracking and management

### 4. Threat Intelligence Integration
- VirusTotal API integration for IP and domain lookups
- Risk classification and scoring
- Threat information display
- Correlation analysis between network entities
- Domain WHOIS information lookup

### 5. Rules Engine
- YAML-based rule format for custom detection rules
- Support for importing Suricata rules
- Pre-configured rule sets for malware and APT detection
- Rule evaluation on data import
- Rule management interface
- Automatic rule reloading

### 6. Reporting
- PDF report generation using ReportLab
- Customizable report templates
- Company branding support
- Session metadata inclusion
- Multiple export formats

## Installation

### Prerequisites
- Python 3.8 or higher
- PyQt6 >= 6.4.0

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
    timeout: 30  # Request timeout in seconds
  openai:
    api_key: ""  # For AI analysis
    model: "gpt-4o"  # AI model to use
    max_tokens: 4000
    timeout: 60

# Analysis Settings
analysis:
  packet_limit: 10000
  max_connections: 5000
  enable_ai: true
  enable_threat_intel: true
  enable_custom_rules: true

# Dashboard Settings
dashboards:
  default: "overview"
  refresh_interval: 30
```

## Project Structure

- **src/** — Main application source code
  - **core/** — Core functionality
    - **analysis/** — Packet and traffic analysis
      - **ai_engine.py** — OpenAI integration and analysis
    - **correlation/** — Entity correlation analysis
    - **data_ingestion/** — Packet capture and processing
    - **rules/** — Rules engine and rule sets
    - **ti/** — Threat intelligence integration
    - **reporting/** — Report generation
  - **models/** — Data models
  - **ui/** — User interface components
    - **dashboards/** — Main application views
      - **ai_insights.py** — AI analysis and chat interface
    - **dialogs/** — Modal dialogs
    - **widgets/** — Reusable UI components
  - **utils/** — Utility functions
- **assets/** — Application assets
- **config.yaml** — Configuration file
- **requirements.txt** — Python dependencies
- **run.sh / run.bat** — Platform-specific launchers

## Development Status

This project is currently in active development. Some features may be incomplete or under construction. We welcome contributions and feedback.

## License
This software is provided as-is under the MIT license. Use at your own risk.
