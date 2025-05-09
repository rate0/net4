# Net4 - Network Forensic Analysis Tool

A powerful desktop application for deep forensic analysis of network artifacts with AI-powered insights and seamless Threat Intelligence integration.

## Features

### 1. Data Ingestion & Processing
- Support for PCAP files and other network capture formats
- Automatic parsing, indexing, and structuring for efficient analysis
- **Native Scapy-based** packet processing with no external dependencies
- **Live network capture** capability with filtering options
- **HTTP/HTTPS traffic analysis** with detailed request/response inspection

### 2. AI-Powered Analysis
- Uses OpenAI API for advanced analysis
- Automatically analyzes data and highlights key findings
- Answers forensic questions about uploaded files
- Detects anomalies and security threats
- Provides natural language explanations of suspicious traffic

### 3. Data Visualization & Exploration
- Interactive dashboards for exploring network flows, anomalies, and key artifacts
- Graph-based analysis to map relationships between IPs, domains, and timestamps
- Timeline views for event tracking
- **Dedicated HTTP Analysis dashboard** for web traffic inspection
- **Enhanced metric cards** for at-a-glance statistics

### 4. Threat Intelligence (TI) Integrations
- Automated lookup of IPs, domains, and hashes via VirusTotal
- Risk classification (malicious, suspicious, safe) with visual indicators
- Detailed threat information panels showing comprehensive intelligence data
- Automatic correlation between network entities and known threats

### 5. Custom Rules Engine
- Create, manage and evaluate custom detection rules via intuitive UI
- YAML-based rule format with flexible conditions and actions
- Support for importing Suricata rules
- Pre-configured rule sets for common threats (APT, malware)
- Automated rule evaluation on data import
- Rule manager dialog for organizing and editing rules

### 6. Reporting & Exporting
- Beautiful, detailed reports with AI insights and TI results
- Export options: PDF, JSON, CSV
- Customizable report templates with company branding
- **Includes automatically generated logo** in PDF reports

## Dashboard System

Net4 features a flexible dashboard system that provides various views for network analysis:

### Overview Dashboard
The central starting point displaying summary information, key metrics, traffic patterns, and security insights across multiple tabs:
- Summary tab: Session metrics, captured files, entity information
- Traffic tab: Packet timeline, protocol distribution, top talkers
- Security tab: Threat summary, malicious entities, high-severity anomalies
- AI Insights tab: AI analysis summaries and security recommendations

### Network Flow Dashboard
Detailed analysis of network connections, providing filtering by IP, port, protocol, and time range. Features:
- Interactive connection table with detailed filtering
- Connection details including packet timeline visualization
- Related connections display

### HTTP Analysis Dashboard
In-depth HTTP/HTTPS traffic analysis with request/response details, headers, and content inspection:
- HTTP/HTTPS distribution metrics
- Protocol and host filtering
- Detailed request/response inspection
- Header and body analysis
- Content-type recognition
- Traffic patterns visualization
- Customizable traffic filters

### Timeline Dashboard
Chronological view of events for incident response and forensic investigation:
- Interactive time-based visualization
- Event filtering and zooming capabilities
- Detailed event inspection
- Correlation with packet data

### AI Insights Dashboard
Interactive AI-powered analysis providing natural language insights about network traffic:
- Natural language summary of findings
- Key security observations
- Actionable recommendations
- Q&A interface for custom inquiries

## Dashboard Architecture

The dashboard system uses the following components:

1. **TimeSeriesChart**: Traffic visualization with standardized height of 300px for consistent display across all dashboards
2. **DataTable**: Customizable table views for data presentation and filtering
3. **MetricCard**: Key metrics display with colored indicators
4. **DashboardCard**: Container for dashboard widgets with unified styling

## Installation

### Prerequisites
- Python 3.8 or higher
- PyQt6

### Installing Dependencies
```bash
# This will be handled automatically by the run.sh script
# but if you need to install dependencies manually:
pip install -r requirements.txt
```

### Running the Application

We provide a unified launcher script that handles everything automatically:

```bash
# Make the script executable
chmod +x run.sh

# Run the application
./run.sh
```

This single-command launcher provides several benefits:
- **Zero-Configuration**: Just run it and everything works
- **Automatic Setup**: Creates the Python virtual environment if needed
- **Dependency Management**: Installs all required packages automatically
- **First-Run Configuration**: Sets up HTTP/HTTPS support on first run
- **Full Feature Access**: Automatically elevates privileges as needed for live capture
- **Compatibility**: Works with both the Python source and compiled distributions

### Live Packet Capture

When you need to capture live traffic:

1. Run the application (privileges are automatically elevated for live capture):
   ```bash
   ./run.sh
   ```

2. Navigate to: File → Import → Live Capture

3. In the live capture dialog:
   - Select your network interface
   - Set optional BPF filters (with common filter presets for HTTP, HTTPS, DNS)
   - Configure packet limits or duration
   - View real-time statistics during capture
   - Click "Start Capture"

### HTTP/HTTPS Traffic Analysis

To analyze web traffic:

1. HTTP/HTTPS support is automatically configured on first run
2. Import a PCAP file containing web traffic
3. Navigate to the "HTTP Analysis" dashboard tab
4. Use the filtering options to focus on specific traffic

You can also enable HTTP/HTTPS support through the application menu if needed:
Tools → Install HTTP/HTTPS Support

## Configuration

Net4 uses a YAML configuration file located at `config.yaml` in the application directory. You can modify this file directly or use the Settings dialog within the application (Tools → Settings).

### Key Configuration Options

```yaml
# API Keys
api:
  virustotal:
    api_key: ""  # For threat intelligence
  openai:
    api_key: ""  # For AI analysis
    model: "gpt-4o"  # AI model to use

# Dashboard Settings
dashboards:
  default: "overview"  # Default dashboard to show on startup
  refresh_interval: 30  # Auto-refresh interval in seconds
  http_analysis:
    max_display_packets: 1000  # Maximum HTTP packets to display
    show_request_headers: true
    show_response_headers: true
    truncate_body_length: 10000  # Truncate large bodies

# Reporting Settings
reporting:
  company_name: "Net4 Security"
  analyst_name: "Security Analyst"
  logo_path: "assets/icons/app_icon.png"
  theme: "corporate"  # corporate, modern, cyber
```

### API Keys
To use all features, you'll need to configure the following API keys:

1. **OpenAI API Key** - For AI-powered analysis
2. **VirusTotal API Key** - For threat intelligence lookups

You can add these directly to the config file or through the Settings dialog.

## Troubleshooting

### Common Issues

#### Live Capture Not Working
- Ensure you're running with root privileges (`./run.sh --root`)
- Check that your network interface is properly selected
- Verify that no other applications are capturing on the same interface

#### HTTP Analysis Not Showing Data
- Make sure HTTP/HTTPS support is installed (`./run.sh --setup-http`)
- Verify your PCAP file contains HTTP/HTTPS traffic
- Check filter settings in the HTTP Analysis dashboard

#### API Features Not Working
- Confirm API keys are properly configured in Settings
- Check your internet connection
- Verify the API service status

### Getting Help
If you encounter issues:
1. Check the application logs in the `logs` directory
2. See if the issue is addressed in this documentation
3. Run with debug mode: `DEBUG=1 ./run.sh`

## License
This software is provided as-is under the MIT license. Use at your own risk.

On Windows simply double-click `run.bat` or execute it from PowerShell / Command Prompt:

```cmd
run.bat
```

The batch script provides the same zero-configuration workflow: it creates a virtual environment, installs dependencies, configures Scapy HTTP/HTTPS support and starts the application.

## Project Structure & Cleanliness

- **src/** — Main application source code (UI, core logic, models, utils)
- **assets/** — Stylesheets and icons
- **config.yaml** — Main configuration file
- **requirements.txt** — Python dependencies
- **run.sh / run.bat** — Cross-platform launchers
- **venv/** — Python virtual environment (auto-created, do not commit)
- **.git/** — Git version control (do not modify)

**Removed legacy/unused files:**
- Node.js files (`package.json`, `package-lock.json`, `node_modules/`) — not used, safe to ignore/remove
- `setup_scapy_http.py` — legacy script, HTTP/HTTPS support is now automatic

## Documentation & Extending Net4

### Main Modules
- **src/ui/** — All PyQt dashboards, dialogs, widgets, and main window logic
- **src/core/** — Data ingestion, analysis, anomaly detection, reporting, rules, threat intelligence
- **src/models/** — Data models for sessions, entities, events
- **src/utils/** — Config and logging helpers

### How to Extend
- Add new dashboards: create a new file in `src/ui/dashboards/` and register it in `main_window.py`
- Add new analysis: implement in `src/core/analysis/` and call from the UI
- Add new rules: edit YAML files in `src/core/rules/`

### Developer Notes
- All virtual environment files (`venv/`) and git internals (`.git/`) are ignored by default
- No Node.js or JavaScript dependencies are required
- For custom builds, use `build.py` for cross-platform packaging