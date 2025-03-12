# Net4 - Network Forensic Analysis Tool

A powerful desktop application for deep forensic analysis of network artifacts with AI-powered insights and seamless Threat Intelligence integration.

## Features

### 1. Data Ingestion & Processing
- Support for PCAP files, network device logs, and other forensic data
- Automatic parsing, indexing, and structuring for efficient analysis

### 2. AI-Powered Analysis
- Uses OpenAI API for advanced analysis
- Automatically analyzes data and highlights key findings
- Answers forensic questions about uploaded files
- Detects anomalies and security threats

### 3. Data Visualization & Exploration
- Interactive dashboards for exploring network flows, anomalies, and key artifacts
- Graph-based analysis to map relationships between IPs, domains, and timestamps
- Timeline views for event tracking

### 4. Threat Intelligence (TI) Integrations
- Automated lookup of IPs, domains, and hashes via VirusTotal
- Risk classification (malicious, suspicious, safe) with visual indicators

### 5. Reporting & Exporting
- Beautiful, detailed reports with AI insights and TI results
- Export options: PDF, JSON, CSV

## Installation

### Prerequisites
- Python 3.8 or higher
- PyQt6

### Installing Dependencies
```bash
pip install -r requirements.txt
```

### Running the Application
```bash
python main.py
```

## Configuration

Net4 stores its configuration in `~/.net4/config.json`. You can modify this file directly or use the Settings dialog within the application.

### API Keys
To use all features, you'll need to configure the following API keys:

1. **OpenAI API Key** - For AI-powered analysis
2. **VirusTotal API Key** - For threat intelligence lookups

## Usage Guide

### Importing Data
1. Use File → Import to select a PCAP file or log file
2. The data will be automatically processed and displayed in the dashboard

### Analysis
1. Use the "Run AI Analysis" button to get AI-powered insights
2. Use "Detect Anomalies" to find suspicious patterns
3. Use "Threat Intelligence" to look up entity reputation

### Navigation
- **Overview Dashboard**: Summary of key findings
- **Network Flow Dashboard**: Connection details and filtering
- **Timeline Dashboard**: Chronological view of events
- **Graph View Dashboard**: Visual relationship mapping

### Exporting Results
1. Use File → Export Data to save your analysis
2. Choose between PDF reports, JSON data, or CSV exports

## License
This software is provided as-is without warranty. Use at your own risk.