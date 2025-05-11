# Net4 Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [Project Overview](#project-overview)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Main Features](#main-features)
   - [Working with Network Data](#working-with-network-data)
   - [Viewing Network Information](#viewing-network-information)
   - [AI Assistant Features](#ai-assistant-features)
   - [Threat Detection](#threat-detection)
   - [Custom Detection Rules](#custom-detection-rules)
   - [Report Creation](#report-creation)
6. [User Interface](#user-interface)
7. [How Net4 Works](#how-net4-works)
8. [External Services](#external-services)
9. [File Types Supported](#file-types-supported)
10. [Development Information](#development-information)
11. [Program Files and Folders](#program-files-and-folders)
12. [Fixing Common Problems](#fixing-common-problems)

## Introduction

Net4 is a tool that helps you analyze network traffic on your computer. It shows you what's happening on your network in a way that's easy to understand. Whether you're checking for security problems or just curious about your network traffic, Net4 makes it simple with helpful visuals and AI-powered assistance.

## Project Overview

Net4 is built to be easy to use, fast, and flexible. It's made with Python and has a friendly user interface that works on Windows, Mac, and Linux. The main parts of Net4 include:

- **Data Processing**: Takes network traffic data and makes sense of it
- **User Interface**: Shows information in a way that's easy to understand
- **AI Assistant**: Uses artificial intelligence to help analyze your data
- **Threat Detection**: Checks if anything suspicious is happening on your network
- **Custom Rules**: Lets you create your own checks for specific network behaviors

## Installation

### What You Need Before Starting
- Python 3.8 or newer
- PyQt6 version 6.4.0 or newer

### How to Install

1. Download the Net4 files to your computer
2. Open a command prompt or terminal window
3. Run this command to install the required software:
   ```
   pip install -r requirements.txt
   ```
4. Optional but recommended: Add your API keys to the `config.yaml` file (for AI and threat detection features)

### Starting the Program

#### On Windows:
Double-click the `run.bat` file or open a command prompt and type:
```
run.bat
```

#### On Mac or Linux:
Open a terminal and type:
```
chmod +x run.sh
./run.sh
```
This first command makes the startup file executable, and the second command runs it.

## Configuration

Net4 uses a file called `config.yaml` to store its settings. You can change these settings by editing this file in a text editor. Here are the main settings you can change:

### API Keys
```yaml
api:
  virustotal:
    api_key: ""  # Add your VirusTotal key here for threat detection
    timeout: 30  # How many seconds to wait for a response
  openai:
    api_key: ""  # Add your OpenAI key here for AI features
    model: "gpt-4o"  # Which AI model to use
    max_tokens: 4000
    timeout: 60
```

### Display Settings
```yaml
ui:
  theme: "dark"  # Choose "dark" or "light"
  font_size: 10
  confirm_actions: true  # Ask before performing important actions
```

### Log Settings
```yaml
logging:
  level: "INFO"  # How much detail to include in logs (INFO is normal)
  file: "net4.log"  # Where to save logs
  max_size_mb: 10  # Maximum log file size
  backup_count: 5  # Number of old log files to keep
```

### Analysis Settings
```yaml
analysis:
  packet_limit: 10000  # Maximum number of network packets to process
  max_connections: 5000  # Maximum number of connections to track
  enable_ai: true  # Turn AI features on/off
  enable_threat_intel: true  # Turn threat detection on/off
  enable_custom_rules: true  # Turn custom rules on/off
```

### Dashboard Settings
```yaml
dashboards:
  default: "overview"  # Which screen to show when starting
  refresh_interval: 30  # How often to update (in seconds)
  http_analysis:
    max_display_packets: 1000  # Maximum HTTP packets to show
    show_request_headers: true  # Show HTTP request details
    show_response_headers: true  # Show HTTP response details
    truncate_body_length: 10000  # Cut off large content after this many characters
```

## Main Features

### Working with Network Data

Net4 can analyze network traffic in several ways:

#### Network Capture Files (PCAP)
- Import and read network capture files (.pcap files)
- Support for various network data formats
- Look at detailed information about network packets
- Track connections between devices
- See which programs are using your network

#### How It Works
Net4 uses a component called `PcapProcessor` to read network data. It:
- Looks at each packet's information
- Groups related packets together
- Identifies what types of connections are happening
- Extracts useful information for analysis

#### Live Capture
Net4 can also capture live network traffic as it happens:
- Choose which network connection to monitor
- Set filters to only capture certain types of traffic
- Save the captured data to a file
- See real-time statistics while capturing

### Viewing Network Information

Net4 has different screens (called dashboards) to help you see what's happening on your network:

#### Overview
- Shows a summary of all network traffic
- Charts showing which protocols (network languages) are being used
- Timeline showing when traffic happened
- Lists of the most active devices on the network
- Quick links to important events

#### Network Flow
- Visual map of connections between devices
- Filter to show only certain types of connections
- Breakdown of which protocols are being used
- Timeline of when connections happened
- Graph showing how devices are connected

#### HTTP/HTTPS Analysis
- See web traffic details (websites visited)
- Look at request and response headers
- View webpage content
- Lists of URLs visited
- Reconstruction of web browsing sessions

#### Event Analysis
- Detailed inspection of individual packets
- Special tools to understand different protocols
- View raw data
- See how events relate in time

### AI Assistant Features

Net4 uses artificial intelligence to help analyze network data:

#### AI Engine
- Uses OpenAI's technology to analyze network traffic
- Works with different AI models depending on what's available
- Supported models include:
  - gpt-4o (main model)
  - o1 (alternative advanced model)
  - gpt-4.1-mini (faster model)
  - gpt-4o-mini (smaller model)
  - o3-mini (alternative smaller model)
  - gpt-4.1-nano (very small model)

#### How It Works
The AI assistant can:
- Find potential security issues in your network traffic
- Explain unusual network behavior in simple terms
- Summarize network activity
- Answer your questions about the traffic
- Suggest what to investigate further

#### Chat Interface
The AI screen includes:
- A chat box where you can ask questions
- History of your previous questions and answers
- Option to save important insights
- Ability to ask about specific devices or connections

### Threat Detection

Net4 can check if devices on your network might be dangerous:

#### VirusTotal Connection
- Looks up IP addresses and domain names in a security database
- Checks file fingerprints (hashes)
- Shows how many security tools flag something as dangerous
- Provides information about related threats

#### Risk Rating
- Scores the risk level of network devices
- Labels items as dangerous, suspicious, or safe
- Connects related threats together
- Shows threat information where it's most helpful

### Custom Detection Rules

Net4 lets you create your own checks for finding specific network behavior:

#### Rule Format
- Simple text-based rule format (YAML)
- Can check for multiple conditions
- Define what happens when a rule matches
- Set severity levels and categories

#### Suricata Rule Support
- Works with Suricata format rules
- Converts rules to work efficiently
- Optimizes performance for imported rules

#### Rule Management
The program includes a special screen for managing rules:
- Turn rules on or off
- Create new rules
- Edit existing rules
- Organize rules by category
- Test rules against your network data

### Report Creation

Net4 can create reports to share your findings:

#### Report Generation
- Creates PDF reports with your network analysis
- Customizable report templates
- Option to add your company logo
- Includes charts and graphs
- Detailed findings section

#### Export Options
- PDF files for formal reports
- CSV files for spreadsheet analysis
- JSON files for use with other tools
- HTML files for viewing in a web browser

## User Interface

Net4 has a modern, easy-to-use interface:

### Main Window
- Tab-based design to switch between different views
- Side panels that can be shown or hidden
- Right-click menus for common actions
- Dark and light color themes
- Status bar showing progress indicators

### Network Device List
- Tree view of network devices grouped by type
- Filter and sort options
- Right-click menus for device-specific actions
- Color indicators for threat levels
- Quick access to device details

### Search
- Search across all your network data
- Suggestions as you type
- Results grouped by type
- Click results to jump to that item

## How Net4 Works

Net4 is built with a modular design that keeps things organized:

### Main Components
- **Data Processing**: Handles reading and understanding network data
- **Analysis**: Examines data to find patterns and issues
- **User Interface**: Shows information and lets you interact with it
- **Integration**: Connects with outside services like OpenAI and VirusTotal

### Processing Tasks
- Heavy processing runs in the background so the interface stays responsive
- Progress updates show you what's happening
- Long operations show progress bars
- Safe data handling prevents crashes

### Data Organization
- Information is organized by sessions
- Network items are connected in a relationship model
- Data is kept in memory for speed with option to save to disk

## External Services

Net4 connects to these outside services to add extra features:

### OpenAI Service
- Uses the chat API for analysis
- Has backup options if the preferred AI model isn't available
- Structures questions to get consistent results
- Handles errors and retries automatically

### VirusTotal Service
- Looks up network items to check if they're dangerous
- Follows rate limits to avoid being blocked
- Saves results to avoid repeated lookups
- Handles connection problems gracefully

## File Types Supported

Net4 works with several file formats:

### Input Files
- PCAP (standard network capture format)
- PCAPNG (newer network capture format)
- Various log file formats

### Output Files
- PDF reports
- CSV spreadsheet data
- JSON data format
- HTML web pages

## Development Information

### Adding New Features
1. Find the right section of code for your feature
2. Follow the patterns used in similar existing code
3. Add tests to make sure everything works
4. Update this documentation with your new feature

### Interface Development
- Use Qt Designer for creating new screens
- Follow the existing layout patterns
- Use signals and slots to connect components
- Keep styling consistent with the rest of the program

### Building Packages
- Use the `build.py` script to create installable packages
- Include all necessary dependencies
- Package all required assets and documentation

## Program Files and Folders

Net4 is organized like this:

```
net4/
├── assets/              # Images, icons, and styles
├── src/                 # Source code
│   ├── core/            # Main program functions
│   │   ├── analysis/    # Analysis tools
│   │   ├── correlation/ # Connection tracking
│   │   ├── data_ingestion/ # Data import
│   │   ├── reporting/   # Report creation
│   │   ├── rules/       # Detection rules
│   │   └── ti/          # Threat intelligence
│   ├── models/          # Data structures
│   ├── ui/              # User interface
│   │   ├── dashboards/  # Main screens
│   │   ├── dialogs/     # Pop-up windows
│   │   └── widgets/     # Reusable interface components
│   └── utils/           # Helper functions
├── tests/               # Program tests
├── config.yaml          # Settings file
├── requirements.txt     # Required software list
├── build.py             # Build script
├── main.py              # Program starting point
└── run.bat/run.sh       # Startup files
```

## Fixing Common Problems

### API Key Issues
- If AI or threat detection isn't working, check that you've added your API keys to `config.yaml`
- Make sure there are no extra spaces in your API keys

### Performance Problems
- If the program is slow with large files, try changing the `packet_limit` and `max_connections` settings in `config.yaml`
- Try turning off AI features for very large data sets by setting `enable_ai: false` in `config.yaml`

### Installation Issues
- Make sure you have Python 3.8 or newer installed
- Verify that all dependencies are installed with `pip install -r requirements.txt`
- If PyQt6 issues occur, try updating with `pip install --upgrade PyQt6`

### Network Capture Problems
- For live capture issues, check that you have the necessary permissions
- On Windows, you may need to install WinPcap or Npcap
- On Linux, you might need to run with admin privileges (sudo)

### Getting Help
- Report bugs through GitHub Issues
- Check this documentation for guidance
- Look at the program logs (default: `net4.log`) for error details 