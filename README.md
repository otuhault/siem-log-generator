# Log Generator - SIEM Testing Tool

A powerful log generation tool for testing SIEM systems. Generate realistic logs from various sources including Apache web servers and Windows Security Event Logs.

## Features

- 🎯 **Multiple Log Types**: Apache access logs, Windows Security Event Logs (with 12 common Event IDs)
- 🎛️ **Easy Management**: Web-based UI to create, enable/disable, clone, and delete senders
- ⚡ **Configurable Frequency**: Control how many logs per second each sender generates
- 📊 **Real-time Monitoring**: See logs generated count in real-time
- 🔄 **Multi-threaded**: Run multiple senders simultaneously without blocking
- 📝 **Realistic Output**: Logs are identical to real server/endpoint output

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser to: `http://localhost:5000`

## Usage

### Creating a Sender

1. Open the web interface
2. Fill in the form:
   - **Sender Name**: A descriptive name (e.g., "Web Server Logs")
   - **Log Type**: Choose Apache Access Log or Windows Security Event Log
   - **Destination**: Full path where logs will be written (e.g., `/tmp/logs/apache.log`)
   - **Frequency**: Logs per second (1-1000)
   - **Start Immediately**: Check to enable right away

3. Click "Create Sender"

### Managing Senders

Each sender card shows:
- Current status (Running/Stopped)
- Destination file
- Frequency
- Total logs generated
- Creation timestamp

Actions available:
- **⏸️/▶️ Toggle**: Start/stop log generation
- **📋 Clone**: Duplicate sender with same settings
- **🗑️ Delete**: Remove sender permanently

## Log Types

### Apache Access Log
Generates logs in Combined Log Format identical to real Apache/Nginx servers:
```
192.168.1.100 - - [02/Feb/2026:18:52:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://www.google.com/" "Mozilla/5.0..."
```

Features:
- Realistic IP addresses
- Varied HTTP methods (GET, POST)
- Mix of status codes (200, 404, 403, 500)
- Authentic user agents (Chrome, Firefox, Safari, Mobile)
- Weighted request distribution

### Windows Security Event Log
Generates authentic Windows Event Logs in XML format with 12 common Event IDs:

- **4624**: Successful Logon
- **4625**: Failed Logon
- **4634**: Logoff
- **4672**: Special Privileges Assigned
- **4688**: Process Created
- **4689**: Process Terminated
- **4698**: Scheduled Task Created
- **4699**: Scheduled Task Deleted
- **4720**: User Account Created
- **4726**: User Account Deleted
- **4732**: Member Added to Security Group
- **4756**: Member Added to Universal Security Group

Each event includes:
- Proper XML structure matching Windows Event Viewer
- Realistic usernames, domains, workstations
- Accurate process paths
- Valid SIDs and Logon IDs

## Project Structure

```
log-generator/
├── app.py                    # Flask web application
├── log_senders.py           # Sender management and threading
├── log_generators/
│   ├── apache.py            # Apache log generator
│   └── windows.py           # Windows Event log generator
├── templates/
│   └── index.html           # Web UI
├── static/
│   ├── css/
│   │   └── style.css        # Styling
│   └── js/
│       └── app.js           # Frontend JavaScript
└── requirements.txt
```

## Future Enhancements

Planned features:
- More log types (Palo Alto, Cisco, AWS CloudTrail, etc.)
- HTTP Event Collector (HEC) output for Splunk
- Syslog output support
- Benchmark mode for performance testing
- Log filtering/customization options
- Statistics and metrics dashboard

## Technical Details

- **Backend**: Python 3 with Flask
- **Threading**: Multi-threaded log generation using Python's threading module
- **Storage**: JSON-based configuration (senders_config.json)
- **Frontend**: Vanilla JavaScript with responsive CSS

## Contributing

To add a new log type:

1. Create a new generator class in `log_generators/`
2. Implement a `generate()` method that returns a single log line
3. Register it in `SenderManager.log_generators` (log_senders.py)
4. Add it to the dropdown in the frontend

Example:
```python
class MyLogGenerator:
    def generate(self):
        # Your log generation logic
        return "your log line here"
```

## License

MIT License - feel free to use and modify!
