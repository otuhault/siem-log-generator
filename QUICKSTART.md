# Quick Start Guide - Log Generator

## Installation & Running

1. **Install dependencies:**
   ```bash
   cd log-generator
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Open in browser:**
   ```
   http://localhost:5000
   ```

## First Steps

### Create Your First Sender

1. In the web interface, fill out the form:
   - **Name**: "Test Apache Logs"
   - **Log Type**: Apache Access Log
   - **Destination**: `/tmp/logs/apache_test.log`
   - **Frequency**: 10 (logs per second)
   - ✅ Check "Start immediately"

2. Click "Create Sender"

3. Watch the logs count increase in real-time!

4. View the generated logs:
   ```bash
   tail -f /tmp/logs/apache_test.log
   ```

### Test Windows Event Logs

1. Create another sender:
   - **Name**: "Test Windows Security"
   - **Log Type**: Windows Security Event Log
   - **Destination**: `/tmp/logs/windows_security.log`
   - **Frequency**: 5

2. View the XML logs:
   ```bash
   tail -f /tmp/logs/windows_security.log
   ```

## Tips

- **Start/Stop**: Use the play/pause button on any sender
- **Clone**: Duplicate a sender to test different frequencies
- **Monitor**: The interface auto-refreshes every 2 seconds
- **Multiple Senders**: Run as many as you want simultaneously

## Testing with SIEM

### For Splunk:
1. Configure a file monitor input pointing to your log destination
2. Set the sourcetype appropriately:
   - `access_combined` for Apache logs
   - `XmlWinEventLog:Security` for Windows logs

### For Elasticsearch:
1. Use Filebeat to monitor the log files
2. Configure the appropriate input type in filebeat.yml

### For Generic SIEM:
- All logs are written to plain text files
- Can be ingested via file monitoring, syslog forwarding, or API

## Next Steps

1. **Add more log types** - Check README.md for how to add custom generators
2. **Implement HEC** - Add Splunk HTTP Event Collector output
3. **Add Syslog** - Stream logs via syslog protocol
4. **Benchmark mode** - Test SIEM ingestion performance

Enjoy testing! 🚀
