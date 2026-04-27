"""
Splunk HEC (HTTP Event Collector) Sender
"""

import re
import requests
import json
import time
from datetime import datetime

# RFC 3164 syslog header: <PRI>Mon DD HH:MM:SS HOSTNAME MESSAGE
_SYSLOG_RE = re.compile(
    r'^<\d+>'                       # <priority>
    r'\w{3}\s+\d{1,2}\s+'          # Month Day
    r'\d{2}:\d{2}:\d{2}\s+'        # HH:MM:SS
    r'(\S+)\s+'                     # hostname (captured)
    r'(.*)$',                       # message (captured)
    re.DOTALL,
)


class HECSender:
    """Sends logs to Splunk HEC"""

    def __init__(self, url, port, token, index=None, sourcetype=None, host=None, source=None):
        """
        Initialize HEC sender
        url: Splunk HEC URL (e.g., https://splunk.example.com)
        port: HEC port (default 8088)
        token: HEC token
        index: Splunk index (optional)
        sourcetype: Splunk sourcetype (optional)
        host: Host field value (optional, leave None to let Splunk extract from log)
        source: Source field value (optional)
        """
        self.url = url.rstrip('/')
        self.port = port
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self.host = host
        self.source = source

        # Build full HEC endpoint URL
        self.hec_url = f"{self.url}:{self.port}/services/collector/event"

        # Setup session with headers
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Splunk {self.token}',
            'Content-Type': 'application/json'
        })

        # Disable SSL verification warnings (for self-signed certs)
        requests.packages.urllib3.disable_warnings()

    @staticmethod
    def _parse_syslog(event):
        """Strip an RFC 3164 syslog header from a log line.

        Returns (hostname, message) when a header is found, or (None, event)
        when the line is not syslog-framed.  Only operates on plain strings.
        """
        if not isinstance(event, str):
            return None, event
        m = _SYSLOG_RE.match(event)
        if m:
            return m.group(1), m.group(2)
        return None, event

    def _build_payload(self, event_data, timestamp):
        """Build a single HEC JSON payload dict, stripping any syslog header
        and setting the host field to the one extracted from it (unless the
        sender already has an explicit host override).
        """
        extracted_host, raw_event = self._parse_syslog(event_data)

        payload = {
            'event': raw_event,
            'time':  timestamp,
        }

        # Explicit host override wins; fall back to what was in the syslog header
        host = self.host or extracted_host
        if host:
            payload['host'] = host
        if self.index:
            payload['index'] = self.index
        if self.sourcetype:
            payload['sourcetype'] = self.sourcetype
        if self.source:
            payload['source'] = self.source

        return payload

    def send_event(self, event_data):
        """
        Send a single event to HEC
        event_data: Log line or event data (string or dict)
        """
        payload = self._build_payload(event_data, time.time())

        try:
            response = self.session.post(
                self.hec_url,
                data=json.dumps(payload),
                verify=False,  # Disable SSL verification for self-signed certs
                timeout=10
            )

            if response.status_code != 200:
                raise Exception(f"HEC returned status {response.status_code}: {response.text}")

            return True

        except Exception as e:
            # Log error but don't crash - allow sender to continue
            print(f"Error sending to HEC: {str(e)}")
            return False

    def send_batch(self, events):
        """
        Send multiple events in batch to HEC
        events: List of log lines or event data
        """
        current_time = time.time()
        batch_payload = [
            json.dumps(self._build_payload(event, current_time))
            for event in events
        ]

        # Join payloads with newlines
        batch_data = '\n'.join(batch_payload)

        try:
            response = self.session.post(
                self.hec_url,
                data=batch_data,
                verify=False,
                timeout=30
            )

            if response.status_code != 200:
                raise Exception(f"HEC returned status {response.status_code}: {response.text}")

            return True

        except Exception as e:
            print(f"Error sending batch to HEC: {str(e)}")
            return False

    def test_connection(self):
        """Test HEC connection"""
        try:
            # Send a test event
            test_event = {
                'message': 'HEC connection test',
                'timestamp': datetime.now().isoformat()
            }

            result = self.send_event(test_event)
            return result

        except Exception as e:
            print(f"HEC connection test failed: {str(e)}")
            return False

    def close(self):
        """Close the session"""
        self.session.close()
