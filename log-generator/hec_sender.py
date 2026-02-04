"""
Splunk HEC (HTTP Event Collector) Sender
"""

import requests
import json
import time
import socket
from datetime import datetime


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
        host: Host field value (optional, defaults to hostname)
        source: Source field value (optional)
        """
        self.url = url.rstrip('/')
        self.port = port
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self.host = host or socket.gethostname()
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

    def send_event(self, event_data):
        """
        Send a single event to HEC
        event_data: Log line or event data (string or dict)
        """
        # Build HEC event payload
        payload = {
            'event': event_data,
            'time': time.time(),
            'host': self.host
        }

        # Add optional fields if configured
        if self.index:
            payload['index'] = self.index
        if self.sourcetype:
            payload['sourcetype'] = self.sourcetype
        if self.source:
            payload['source'] = self.source

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
        # Build batch payload (multiple JSON objects separated by newlines)
        batch_payload = []
        current_time = time.time()

        for event in events:
            payload = {
                'event': event,
                'time': current_time,
                'host': self.host
            }

            if self.index:
                payload['index'] = self.index
            if self.sourcetype:
                payload['sourcetype'] = self.sourcetype
            if self.source:
                payload['source'] = self.source

            batch_payload.append(json.dumps(payload))

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
