"""
Splunk HEC (HTTP Event Collector) Sender
"""

import re
import requests
import json
import time
from datetime import datetime

# The wire framing a relay adds. Only the priority is transport: the timestamp
# and hostname after it are part of the message, and add-ons read them back —
# [cisco:asa] takes its time from position 0 (TIME_PREFIX = ^), Splunk_TA_nix
# takes `dest` from the hostname. Removing them costs a field for nothing.
_PRI_RE = re.compile(r'^<\d+>')

# `[<PRI>]Mmm dd hh:mm:ss host …` — the hostname, wherever the line came from.
_SYSLOG_HOST_RE = re.compile(
    r'^(?:<\d+>)?'                  # optional priority
    r'\w{3}\s+\d{1,2}\s+'          # Month Day
    r'\d{2}:\d{2}:\d{2}\s+'        # HH:MM:SS
    r'(\S+)\s'                      # hostname (captured)
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
        """Read the host from a syslog header, and strip only the priority.

        A relay's `<PRI>` is transport and goes. What follows it is not: the
        timestamp and hostname are part of the message, and the add-ons read
        them back — [cisco:asa] takes its time from position 0, Splunk_TA_nix
        takes `dest` from the hostname. This used to remove the whole header,
        which left ASA events beginning `: %ASA-6-302013:` with no timestamp
        for the add-on to find.

        Returns (hostname, message). Only operates on plain strings.
        """
        if not isinstance(event, str):
            return None, event

        body = _PRI_RE.sub('', event, count=1)
        match = _SYSLOG_HOST_RE.match(event)
        return (match.group(1) if match else None), body

    def _build_payload(self, event_data, timestamp, sourcetype=None, source=None, host=None):
        """Build a single HEC JSON payload dict, stripping any syslog header
        and setting the host field to the one extracted from it (unless the
        sender already has an explicit host override).

        `sourcetype` and `source` are the per-event values resolved by the
        caller (one sender can emit several Splunk sourcetypes, and the Windows
        TA classifies on `source`); each wins over the sender-wide default set
        at construction time. Neither is emitted when it resolves to nothing.
        """
        extracted_host, raw_event = self._parse_syslog(event_data)

        payload = {
            'event': raw_event,
            'time':  timestamp,
        }

        # A per-event host is part of the event the caller built (an attack names
        # the machine it happened on); then the sender's override, then the
        # syslog header.
        host = host or self.host or extracted_host
        if host:
            payload['host'] = host
        if self.index:
            payload['index'] = self.index
        effective_sourcetype = sourcetype or self.sourcetype
        if effective_sourcetype:
            payload['sourcetype'] = effective_sourcetype
        effective_source = source or self.source
        if effective_source:
            payload['source'] = effective_source

        return payload

    def send_event(self, event_data, sourcetype=None, source=None, host=None):
        """
        Send a single event to HEC
        event_data: Log line or event data (string or dict)
        sourcetype: per-event Splunk sourcetype; falls back to the sender-wide one
        source:     per-event Splunk source; falls back to the sender-wide one
        host:       per-event host; falls back to the sender-wide one, then to
                    the hostname read from a syslog header
        """
        payload = self._build_payload(event_data, time.time(), sourcetype, source, host)

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
