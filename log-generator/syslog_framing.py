"""RFC 3164 framing, for sources shipped over syslog rather than by a forwarder.

A source collected by a universal forwarder or a scripted input reaches Splunk as
the file's own bytes: `type=USER_AUTH msg=audit(...)` for auditd, the plain sshd
line for /var/log/secure. Send those same bytes to SC4S and nothing can be done
with them — there is no priority to route on, no program name to pick a
sourcetype from, and no hostname to attribute the event to.

So the delivery format is a property of the sender, not of the source: the same
auditd record is one thing on a forwarder and another on the wire to a
collector. `delivery_format` picks between them, and this module adds the
framing when it is `syslog`.

Which facility, severity and program name each source uses is declared in
ta_registry.py, not here — a TA without `syslog_framing` either frames itself
already (Palo Alto, Cisco ASA/FTD/XR emit their own priority) or is not
collected over syslog at all (Windows, Active Directory).
"""

import random
import re
from datetime import datetime

#: Numeric codes, RFC 3164 §4.1.1.
FACILITIES = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3, 'auth': 4, 'syslog': 5,
    'lpr': 6, 'news': 7, 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

SEVERITIES = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7,
}

#: A line that already carries a priority needs nothing from us.
_HAS_PRI = re.compile(r'^<\d+>')

#: `key=value` severity carried by the event itself, for the sources whose
#: framing declares `severity_field`.
def _field_value(line, field):
    match = re.search(rf'\b{re.escape(field)}="?([A-Za-z]+)"?', line)
    return match.group(1) if match else None


#: Vendor spellings of the syslog severities. FortiOS writes `level=information`
#: where RFC 3164 says `info`; the three below are the only ones that differ.
SEVERITY_ALIASES = {
    'emergency': 'emerg',
    'critical': 'crit',
    'error': 'err',
    'information': 'info',
    'informational': 'info',
    'notification': 'notice',
    'warn': 'warning',
}

#: `Mmm dd hh:mm:ss host tag` — the header sshd writes to a file. Such a line
#: needs the priority prepended and nothing else: rebuilding the header would
#: replace the hostname the add-on reads `dest` back out of.
_HAS_BSD_HEADER = re.compile(r'^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s\S+\s\w+')


def priority(facility, severity):
    """The <PRI> value, or None when either name is unknown."""
    fac = FACILITIES.get(facility)
    sev = SEVERITIES.get(severity)
    if fac is None or sev is None:
        return None
    return fac * 8 + sev


def _timestamp(now=None):
    """`Mmm dd hh:mm:ss`, with the day space-padded as RFC 3164 requires."""
    now = now or datetime.now()
    return f'{now.strftime("%b")} {now.day:>2} {now.strftime("%H:%M:%S")}'


class SyslogFramer:
    """Adds RFC 3164 framing to lines that lack it.

    Deliberately conservative about what it rewrites: a line that already has a
    priority is returned untouched, and a line that already has a header keeps
    it. Only the missing part is added, because the hostname and timestamp a
    generator wrote are the ones the add-on's own extractions read.
    """

    def __init__(self, framing, host_pool=None, default_host='localhost'):
        """
        framing      : the TA's `syslog_framing` dict from the registry
        host_pool    : roster key holding a hostname for this log type, if any
        default_host : used when neither the line nor the environment has one
        """
        self.facility = framing.get('facility', 'user')
        self.severity = framing.get('severity', 'info')
        self.priority = priority(self.facility, self.severity)
        self.tag = framing.get('tag')
        # Three shapes, because three kinds of device write three headers:
        #   bsd        the ordinary RFC 3164 frame — ssh, auditd, apache, zscaler
        #   none       priority then payload, nothing between — FortiOS
        #   origin-id  priority, the device's own name, then its console body —
        #              Cisco IOS, which is `logging origin-id hostname`
        self.header = framing.get('header', 'bsd')
        # A device that derives the PRI severity from the event itself rather
        # than sending everything at one level: FortiOS from a `key=value`
        # field, Cisco IOS from the digit inside %FACILITY-SEVERITY-MNEMONIC.
        self.severity_field = framing.get('severity_field')
        self.severity_pattern = (re.compile(framing['severity_pattern'])
                                 if framing.get('severity_pattern') else None)
        self.host_pool = host_pool
        self.default_host = default_host

    def _priority_for(self, line):
        """The <PRI> of one line: the event's own severity when it has one.

        Either a name the vendor spells its own way, or the bare digit Cisco puts
        in the middle of its message tag. Anything unrecognised falls back to the
        declared default rather than being guessed at.
        """
        if self.severity_pattern:
            match = self.severity_pattern.search(line)
            if not match or not match.group(1).isdigit():
                return self.priority
            value = int(match.group(1))
            if not 0 <= value <= 7:
                return self.priority
            return FACILITIES[self.facility] * 8 + value
        if not self.severity_field:
            return self.priority
        raw = _field_value(line, self.severity_field)
        if not raw:
            return self.priority
        name = SEVERITY_ALIASES.get(raw.lower(), raw.lower())
        return priority(self.facility, name) or self.priority

    def frame(self, line, host=None):
        """Return `line` with whatever framing it is missing."""
        if self.priority is None or not isinstance(line, str) or not line:
            return line
        if _HAS_PRI.match(line):
            return line
        if self.header == 'none':
            return f'<{self._priority_for(line)}>{line}'
        if self.header == 'origin-id':
            # No timestamp and no host of ours: the device keeps its own console
            # header and only names itself in front of it, which is the one thing
            # SC4S can attribute the event to.
            return f'<{self._priority_for(line)}>{host or self.default_host}: {line}'
        if _HAS_BSD_HEADER.match(line):
            # Keep the generator's own header — it carries the hostname the
            # add-on reads dest from — and prepend only the priority.
            return f'<{self.priority}>{line}'

        header = f'<{self.priority}>{_timestamp()} {host or self.default_host}'
        if self.tag:
            header = f'{header} {self.tag}:'
        return f'{header} {line}'

    def host_for(self, generator):
        """The hostname of the entity the generator just drew, when there is one.

        Resolved through the generator's own lookup rather than by reaching into
        its state: the mixin already knows which side each pool belongs to, and
        the host of a log is the machine that wrote it — the dest end for ssh and
        auditd, where the address is the remote caller.
        """
        # An attack names the machine its events happened on, and the detection
        # groups by that name. It wins over any roster draw — and over the
        # default host, which would otherwise be what a collector attributes an
        # attack's events to.
        named = getattr(generator, 'syslog_host', None)
        if named:
            return named
        if not self.host_pool:
            return None
        lookup = getattr(generator, '_entity_field', None)
        if lookup is None:
            return None
        if self.header == 'origin-id':
            # Here the hostname is not decoration: it is the only thing SC4S can
            # attribute the event to, so with no environment configured it falls
            # back to the generator's own roster rather than to `localhost`.
            # Scoped to this mode, so the sources already on the wire keep the
            # behaviour they have.
            own = getattr(generator, self.host_pool, None) or []
            return lookup(self.host_pool,
                          lambda: random.choice(own) if own else None)
        return lookup(self.host_pool, lambda: None)


def host_pool_for(log_type):
    """Which roster key holds a hostname for `log_type`, if any."""
    from environment_manager import ENTITY_TYPE_ROLES

    for log_map in ENTITY_TYPE_ROLES.values():
        for pool, entity_field, _ in log_map.get(log_type, []):
            if entity_field == 'nt_host':
                return pool
    return None


class SyslogFramedGenerator:
    """Wraps one generator instance so every line it produces leaves framed.

    Wrapped per instance, before MultiSourceLogGenerator groups them: the
    hostname comes from the entity *that instance* just drew, and the sourcetype
    and source attribution above stays untouched.

    Wrapping rather than teaching each generator keeps one implementation of the
    framing, and keeps the file and HEC paths consistent with the syslog one —
    the delivery format describes the events, not just the transport that
    happens to carry them.
    """

    def __init__(self, inner, framer):
        self._inner = inner
        self._framer = framer

    def generate(self):
        line = self._inner.generate()
        return self._framer.frame(line, self._framer.host_for(self._inner))

    def generate_noise(self):
        # An attack's benign events leave in the same shape as its attack events.
        line = self._inner.generate_noise()
        return self._framer.frame(line, self._framer.host_for(self._inner))

    def __getattr__(self, name):
        # Injection (inject_into, inject_network_pools_into) and the A&I state it
        # sets must keep reaching the real generator.
        return getattr(self._inner, name)


# ── delivery format: what the bytes look like, per destination ─────────────────
#
# Two shapes of the same event:
#   uf      the raw event — what a forwarder reads from disk, and what Splunk
#           indexes once a collector has taken the framing off
#   syslog  framed — priority and header, as a device sends it to a collector
#
# Which ones a destination can hold:
#   HEC     the event itself; a priority would only be stripped again  → no choice
#   syslog  a source that frames itself, or has no forwarder path, is always
#           framed; the others choose                                  → sometimes
#   file    either shape is a legitimate file — a forwarder's input, or a
#           capture of what a device put on the wire                   → always,
#           for any source collected over syslog at all

DELIVERY_FORMATS = ('uf', 'syslog')


def self_framed(ta):
    """A source whose generator writes its own priority (Palo Alto, Cisco ASA).

    A TA with no `syslog_framing` either does that or is never collected over
    syslog — ta_registry.py documents exactly those two cases.
    """
    return ta.get('syslog_viable', True) is not False and not ta.get('syslog_framing')


def default_delivery_format(ta):
    """The shape a source's events already have when nothing is chosen."""
    return 'syslog' if self_framed(ta) else 'uf'


def offered_delivery_formats(ta, destination_type):
    """The formats a form should offer; fewer than two means there is no choice."""
    if ta.get('syslog_viable') is False:
        return []
    if destination_type == 'file':
        return list(DELIVERY_FORMATS)
    if destination_type == 'syslog':
        if ta.get('syslog_framing') and ta.get('forwarder_viable', True):
            return list(DELIVERY_FORMATS)
    return []


def delivery_description(ta):
    """The per-destination offer and default, as the API hands it to a form."""
    return {
        'default': default_delivery_format(ta),
        'offered': {dest: offered_delivery_formats(ta, dest)
                    for dest in ('file', 'syslog', 'configuration')},
    }


class PriorityStrippedGenerator:
    """Wraps a self-framing generator so its lines leave without the <PRI>.

    What a syslog server writes to disk, and what a forwarder then reads: the
    header and the message, the priority consumed on arrival.
    """

    def __init__(self, inner):
        self._inner = inner

    @staticmethod
    def _strip(line):
        return _HAS_PRI.sub('', line, count=1) if isinstance(line, str) else line

    def generate(self):
        return self._strip(self._inner.generate())

    def generate_noise(self):
        return self._strip(self._inner.generate_noise())

    def __getattr__(self, name):
        return getattr(self._inner, name)


def apply_delivery_format(instances, log_type, requested, destination_type):
    """Wrap each generator so its lines leave in the delivery format that applies."""
    from ta_registry import get_ta

    ta = get_ta(log_type) or {}
    if ta.get('syslog_viable') is False or destination_type not in ('file', 'syslog'):
        return instances

    framing = ta.get('syslog_framing')
    if destination_type == 'syslog':
        wanted = 'syslog' if (self_framed(ta) or requested == 'syslog'
                              or ta.get('forwarder_viable', True) is False) else 'uf'
    else:
        wanted = requested if requested in DELIVERY_FORMATS else default_delivery_format(ta)

    if self_framed(ta):
        return [PriorityStrippedGenerator(g) for g in instances] if wanted == 'uf' else instances
    if framing and wanted == 'syslog':
        framer = SyslogFramer(framing, host_pool_for(log_type))
        return [SyslogFramedGenerator(g, framer) for g in instances]
    return instances
