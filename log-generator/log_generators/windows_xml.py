"""Render a Windows event the way Windows itself renders it.

A universal forwarder with `renderXml = true` ships the XML that the Windows
Event Log API produces, and that XML has a precise shape: one line, no
indentation, every attribute in single quotes, and a `SystemTime` in UTC with
seven fractional digits and a `Z`.

    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{…}'/><EventID>4688</EventID>…<TimeCreated SystemTime='2026-09-14T15:51:56.4359330Z'/>…</System><EventData><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data>…</EventData></Event>

The shape is not cosmetic. Splunk_TA_windows extracts every `<Data>` field at
search time with

    [eventdata_xml_data]
    REGEX = <(?:\\w+)\\sName='([^>]*)'\\/?>([^<]*)(?:<\\/\\1>)?

and sixteen more transforms — process, new_process, parent_process,
process_id, the command line, SystemTime — are written against the same
single-quoted form. With double quotes none of them match: the event indexes,
`EventCode` and `Computer` still extract (their regexes accept either quote),
and every EventData field is silently missing, which empties the Endpoint
datamodel.

The generators keep their readable, indented templates; everything they build
passes through `render()` on the way out, so the format is decided in one place
and a new template cannot get it wrong.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

#: The fractional seconds of an ISO timestamp — the digits only, not an offset.
_FRACTION = re.compile(r'\.(\d+)')


def _local(tag):
    """(namespace, local name) of an ElementTree tag like '{ns}Event'."""
    if tag.startswith('{'):
        namespace, _, name = tag[1:].partition('}')
        return namespace, name
    return '', tag


def _text(value):
    return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _attribute(value):
    return _text(value).replace("'", '&apos;')


def system_time(value):
    """`SystemTime` as Windows writes it: UTC, seven fractional digits, `Z`.

    Accepts whatever a template produced — naive local time, an offset, or a
    value already in UTC — so no template has to know the rule.
    """
    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    # fromisoformat before Python 3.11 takes exactly three or six fractional
    # digits, and Windows writes seven.
    text = _FRACTION.sub(lambda m: '.' + m.group(1)[:6].ljust(6, '0'), text, count=1)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return value                                # not ours to reinterpret
    if moment.tzinfo is None:
        moment = moment.astimezone()                # naive means local time
    moment = moment.astimezone(timezone.utc)
    return moment.strftime('%Y-%m-%dT%H:%M:%S.') + f'{moment.microsecond:06d}0Z'


def _serialize(element, parent_namespace):
    namespace, name = _local(element.tag)
    attributes = []
    if namespace != parent_namespace:
        attributes.append(f"xmlns='{_attribute(namespace)}'")
    for key, value in element.attrib.items():
        if name == 'TimeCreated' and key == 'SystemTime':
            value = system_time(value)
        attributes.append(f"{_local(key)[1]}='{_attribute(value)}'")
    opening = name + (' ' + ' '.join(attributes) if attributes else '')

    children = list(element)
    if children:
        # Indentation between elements is template layout, not event content.
        inner = ''.join(_serialize(child, namespace) for child in children)
        return f'<{opening}>{inner}</{name}>'
    if element.text:
        return f'<{opening}>{_text(element.text)}</{name}>'
    return f'<{opening}/>'


def render(event_xml):
    """One Windows event, re-serialised in the form Windows renders."""
    return _serialize(ET.fromstring(event_xml), parent_namespace=None)
