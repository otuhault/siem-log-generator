"""What the generator can produce, assembled for the Catalog tab.

Nothing here is new information. Every value is read from the three registries
that already own it — the generators' METADATA, ta_registry.py and
ATTACK_REGISTRY — so the catalog cannot drift from what a sender actually emits.
The join lives on the server rather than in the page so that it is tested with
the rest of the registry, and so the page stays a renderer.
"""

from attack_generators import ATTACK_REGISTRY
from log_generators import REGISTRY
from ta_registry import get_ta


def _sc4s(ta):
    """The SC4S source page for this technology, when syslog can carry it.

    Only for a source SC4S has a parser for that assigns the sourcetype this
    generator targets. A device whose events syslog can carry but SC4S would
    file as something else — a *nix daemon landing under `nix:syslog` rather
    than the add-on's own sourcetype — is not compatible in any useful sense,
    and says nothing rather than implying it works.
    """
    if ta.get('syslog_viable') is False:
        return None
    return ta.get('sc4s_url') or None


def _wire_sourcetype(ta, sourcetype):
    """The sourcetype put on the wire over HEC, when it differs from the final one."""
    by_format = ta.get('hec_default_sourcetype_by_render_format')
    if by_format:
        return ' / '.join(sorted(set(by_format.values())))
    return ta.get('hec_default_sourcetype') or sourcetype['name']


def _attack_sources(attack):
    """The data sources an attack is sent as: each declared one, else its log type."""
    declared = [s['log_type'] for s in attack.get('data_sources') or []]
    return list(dict.fromkeys(declared)) or [attack.get('log_type')]


def _mapping(sourcetype):
    """How this sourcetype reaches CIM, as the registry records it.

    The Catalog's Sourcetypes view and the old Configuration → Sourcetype
    Mapping view were two renderings of the same registry, so they are one view
    now, and it needs the deep half here rather than in a second round of
    per-TA requests from the page.
    """
    return {
        'eventtypes': list(sourcetype.get('eventtypes', [])),
        'tags': list(sourcetype.get('tags', [])),
        'datamodel_conditions': [
            {
                'when': c.get('when', ''),
                'eventtype': c.get('eventtype', ''),
                'tags': list(c.get('tags', [])),
                'datamodels': list(c.get('datamodels', [])),
            }
            for c in sourcetype.get('datamodel_conditions', [])
        ],
        'fields': [
            {
                'raw_field': f.get('raw_field', ''),
                'cim_field': f.get('cim_field', ''),
                'datamodels': list(f.get('datamodels', [])),
                # Passed through, never substituted: a field that declared no
                # origin must read as the registry gap it is, not as "random".
                'ai_source': f.get('ai_source'),
                'csv_position': f.get('csv_position'),
                'extracted_from': f.get('extracted_from', ''),
                'description': f.get('description', ''),
            }
            for f in sourcetype.get('fields', [])
        ],
        'entity_types': list(sourcetype.get('entity_types', [])),
        'account_types': list(sourcetype.get('account_types', [])),
    }


def _datamodels(sources, attacks):
    """Each CIM datamodel, and what actually reaches it.

    Built by inverting the sources rather than from a list of its own: a
    datamodel appears here only because some sourcetype's add-on grants it, so
    the view cannot claim one nothing populates.
    """
    found = {}
    for source in sources:
        for sourcetype in source['sourcetypes']:
            for name in sourcetype['datamodels']:
                entry = found.setdefault(name, {'name': name, 'sourcetypes': [], 'attacks': []})
                entry['sourcetypes'].append({
                    'name': sourcetype['name'],
                    'source': source['name'],
                    'source_key': source['key'],
                })
    for attack in attacks:
        entry = found.get(attack['datamodel'])
        if entry:
            entry['attacks'].append(attack['name'])

    for entry in found.values():
        entry['sourcetypes'].sort(key=lambda s: (s['source'].lower(), s['name']))
        entry['sources'] = sorted({s['source'] for s in entry['sourcetypes']})
        entry['attacks'].sort()
    return sorted(found.values(), key=lambda d: d['name'])


def build_catalog():
    """Data sources, the datamodels they reach, and the attacks that use them."""
    attacks_by_source = {}
    for key, attack in ATTACK_REGISTRY.items():
        for log_type in _attack_sources(attack):
            attacks_by_source.setdefault(log_type, []).append(key)

    sources = []
    for log_type, generator in REGISTRY.items():
        ta = get_ta(log_type) or {}
        metadata = generator.METADATA
        sourcetypes = [
            {
                'name': st['name'],
                'wire': _wire_sourcetype(ta, st),
                'description': st.get('description', ''),
                'datamodels': list(st.get('datamodels', [])),
                **_mapping(st),
            }
            for st in ta.get('sourcetypes', [])
        ]
        sources.append({
            'key': log_type,
            'name': ta.get('display_name') or metadata.get('name', log_type),
            'vendor': ta.get('vendor', ''),
            'add_on': ta.get('name', ''),
            'add_on_url': ta.get('splunkbase_url', ''),
            # The version the source was modelled against, not one read at run
            # time: the add-ons are not shipped with this application.
            'add_on_version': ta.get('add_on_version', ''),
            'description': ta.get('description') or metadata.get('description', ''),
            'sourcetypes': sourcetypes,
            'datamodels': sorted({dm for st in sourcetypes for dm in st['datamodels']}),
            'categories': [
                {'id': c['id'], 'name': c['name'], 'description': c.get('description', '')}
                for c in metadata.get('sources', [])
            ],
            'sc4s_url': _sc4s(ta),
            'attacks': sorted(attacks_by_source.get(log_type, [])),
        })

    source_names = {s['key']: s['name'] for s in sources}
    attacks = [
        {
            'key': key,
            'name': attack.get('name', key),
            'description': attack.get('description', ''),
            'category': attack.get('category', ''),
            'source': attack.get('log_type'),
            'source_name': ' · '.join(source_names.get(t, t) for t in _attack_sources(attack)),
            'datamodel': attack.get('datamodel', ''),
            'research_url': attack.get('splunk_research_url', ''),
            'sample': (attack.get('sample_logs') or [None])[0],
        }
        for key, attack in ATTACK_REGISTRY.items()
    ]

    sources.sort(key=lambda s: s['name'].lower())
    attacks.sort(key=lambda a: (a['category'].lower(), a['name'].lower()))
    return {'sources': sources, 'attacks': attacks,
            'datamodels': _datamodels(sources, attacks)}
