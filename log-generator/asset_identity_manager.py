"""
Asset & Identity Manager

Stores and retrieves assets (network entities) and identities (user accounts).
Used to inject realistic, consistent data pools into log generators at runtime,
replacing hardcoded defaults when a sender has 'use_assets_identities' enabled.

Data model inspired by Splunk Enterprise Security asset/identity lookups:
  - Assets   → ip, nt_host, dns, mac, category, os, bunit, owner, priority
  - Identities → identity, email, first, last, bunit, category, priority, watchlist
"""

import uuid
from collections import Counter
from datetime import datetime
from store import JsonStore


ASSET_CATEGORIES = [
    'windows',
    'ssh',
    'apache',
    'paloalto',
    'cisco_ftd',
    'cisco_asa',
    'cisco_ios',
    'cisco_xr',
    'active_directory',
    'zscaler',
    'external',
]

ASSET_CATEGORY_LABELS = {
    'windows':          'Windows Events (Security / Application)',
    'ssh':              'Linux / SSH',
    'apache':           'Apache / Web Server',
    'paloalto':         'Palo Alto Networks',
    'cisco_ftd':        'Cisco Firepower (FTD)',
    'cisco_asa':        'Cisco ASA',
    'cisco_ios':        'Cisco IOS',
    'cisco_xr':         'Cisco IOS XR',
    'active_directory': 'Active Directory',
    'zscaler':          'Zscaler',
    'external':         'External / Internet IP',
}

IDENTITY_CATEGORIES = [
    'standard', 'privileged', 'service_account', 'contractor',
]

IDENTITY_CATEGORY_LABELS = {
    'standard':        'Standard User',
    'privileged':      'Privileged / Admin',
    'service_account': 'Service Account',
    'contractor':      'Contractor',
}

PRIORITIES = ['unknown', 'low', 'medium', 'high', 'critical']


class AssetIdentityManager(JsonStore):
    """
    Manages Assets and Identities for injection into log generators.

    Storage format (assets_identities.json):
      {
        "assets":     { "<uuid>": { ... } },
        "identities": { "<uuid>": { ... } }
      }
    """

    def __init__(self, config_file='assets_identities.json'):
        super().__init__(config_file)
        if 'assets' not in self._data:
            self._data['assets'] = {}
        if 'identities' not in self._data:
            self._data['identities'] = {}

    # ------------------------------------------------------------------
    # Assets CRUD
    # ------------------------------------------------------------------

    def get_all_assets(self):
        return list(self._data['assets'].values())

    def get_asset(self, asset_id):
        return self._data['assets'].get(asset_id)

    def create_asset(self, ip, nt_host=None, dns=None, mac=None,
                     category=None, os=None, bunit=None, owner=None, priority='unknown'):
        if not ip:
            raise ValueError("ip is required")
        asset_id = str(uuid.uuid4())
        self._data['assets'][asset_id] = {
            'id':         asset_id,
            'ip':         ip.strip(),
            'nt_host':    (nt_host or '').strip(),
            'dns':        (dns or '').strip(),
            'mac':        (mac or '').strip(),
            'category':   category if isinstance(category, list) else [],
            'os':         (os or '').strip(),
            'bunit':      (bunit or '').strip(),
            'owner':      (owner or '').strip(),
            'priority':   priority if priority in PRIORITIES else 'unknown',
            'created_at': datetime.now().isoformat(),
        }
        self._save()
        return asset_id

    def update_asset(self, asset_id, data):
        if asset_id not in self._data['assets']:
            raise ValueError(f"Asset {asset_id} not found")
        asset = self._data['assets'][asset_id]
        for field in ('ip', 'nt_host', 'dns', 'mac', 'os', 'bunit', 'owner'):
            if field in data:
                asset[field] = data[field].strip() if isinstance(data[field], str) else data[field]
        if 'category' in data:
            asset['category'] = data['category'] if isinstance(data['category'], list) else []
        if 'priority' in data and data['priority'] in PRIORITIES:
            asset['priority'] = data['priority']
        self._save()

    def delete_asset(self, asset_id):
        if asset_id not in self._data['assets']:
            raise ValueError(f"Asset {asset_id} not found")
        del self._data['assets'][asset_id]
        self._save()

    # ------------------------------------------------------------------
    # Identities CRUD
    # ------------------------------------------------------------------

    def get_all_identities(self):
        return list(self._data['identities'].values())

    def get_identity(self, identity_id):
        return self._data['identities'].get(identity_id)

    def create_identity(self, identity, email=None, first=None, last=None,
                        bunit=None, category=None, priority='unknown', watchlist=False):
        if not identity:
            raise ValueError("identity (username) is required")
        identity_id = str(uuid.uuid4())
        self._data['identities'][identity_id] = {
            'id':         identity_id,
            'identity':   identity.strip(),
            'email':      (email or '').strip(),
            'first':      (first or '').strip(),
            'last':       (last or '').strip(),
            'bunit':      (bunit or '').strip(),
            'category':   category if isinstance(category, list) else [],
            'priority':   priority if priority in PRIORITIES else 'unknown',
            'watchlist':  bool(watchlist),
            'created_at': datetime.now().isoformat(),
        }
        self._save()
        return identity_id

    def update_identity(self, identity_id, data):
        if identity_id not in self._data['identities']:
            raise ValueError(f"Identity {identity_id} not found")
        ident = self._data['identities'][identity_id]
        for field in ('identity', 'email', 'first', 'last', 'bunit'):
            if field in data:
                ident[field] = data[field].strip() if isinstance(data[field], str) else data[field]
        if 'category' in data:
            ident['category'] = data['category'] if isinstance(data['category'], list) else []
        if 'priority' in data and data['priority'] in PRIORITIES:
            ident['priority'] = data['priority']
        if 'watchlist' in data:
            ident['watchlist'] = bool(data['watchlist'])
        self._save()

    def delete_identity(self, identity_id):
        if identity_id not in self._data['identities']:
            raise ValueError(f"Identity {identity_id} not found")
        del self._data['identities'][identity_id]
        self._save()

    # ------------------------------------------------------------------
    # Pool extraction — used by inject_into()
    # ------------------------------------------------------------------

    def get_pool(self, pool_type: str, field: str, categories: list = None) -> list:
        """
        Return a list of non-empty field values from assets or identities.

        pool_type : 'asset' or 'identity'
        field     : field name to extract ('ip', 'nt_host', 'identity', 'email', …)
        categories: optional whitelist of categories (OR logic); None = all records

        Returns [] if nothing matches — callers fall back to hardcoded defaults.
        """
        if pool_type == 'asset':
            records = self._data['assets'].values()
        elif pool_type == 'identity':
            records = self._data['identities'].values()
        else:
            return []

        results = []
        for record in records:
            if categories:
                rec_cats = record.get('category', [])
                if not any(c in rec_cats for c in categories):
                    continue
            value = record.get(field, '')
            if value:
                results.append(value)
        return results

    def inject_into(self, generator_instance, generator_class, ratio: int = 100):
        """
        Override pool attributes on a generator instance from ASSET_IDENTITY_MAPPING.

        ratio : 0-100 — percentage of A&I values vs hardcoded defaults.
                100 = full A&I, 0 = full defaults (no-op), 70 = 70% A&I.

        The mixed pool is built by repeating A&I values `ratio` times and
        default values `(100-ratio)` times, then shuffled. random.choice()
        in generators will naturally honour the distribution.
        """
        import random as _random
        mapping = getattr(generator_class, 'ASSET_IDENTITY_MAPPING', {})
        for pool_name, spec in mapping.items():
            ai_values = self.get_pool(
                pool_type=spec['type'],
                field=spec['field'],
                categories=spec.get('categories'),
            )
            if not ai_values:
                continue  # nothing in store for this pool → keep defaults

            if ratio >= 100:
                setattr(generator_instance, pool_name, ai_values)
                continue

            if ratio <= 0:
                continue  # keep defaults untouched

            # Build weighted pool
            defaults = list(getattr(generator_instance, pool_name, []))
            if not defaults:
                setattr(generator_instance, pool_name, ai_values)
                continue

            ai_part      = (ai_values  * ratio)[:ratio]
            default_part = (defaults   * (100 - ratio))[:(100 - ratio)]
            mixed        = ai_part + default_part
            _random.shuffle(mixed)
            setattr(generator_instance, pool_name, mixed)

    def has_data(self):
        """Return True if at least one asset or identity is configured."""
        return bool(self._data['assets'] or self._data['identities'])

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self):
        asset_cats = Counter()
        for a in self._data['assets'].values():
            for c in a.get('category', []):
                asset_cats[c] += 1
        identity_cats = Counter()
        for i in self._data['identities'].values():
            for c in i.get('category', []):
                identity_cats[c] += 1
        return {
            'total_assets':          len(self._data['assets']),
            'total_identities':      len(self._data['identities']),
            'asset_categories':      dict(asset_cats),
            'identity_categories':   dict(identity_cats),
        }
