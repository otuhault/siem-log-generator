"""
Environment Manager

Stores entities (network assets) and accounts (user identities) used to inject
realistic, consistent values into log generators at runtime.

Entities represent network machines/devices:
  - endpoint        → workstations, laptops (src_ip, src_nt_host, src_mac)
  - server          → internal servers (dest_ip, dest_host)
  - domain_controller → AD DCs (Computer FQDN, dest_ip)
  - firewall        → FTD/ASA/PaloAlto appliances (dvc)
  - router          → IOS/XR routers/switches (dvc)
  - external        → internet IPs (dest_ip in firewall logs)

Accounts represent user/service identities:
  - standard        → regular users (user field in most logs)
  - admin           → privileged accounts (user field)
  - service_account → automated/service accounts (user field in Windows/SSH/AD)
"""

import uuid
from collections import Counter
from pathlib import Path
from store import JsonStore


ENTITY_TYPES = ['endpoint', 'server', 'domain_controller', 'firewall', 'router', 'external']

ENTITY_TYPE_LABELS = {
    'endpoint':          'Endpoint / Workstation',
    'server':            'Server',
    'domain_controller': 'Domain Controller',
    'firewall':          'Firewall / NGFW',
    'router':            'Router / Switch',
    'external':          'External / Internet',
}

ACCOUNT_TYPES = ['standard', 'admin', 'service_account']

ACCOUNT_TYPE_LABELS = {
    'standard':       'Standard User',
    'admin':          'Administrator / Privileged',
    'service_account':'Service Account',
}


# ── Central injection mapping ──────────────────────────────────────────────────
#
# ENTITY_TYPE_ROLES[(entity_type)][log_type] = list of (pool_name, entity_field, cim_field)
#   pool_name    : generator instance attribute to override
#   entity_field : field to read from the entity ('ip', 'nt_host', 'mac', 'fqdn')
#   cim_field    : Splunk CIM field name (for UI display only)
#
# A None entity_field means the pool is fed by ACCOUNT_TYPE_ROLES (accounts).

ENTITY_TYPE_ROLES = {
    'endpoint': {
        'windows':          [('ip_addresses',      'ip',      'src_ip'),
                             ('workstations',      'nt_host', 'src_nt_host')],
        'ssh':              [('ip_addresses',       'ip',      'src_ip'),
                             ('hostnames',          'nt_host', 'dest_host')],
        'apache':           [('ip_addresses',       'ip',      'src_ip')],
        'paloalto':         [('internal_ips',       'ip',      'src_ip')],
        'cisco_ftd':        [('internal_ips',       'ip',      'src_ip')],
        'cisco_asa':        [('internal_ips',       'ip',      'src_ip')],
        'cisco_ios':        [('internal_ips',       'ip',      'src_ip'),
                             ('mac_addresses',      'mac',     'src_mac')],
        'active_directory': [('computer_accounts',  'nt_host', 'src_nt_host')],
        'zscaler':          [('_INTERNAL_IPS',      'ip',      'src_ip'),
                             ('_device_names',      'nt_host', 'src_nt_host'),
                             ('_device_os_types',   'os',      'deviceostype')],
    },
    'server': {
        'ssh':              [('ip_addresses',       'ip',      'src_ip'),
                             ('hostnames',          'nt_host', 'dest_host')],
        'paloalto':         [('internal_ips',       'ip',      'dest_ip')],
        'cisco_ftd':        [('internal_ips',       'ip',      'dest_ip')],
        'cisco_asa':        [('internal_ips',       'ip',      'dest_ip')],
    },
    'domain_controller': {
        'active_directory': [('domain_controllers', 'fqdn',    'Computer')],
        'windows':          [('ip_addresses',       'ip',      'dest_ip')],
    },
    'firewall': {
        'paloalto':         [('hostnames',          'nt_host', 'dvc')],
        'cisco_ftd':        [('devices',            'nt_host', 'dvc')],
        'cisco_asa':        [('devices',            'nt_host', 'dvc')],
    },
    'router': {
        'cisco_ios':        [('hostnames',          'nt_host', 'dvc')],
        'cisco_xr':         [('devices',            'nt_host', 'dvc')],
    },
    'external': {
        'paloalto':         [('external_ips',       'ip',      'dest_ip')],
        'cisco_ftd':        [('external_ips',       'ip',      'dest_ip')],
        'cisco_asa':        [('external_ips',       'ip',      'dest_ip')],
    },
}

# ACCOUNT_TYPE_ROLES[account_type][log_type] = pool_name on the generator
ACCOUNT_TYPE_ROLES = {
    'standard': {
        'windows':          'usernames',
        'ssh':              'valid_users',
        'paloalto':         'usernames',
        'cisco_ftd':        'users',
        'cisco_asa':        'users',
        'active_directory': 'target_users',
        'zscaler':          '_USERS',
    },
    'admin': {
        'windows':          'usernames',
        'ssh':              'valid_users',
        'paloalto':         'usernames',
        'cisco_ftd':        'users',
        'cisco_asa':        'users',
        'cisco_ios':        'admin_users',
        'active_directory': 'target_users',
    },
    'service_account': {
        'windows':          'usernames',
        'ssh':              'valid_users',
        'active_directory': 'target_users',
    },
}

# Lookup: old category name → new entity type (migration from assets_identities.json)
_OLD_CATEGORY_TO_ENTITY_TYPE = {
    'windows':          'endpoint',
    'ssh':              'endpoint',
    'apache':           'endpoint',
    'paloalto':         'firewall',
    'cisco_ftd':        'firewall',
    'cisco_asa':        'firewall',
    'cisco_ios':        'router',
    'cisco_xr':         'router',
    'active_directory': 'domain_controller',
    'zscaler':          'endpoint',
    'external':         'external',
}

_OLD_IDENTITY_CATEGORY_TO_ACCOUNT_TYPE = {
    'standard':       'standard',
    'privileged':     'admin',
    'service_account':'service_account',
    'contractor':     'standard',
}


class EnvironmentManager(JsonStore):
    """
    Manages Entities and Accounts for injection into log generators.

    Storage format (environment.json):
      {
        "entities": { "<uuid>": { "id", "name", "type", "ip", "nt_host", "mac", "fqdn", "os" } },
        "accounts": { "<uuid>": { "id", "username", "email", "type", "linked_entity" } }
      }
    """

    def __init__(self, config_file='environment.json'):
        super().__init__(config_file)
        if 'entities' not in self._data:
            self._data['entities'] = {}
        if 'accounts' not in self._data:
            self._data['accounts'] = {}
        # Migrate from old assets_identities.json if new file is empty
        if not self._data['entities'] and not self._data['accounts']:
            self._migrate_from_old_format()

    # ------------------------------------------------------------------
    # Migration
    # ------------------------------------------------------------------

    def _migrate_from_old_format(self):
        old_path = Path('assets_identities.json')
        if not old_path.exists():
            return
        import json as _json
        try:
            with old_path.open() as f:
                old = _json.load(f)
        except Exception:
            return

        for asset in old.get('assets', {}).values():
            cats = asset.get('category', [])
            entity_type = 'endpoint'
            for c in cats:
                if c in _OLD_CATEGORY_TO_ENTITY_TYPE:
                    entity_type = _OLD_CATEGORY_TO_ENTITY_TYPE[c]
                    break
            entity_id = asset.get('id') or str(uuid.uuid4())
            self._data['entities'][entity_id] = {
                'id':      entity_id,
                'name':    asset.get('nt_host') or asset.get('ip', ''),
                'type':    entity_type,
                'ip':      asset.get('ip', ''),
                'nt_host': asset.get('nt_host', ''),
                'mac':     asset.get('mac', ''),
                'fqdn':    asset.get('dns', ''),
                'os':      asset.get('os', ''),
            }

        for ident in old.get('identities', {}).values():
            cats = ident.get('category', [])
            account_type = 'standard'
            for c in cats:
                if c in _OLD_IDENTITY_CATEGORY_TO_ACCOUNT_TYPE:
                    account_type = _OLD_IDENTITY_CATEGORY_TO_ACCOUNT_TYPE[c]
                    break
            account_id = ident.get('id') or str(uuid.uuid4())
            self._data['accounts'][account_id] = {
                'id':            account_id,
                'username':      ident.get('identity', ''),
                'email':         ident.get('email', ''),
                'type':          account_type,
                'linked_entity': None,
            }

        if self._data['entities'] or self._data['accounts']:
            self._save()

    # ------------------------------------------------------------------
    # Entities CRUD
    # ------------------------------------------------------------------

    def get_all_entities(self):
        return list(self._data['entities'].values())

    def get_entity(self, entity_id):
        return self._data['entities'].get(entity_id)

    def create_entity(self, name, entity_type, ip='', nt_host='', mac='', fqdn='', os=''):
        if not name:
            raise ValueError("name is required")
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"Invalid entity type: {entity_type}")
        entity_id = str(uuid.uuid4())
        self._data['entities'][entity_id] = {
            'id':      entity_id,
            'name':    name.strip(),
            'type':    entity_type,
            'ip':      ip.strip() if ip else '',
            'nt_host': nt_host.strip() if nt_host else '',
            'mac':     mac.strip() if mac else '',
            'fqdn':    fqdn.strip() if fqdn else '',
            'os':      os.strip() if os else '',
        }
        self._save()
        return entity_id

    def update_entity(self, entity_id, data):
        if entity_id not in self._data['entities']:
            raise ValueError(f"Entity {entity_id} not found")
        entity = self._data['entities'][entity_id]
        for field in ('name', 'ip', 'nt_host', 'mac', 'fqdn', 'os'):
            if field in data:
                entity[field] = data[field].strip() if isinstance(data[field], str) else data[field]
        if 'type' in data:
            if data['type'] not in ENTITY_TYPES:
                raise ValueError(f"Invalid entity type: {data['type']}")
            entity['type'] = data['type']
        self._save()

    def delete_entity(self, entity_id):
        if entity_id not in self._data['entities']:
            raise ValueError(f"Entity {entity_id} not found")
        del self._data['entities'][entity_id]
        # Unlink any accounts pointing to this entity
        for acc in self._data['accounts'].values():
            if acc.get('linked_entity') == entity_id:
                acc['linked_entity'] = None
        self._save()

    # ------------------------------------------------------------------
    # Accounts CRUD
    # ------------------------------------------------------------------

    def get_all_accounts(self):
        return list(self._data['accounts'].values())

    def get_account(self, account_id):
        return self._data['accounts'].get(account_id)

    def create_account(self, username, email='', account_type='standard', linked_entity=None):
        if not username:
            raise ValueError("username is required")
        if account_type not in ACCOUNT_TYPES:
            raise ValueError(f"Invalid account type: {account_type}")
        account_id = str(uuid.uuid4())
        self._data['accounts'][account_id] = {
            'id':            account_id,
            'username':      username.strip(),
            'email':         email.strip() if email else '',
            'type':          account_type,
            'linked_entity': linked_entity,
        }
        self._save()
        return account_id

    def update_account(self, account_id, data):
        if account_id not in self._data['accounts']:
            raise ValueError(f"Account {account_id} not found")
        acc = self._data['accounts'][account_id]
        for field in ('username', 'email'):
            if field in data:
                acc[field] = data[field].strip() if isinstance(data[field], str) else data[field]
        if 'type' in data:
            if data['type'] not in ACCOUNT_TYPES:
                raise ValueError(f"Invalid account type: {data['type']}")
            acc['type'] = data['type']
        if 'linked_entity' in data:
            acc['linked_entity'] = data['linked_entity'] or None
        self._save()

    def delete_account(self, account_id):
        if account_id not in self._data['accounts']:
            raise ValueError(f"Account {account_id} not found")
        del self._data['accounts'][account_id]
        self._save()

    # ------------------------------------------------------------------
    # Injection
    # ------------------------------------------------------------------

    def inject_into(self, generator_instance, log_type: str, ratio: int = 100):
        """
        Override pool attributes on a generator instance using ENTITY_TYPE_ROLES
        and ACCOUNT_TYPE_ROLES.

        ratio : 0-100 — percentage of environment values vs hardcoded defaults.
        """
        import random as _random

        # Build pool_name → list of values from entities
        pool_values: dict[str, list] = {}

        for entity_type, log_map in ENTITY_TYPE_ROLES.items():
            roles = log_map.get(log_type, [])
            for pool_name, entity_field, _ in roles:
                for entity in self._data['entities'].values():
                    if entity.get('type') != entity_type:
                        continue
                    value = entity.get(entity_field, '')
                    if value:
                        pool_values.setdefault(pool_name, []).append(value)

        # Build pool_name → list of values from accounts
        for account_type, log_map in ACCOUNT_TYPE_ROLES.items():
            pool_name = log_map.get(log_type)
            if not pool_name:
                continue
            for acc in self._data['accounts'].values():
                if acc.get('type') != account_type:
                    continue
                # Zscaler uses email as user identifier
                field = 'email' if log_type == 'zscaler' else 'username'
                value = acc.get(field, '')
                if value:
                    pool_values.setdefault(pool_name, []).append(value)

        # Apply to generator with ratio mixing
        for pool_name, ai_values in pool_values.items():
            if not ai_values:
                continue

            if ratio >= 100:
                setattr(generator_instance, pool_name, ai_values)
                continue

            if ratio <= 0:
                continue

            defaults = list(getattr(generator_instance, pool_name, []))
            if not defaults:
                setattr(generator_instance, pool_name, ai_values)
                continue

            ai_part      = [ai_values[i % len(ai_values)]  for i in range(ratio)]
            default_part = [defaults[i % len(defaults)]     for i in range(100 - ratio)]
            mixed        = ai_part + default_part
            _random.shuffle(mixed)
            setattr(generator_instance, pool_name, mixed)

    def get_impact(self, log_type: str) -> list:
        """
        Return a list of {pool, cim_field, count, available} rows for a given log_type.
        Used by the /api/environment/impact/<log_type> route.
        """
        seen: dict[str, dict] = {}  # pool_name → row

        for entity_type, log_map in ENTITY_TYPE_ROLES.items():
            for pool_name, entity_field, cim_field in log_map.get(log_type, []):
                if pool_name not in seen:
                    seen[pool_name] = {'pool': pool_name, 'cim_field': cim_field, 'count': 0}
                for entity in self._data['entities'].values():
                    if entity.get('type') == entity_type and entity.get(entity_field, ''):
                        seen[pool_name]['count'] += 1

        for account_type, log_map in ACCOUNT_TYPE_ROLES.items():
            pool_name = log_map.get(log_type)
            if not pool_name:
                continue
            if pool_name not in seen:
                seen[pool_name] = {'pool': pool_name, 'cim_field': 'user', 'count': 0}
            field = 'email' if log_type == 'zscaler' else 'username'
            for acc in self._data['accounts'].values():
                if acc.get('type') == account_type and acc.get(field, ''):
                    seen[pool_name]['count'] += 1

        rows = list(seen.values())
        for row in rows:
            row['available'] = row['count'] > 0
        return rows

    def get_counts_by_log_type(self, log_types: list) -> dict:
        """
        For each log_type in the provided list, return the count of distinct
        entities and accounts that would contribute to injection.

        Only log types that have at least one mapping defined are included
        in the result (log types with no mapping are omitted).

        Returns: { log_type: {'entities': N, 'accounts': N}, ... }
        """
        result = {}
        for log_type in log_types:
            entity_ids  = set()
            account_ids = set()
            has_mapping = False

            for entity_type, log_map in ENTITY_TYPE_ROLES.items():
                roles = log_map.get(log_type, [])
                if roles:
                    has_mapping = True
                for pool_name, entity_field, _ in roles:
                    for entity in self._data['entities'].values():
                        if entity.get('type') == entity_type and entity.get(entity_field, ''):
                            entity_ids.add(entity['id'])

            for account_type, log_map in ACCOUNT_TYPE_ROLES.items():
                pool_name = log_map.get(log_type)
                if pool_name:
                    has_mapping = True
                    field = 'email' if log_type == 'zscaler' else 'username'
                    for acc in self._data['accounts'].values():
                        if acc.get('type') == account_type and acc.get(field, ''):
                            account_ids.add(acc['id'])

            if has_mapping:
                result[log_type] = {
                    'entities': len(entity_ids),
                    'accounts': len(account_ids),
                }
        return result

    # ------------------------------------------------------------------
    # Stats / helpers
    # ------------------------------------------------------------------

    def has_data(self):
        return bool(self._data['entities'] or self._data['accounts'])

    def get_stats(self):
        entity_types = Counter(e.get('type') for e in self._data['entities'].values())
        account_types = Counter(a.get('type') for a in self._data['accounts'].values())
        return {
            'total_entities':  len(self._data['entities']),
            'total_accounts':  len(self._data['accounts']),
            'entity_types':    dict(entity_types),
            'account_types':   dict(account_types),
        }
