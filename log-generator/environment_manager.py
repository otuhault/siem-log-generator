"""
Environment Manager (V2 - A&I Explicit)

Stores entities (network assets) and accounts (user identities) used to inject
realistic, consistent values into log generators at runtime.

V2 changes: Integrates with TA Registry, A&I Mapping, and Network Pools for
Splunk-centric, explicit field-level injection.

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
from ta_registry import get_ta, get_sourcetype_info, TA_REGISTRY
from a_i_mapping import AIMappingManager


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
        'auditd':           [('ip_addresses',       'ip',      'src'),
                             ('hostnames',          'nt_host', 'dest')],
        'apache':           [('ip_addresses',       'ip',      'src_ip')],
        'paloalto':         [('internal_ips',       'ip',      'src_ip')],
        'cisco_asa':        [('internal_ips',       'ip',      'src_ip')],
        'cisco_ios':        [('internal_ips',       'ip',      'src_ip'),
                             ('mac_addresses',      'mac',     'src_mac')],
        'active_directory': [('computer_accounts',  'nt_host', 'src_nt_host')],
        'fortigate':        [('internal_ips',       'ip',      'src_ip')],
        'zscaler':          [('_INTERNAL_IPS',      'ip',      'src_ip'),
                             ('_device_names',      'nt_host', 'src_nt_host'),
                             ('_device_os_types',   'os',      'deviceostype')],
    },
    'server': {
        # Apache logs name the client only; the server is what `host` and the
        # syslog header identify, so it is the dest end of the request.
        'apache':           [('hostnames',          'nt_host', 'dest')],
        'ssh':              [('ip_addresses',       'ip',      'src_ip'),
                             ('hostnames',          'nt_host', 'dest_host')],
        'auditd':           [('ip_addresses',       'ip',      'src'),
                             ('hostnames',          'nt_host', 'dest')],
        'paloalto':         [('internal_ips',       'ip',      'dest_ip')],
        'cisco_asa':        [('internal_ips',       'ip',      'dest_ip')],
        'fortigate':        [('internal_ips',       'ip',      'dest_ip')],
    },
    'domain_controller': {
        'active_directory': [('domain_controllers', 'fqdn',    'Computer')],
        'windows':          [('ip_addresses',       'ip',      'dest_ip')],
    },
    'firewall': {
        'paloalto':         [('hostnames',          'nt_host', 'dvc')],
        'cisco_asa':        [('devices',            'nt_host', 'dvc')],
        'fortigate':        [('hostnames',          'nt_host', 'dvc')],
    },
    'router': {
        'cisco_ios':        [('hostnames',          'nt_host', 'dvc')],
    },
    'external': {
        'paloalto':         [('external_ips',       'ip',      'dest_ip')],
        'cisco_asa':        [('external_ips',       'ip',      'dest_ip')],
        # Also the src end of an inbound IPS detection or a DoS flood — the pool
        # is read on both sides, so fortigate.py passes `side=` explicitly.
        'fortigate':        [('external_ips',       'ip',      'dest_ip')],
    },
}

#: CIM fields whose name does not betray the side they describe.
#: `deviceostype` is Zscaler's OS of the *client* device, not of the appliance —
#: reading the prefix would put it with the collector and split it from the
#: device name and address it belongs with.
ROLE_SIDE_OVERRIDES = {
    'deviceostype': 'src',
}


def role_side(cim_field: str) -> str:
    """Which end of the event a role describes, read off its CIM field.

    An event usually involves two machines — a client and a server, an attacker
    and a target — plus, sometimes, the appliance that logged it. Grouping the
    roles this way is what lets one event carry two coherent entities instead of
    one, or two halves of two different ones.
    """
    if cim_field in ROLE_SIDE_OVERRIDES:
        return ROLE_SIDE_OVERRIDES[cim_field]
    if cim_field.startswith('src'):
        return 'src'
    if cim_field.startswith('dest'):
        return 'dest'
    return 'device'


SIDES = ('src', 'dest', 'device')


# DOMAIN_ROLES[log_type] = (nt_domain_pool, dns_domain_pool or None)
#
# The environment's AD domain is not mixed by ratio like the other pools: a lab
# has one domain, and drawing it per event is what made the same account appear
# under five domains at once, splitting it into five CIM identities.
DOMAIN_ROLES = {
    'windows':          ('domains', None),
    'active_directory': ('domains', 'domain_dns'),
}

# ACCOUNT_TYPE_ROLES[account_type][log_type] = pool_name on the generator
ACCOUNT_TYPE_ROLES = {
    'standard': {
        'windows':          'usernames',
        'auditd':           'acct_users',
        'ssh':              'valid_users',
        'paloalto':         'usernames',
        'cisco_asa':        'users',
        'fortigate':        'users',
        'active_directory': 'target_users',
        'zscaler':          '_USERS',
    },
    'admin': {
        'windows':          'usernames',
        'auditd':           'acct_users',
        'ssh':              'valid_users',
        'paloalto':         'usernames',
        'cisco_asa':        'users',
        'cisco_ios':        'admin_users',
        'fortigate':        'admin_users',
        'active_directory': 'target_users',
    },
    'service_account': {
        'windows':          'usernames',
        'auditd':           'acct_users',
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
    'cisco_asa':        'firewall',
    'fortigate':        'firewall',
    'cisco_ios':        'router',
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
        "accounts": { "<uuid>": { "id", "username", "email", "type", "linked_entity" } },
        "settings": { "ad_domain", "ad_domain_dns" }
      }

    `settings` holds environment-wide facts that belong to no single entity or
    account. The AD domain is the first: it is not a per-entity attribute (a lab
    has one domain, not one per machine) and it is not a common field either —
    only the Windows and Active Directory generators have any notion of it — so
    it would not earn a column in the entity/account schema.
    """

    def __init__(self, config_file='environment.json'):
        super().__init__(config_file)
        if 'entities' not in self._data:
            self._data['entities'] = {}
        if 'accounts' not in self._data:
            self._data['accounts'] = {}
        if 'settings' not in self._data:
            self._data['settings'] = {}
        # Migrate from old assets_identities.json if new file is empty
        if not self._data['entities'] and not self._data['accounts']:
            self._migrate_from_old_format()
        # Initialize A&I mapping manager for TA-aware workflows
        self._ai_manager = AIMappingManager()

    # ------------------------------------------------------------------
    # Environment-wide settings
    # ------------------------------------------------------------------

    #: Used when the environment declares no domain, so behaviour is unchanged
    #: for anyone who never opens the setting.
    DEFAULT_SETTINGS = {
        'ad_domain':     '',
        'ad_domain_dns': '',
    }

    def get_settings(self) -> dict:
        """Environment-wide settings, with defaults filled in."""
        return {**self.DEFAULT_SETTINGS, **self._data.get('settings', {})}

    def update_settings(self, data: dict) -> dict:
        """Merge `data` into the settings. Unknown keys are ignored."""
        settings = self.get_settings()
        for key in self.DEFAULT_SETTINGS:
            if key in data:
                settings[key] = (data[key] or '').strip()
        self._data['settings'] = settings
        self._save()
        return settings

    # ------------------------------------------------------------------
    # Migration
    # ------------------------------------------------------------------

    def _migrate_from_old_format(self):
        from store import store_path
        old_path = store_path('assets_identities.json')
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

        # Build pool_name → list of values from accounts.
        # Accounts pinned to an entity are deliberately left out: they reach the
        # generator through their entity's roster record instead, so they can
        # never be drawn for somebody else's machine.
        pinned = {a['id'] for accounts in self._linked_accounts(log_type).values()
                  for a in accounts}
        for account_type, log_map in ACCOUNT_TYPE_ROLES.items():
            pool_name = log_map.get(log_type)
            if not pool_name:
                continue
            for acc in self._data['accounts'].values():
                if acc.get('type') != account_type or acc.get('id') in pinned:
                    continue
                value = acc.get(self._account_field(log_type), '')
                if value:
                    pool_values.setdefault(pool_name, []).append(value)

        # The AD domain is environment-wide, so it replaces the pool outright
        # rather than being blended in.
        self._apply_domain(generator_instance, log_type)

        # Per-entity records, so a generator can keep one machine's fields
        # together instead of drawing each of them from its own flat pool.
        self._apply_entity_roster(generator_instance, log_type, ratio)

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

    def _account_field(self, log_type: str) -> str:
        """Which account attribute identifies a user for this log type."""
        return 'email' if log_type == 'zscaler' else 'username'

    def _account_pools(self, log_type: str) -> dict:
        """account_type -> generator pool, for the account types this TA uses."""
        return {account_type: log_map[log_type]
                for account_type, log_map in ACCOUNT_TYPE_ROLES.items()
                if log_map.get(log_type)}

    def _entity_records(self, log_type: str, side: str = None) -> list:
        """(entity_id, record) for every entity contributing to `log_type`.

        With `side`, only the roles describing that end of the event are kept, so
        a record holds one machine's fields *in the part it plays*. Without it,
        every role is merged — the shape the pool-building code below wants.
        """
        records = []
        for entity_type, log_map in ENTITY_TYPE_ROLES.items():
            roles = [r for r in log_map.get(log_type, [])
                     if side is None or role_side(r[2]) == side]
            if not roles:
                continue
            for entity in self._data['entities'].values():
                if entity.get('type') != entity_type:
                    continue
                record = {pool: entity.get(field, '')
                          for pool, field, _ in roles
                          if field and entity.get(field)}
                if record:
                    records.append((entity.get('id'), record))
        return records

    def _linked_accounts(self, log_type: str) -> dict:
        """entity_id -> accounts pinned to it that this log type can emit.

        Only entities this log type actually emits count. An account pinned to,
        say, a firewall is not pinned as far as the Windows add-on is concerned:
        pinning it there would drop it from the free pool without ever giving it
        a record to ride on, and the account would vanish from the output.
        """
        pools = self._account_pools(log_type)
        field = self._account_field(log_type)
        contributing = {entity_id for entity_id, _ in self._entity_records(log_type)}
        linked = {}
        for account in self._data['accounts'].values():
            entity_id = account.get('linked_entity')
            if not entity_id or entity_id not in contributing:
                continue
            if account.get('type') not in pools or not account.get(field):
                continue
            linked.setdefault(entity_id, []).append(account)
        return linked

    def _entity_roster(self, log_type: str) -> dict:
        """Records per side: {'src': [...], 'dest': [...], 'device': [...]}.

        A record holds every field one entity contributes *on that side*, so
        reading two of them yields two properties of the same machine. Splitting
        by side is what lets one event describe a client and a server at once —
        an Apache request, a firewall session — instead of forcing both ends to
        be the same host, or drawing each field from an unrelated one.

        An account linked to an entity is folded into that entity's record on the
        src side, where the actor is: a linked account can then only ever be
        emitted alongside its own machine. Its entity gets one record per linked
        account; an entity with none keeps a plain record that any roaming
        account can land on.
        """
        pools = self._account_pools(log_type)
        field = self._account_field(log_type)
        linked = self._linked_accounts(log_type)

        roster = {}
        for side in SIDES:
            records = []
            for entity_id, record in self._entity_records(log_type, side):
                accounts = linked.get(entity_id, []) if side == 'src' else []
                if not accounts:
                    records.append(record)
                    continue
                for account in accounts:
                    records.append({**record, pools[account['type']]: account[field]})
            if records:
                roster[side] = records

        # An account pinned to an entity that contributes nothing on the src side
        # would otherwise never be emitted: give it a record of its own.
        if 'src' not in roster and linked:
            roster['src'] = [{pools[a['type']]: a[field]}
                             for accounts in linked.values() for a in accounts]
        return roster

    def _apply_entity_roster(self, generator_instance, log_type: str,
                             ratio: int) -> None:
        """Publish the roster, already weighted by `ratio`.

        The ratio is folded in as empty records — "use your own defaults here" —
        so a generator draws one record per event and never has to know about
        mixing. Below 1% nothing is published and behaviour is unchanged.
        """
        import random as _random

        roster = self._entity_roster(log_type)
        if not roster or ratio <= 0:
            return
        if ratio < 100:
            blended = {}
            for side, records in roster.items():
                mixed = [records[i % len(records)] for i in range(ratio)]
                mixed += [{} for _ in range(100 - ratio)]
                _random.shuffle(mixed)
                blended[side] = mixed
            roster = blended
        generator_instance._ai_entity_roster = roster

        # Which side each pool belongs to, so a generator only has to name the
        # side for a pool read on both ends.
        sides = {}
        for side, records in roster.items():
            for record in records:
                for pool in record:
                    sides.setdefault(pool, set()).add(side)
        generator_instance._ai_pool_sides = {
            pool: next(iter(s)) for pool, s in sides.items() if len(s) == 1
        }

    def _apply_domain(self, generator_instance, log_type: str) -> None:
        """Pin the generator's domain pools to the environment's AD domain.

        Left untouched when the environment declares no domain, so a user who
        never opens the setting keeps the generator's own sample domains.
        """
        roles = DOMAIN_ROLES.get(log_type)
        if not roles:
            return
        settings = self.get_settings()
        nt_pool, dns_pool = roles
        nt = settings.get('ad_domain')
        dns = settings.get('ad_domain_dns')
        if nt and hasattr(generator_instance, nt_pool):
            setattr(generator_instance, nt_pool, [nt])
        if dns and dns_pool and hasattr(generator_instance, dns_pool):
            setattr(generator_instance, dns_pool, [dns])

    def inject_network_pools_into(self, generator_instance, log_type: str,
                                  options: dict, network_pool_mgr) -> None:
        """
        Phase 4c — set src_ip_pool / dest_ip_pool on the generator from
        sender options (`{src,dest}_pool_mode|id|ai_ratio`).

        Modes:
          - entities (default): no override (keeps inject_into behaviour)
          - pool: full pool IPs
          - both: mix pool IPs with entity-derived IPs (ratio 0–100 = % pool)
        """
        import random as _random

        def _entity_ips_for(direction: str) -> list:
            """Pull IPs from configured entities matching the direction's role."""
            wanted_types = {'src': ('endpoint',),
                            'dest': ('server', 'external')}.get(direction, ())
            ips = []
            for ent in self._data['entities'].values():
                if ent.get('type') in wanted_types:
                    ip = ent.get('ip', '')
                    if ip:
                        ips.append(ip)
            return ips

        def _resolve_pool(pool_id: str) -> list:
            """pool_id format = 'category/name'."""
            if not pool_id or '/' not in pool_id:
                return []
            cat, name = pool_id.split('/', 1)
            try:
                return network_pool_mgr.get_pool(cat, name)
            except Exception:
                return []

        for direction in ('src', 'dest'):
            mode = options.get(f'{direction}_pool_mode')
            if not mode or mode == 'entities':
                continue   # no override; inject_into already handled entity injection

            pool_ips = _resolve_pool(options.get(f'{direction}_pool_id'))
            if mode == 'pool':
                final = pool_ips
            elif mode == 'both':
                ent_ips = _entity_ips_for(direction)
                ratio = max(0, min(100, int(options.get(f'{direction}_pool_ai_ratio', 50))))
                if pool_ips and ent_ips:
                    pool_part = [pool_ips[i % len(pool_ips)] for i in range(ratio)]
                    ent_part  = [ent_ips[i % len(ent_ips)]   for i in range(100 - ratio)]
                    final = pool_part + ent_part
                    _random.shuffle(final)
                else:
                    final = pool_ips or ent_ips
            else:
                final = []

            if final:
                attr = f'{direction}_ip_pool'
                if hasattr(generator_instance, attr):
                    setattr(generator_instance, attr, final)

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    @staticmethod
    def _specs(spec):
        """The entity/account specs behind one ai_fields entry (unwraps `either`)."""
        if spec.get('type') == 'either':
            return [o for o in spec.get('options', []) if o.get('type') in ('entity', 'account')]
        return [spec] if spec.get('type') in ('entity', 'account') else []

    def _values_for(self, spec):
        """(record_id, value) pairs the environment holds for one spec."""
        out = []
        if spec['type'] == 'entity':
            for entity in self._data['entities'].values():
                value = entity.get(spec.get('entity_field', ''), '')
                if entity.get('type') == spec.get('entity_type') and value:
                    out.append((entity['id'], value))
        else:
            for account in self._data['accounts'].values():
                value = account.get(spec.get('account_field', 'username'), '')
                if account.get('type') == spec.get('account_type') and value:
                    out.append((account['id'], value))
        return out

    def attack_environment(self, ai_fields: dict) -> dict:
        """What the environment can put in an attack's fields, drawn per event.

        `entities` holds one record per entity for each entity-backed field,
        carrying the accounts linked to it; `unlinked` holds, per account-backed
        field, the accounts linked to no contributing entity. An event drawn from
        the environment picks an entity and then a user it is allowed to show: one
        of that entity's own accounts, or else one bound to no machine — never a
        user from someone else's host, which is what the links exist to prevent.

        `values` (every candidate) and `pairs` (entity + linked account) are kept
        for the impact panel and for callers that want them flat.
        """
        entity_specs, account_specs = {}, {}
        for field, spec in (ai_fields or {}).items():
            for sub in self._specs(spec):
                target = entity_specs if sub['type'] == 'entity' else account_specs
                target.setdefault(field, []).append(sub)

        accounts_by_field = {field: {account_id: value
                                     for sub in subs for account_id, value in self._values_for(sub)}
                             for field, subs in account_specs.items()}

        entities, linked_ids = {}, set()
        for field, subs in entity_specs.items():
            records = []
            for sub in subs:
                for entity_id, value in self._values_for(sub):
                    linked = {}
                    for account_field, accounts in accounts_by_field.items():
                        own = [v for aid, v in accounts.items()
                               if (self._data['accounts'].get(aid) or {}).get('linked_entity') == entity_id]
                        if own:
                            linked[account_field] = own
                            linked_ids.update(aid for aid in accounts
                                              if (self._data['accounts'].get(aid) or {}).get('linked_entity') == entity_id)
                    records.append({'value': value, 'linked': linked})
            if records:
                entities[field] = records

        unlinked = {field: sorted({v for aid, v in accounts.items() if aid not in linked_ids})
                    for field, accounts in accounts_by_field.items()}
        values = {field: sorted({r['value'] for r in records}) for field, records in entities.items()}
        values.update({field: sorted(set(accounts.values()))
                       for field, accounts in accounts_by_field.items() if accounts})
        pairs = [{entity_field: record['value'], account_field: user}
                 for entity_field, records in entities.items()
                 for record in records
                 for account_field, users in record['linked'].items()
                 for user in users]
        return {'entities': entities, 'unlinked': unlinked, 'values': values, 'pairs': pairs}

    def get_attack_impact(self, ai_fields: dict) -> list:
        """One row per environment-backed attack field, for the attack form."""
        rows = []
        for field, spec in (ai_fields or {}).items():
            subs = self._specs(spec)
            if not subs:
                continue
            sources = [f"{s['entity_type']} · {s['entity_field']}" if s['type'] == 'entity'
                       else f"{s['account_type']} account · {s.get('account_field', 'username')}"
                       for s in subs]
            count = sum(len(self._values_for(s)) for s in subs)
            rows.append({'field': field, 'description': spec.get('description', ''),
                         'sources': sources, 'count': count, 'available': count > 0})
        return rows

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

    # ------------------------------------------------------------------
    # A&I Explicit Workflow (V2 - TA-Centric)
    # ------------------------------------------------------------------

    def get_mutable_fields_for_sourcetype(self, ta_name: str, sourcetype: str) -> dict:
        """
        Get all mutable A&I fields for a TA/sourcetype combination.

        Returns: {
          'entity_fields': {
            'field_name': {'entity_types': [...], 'entity_field': 'ip', 'cim_field': 'src_ip'},
            ...
          },
          'account_fields': {
            'field_name': {'account_types': [...], 'cim_field': 'user'},
            ...
          }
        }
        """
        mapping = self._ai_manager.get_mapping(ta_name, sourcetype)

        entity_fields = {}
        account_fields = {}

        for field_name, field_mapping in mapping.items():
            if not field_mapping.get('mutable', False):
                continue

            if 'entity_type' in field_mapping:
                entity_fields[field_name] = {
                    'entity_type': field_mapping['entity_type'],
                    'entity_field': field_mapping.get('entity_field'),
                    'cim_field': field_mapping.get('cim_field'),
                    'description': field_mapping.get('description', ''),
                }
            elif 'account_type' in field_mapping:
                account_fields[field_name] = {
                    'account_type': field_mapping['account_type'],
                    'account_field': field_mapping.get('account_field', 'username'),
                    'cim_field': field_mapping.get('cim_field'),
                    'description': field_mapping.get('description', ''),
                }

        return {
            'entity_fields': entity_fields,
            'account_fields': account_fields,
        }

    def get_available_entities_for_sourcetype(self, ta_name: str, sourcetype: str) -> dict:
        """
        Get entities grouped by type that can contribute to a sourcetype.

        Returns: {
          'entity_type_name': [
            {'id': '...', 'name': '...', 'ip': '...', 'nt_host': '...', ...},
            ...
          ],
          ...
        }
        """
        mapping = self._ai_manager.get_mapping(ta_name, sourcetype)
        required_entity_types = self._ai_manager.get_entity_types_for_sourcetype(ta_name, sourcetype)

        result = {et: [] for et in required_entity_types}

        for entity in self._data['entities'].values():
            et = entity.get('type')
            if et in required_entity_types:
                result[et].append(entity)

        return result

    def get_available_accounts_for_sourcetype(self, ta_name: str, sourcetype: str) -> dict:
        """
        Get accounts grouped by type that can contribute to a sourcetype.

        Returns: {
          'account_type_name': [
            {'id': '...', 'username': '...', 'email': '...', ...},
            ...
          ],
          ...
        }
        """
        required_account_types = self._ai_manager.get_account_types_for_sourcetype(ta_name, sourcetype)

        result = {at: [] for at in required_account_types}

        for account in self._data['accounts'].values():
            at = account.get('type')
            if at in required_account_types:
                result[at].append(account)

        return result

    def get_sourcetype_context(self, ta_name: str, sourcetype: str) -> dict:
        """
        Get complete A&I context for a TA/sourcetype: metadata, mutable fields,
        available entities/accounts.

        Returns: {
          'ta_name': 'paloalto',
          'sourcetype': 'pan:traffic',
          'sourcetype_info': {...},  # from TA registry
          'mutable_fields': {...},    # from A&I mapping
          'available_entities': {...},
          'available_accounts': {...},
        }
        """
        st_info = get_sourcetype_info(ta_name, sourcetype)
        if not st_info:
            return None

        return {
            'ta_name': ta_name,
            'sourcetype': sourcetype,
            'sourcetype_info': st_info,
            'mutable_fields': self.get_mutable_fields_for_sourcetype(ta_name, sourcetype),
            'available_entities': self.get_available_entities_for_sourcetype(ta_name, sourcetype),
            'available_accounts': self.get_available_accounts_for_sourcetype(ta_name, sourcetype),
        }

    def get_impact_for_sourcetype(self, ta_name: str, sourcetype: str) -> list:
        """
        Return a list of impact rows for a TA/sourcetype, showing which A&I fields
        can be populated and how many entities/accounts are available.

        Returns: [
          {
            'field': 'device_name',
            'entity_type': 'firewall',
            'cim_field': 'dvc',
            'available_entities': 3,
            'account_type': None,
          },
          ...
        ]
        """
        mutable = self.get_mutable_fields_for_sourcetype(ta_name, sourcetype)
        entities_by_type = self.get_available_entities_for_sourcetype(ta_name, sourcetype)
        accounts_by_type = self.get_available_accounts_for_sourcetype(ta_name, sourcetype)

        rows = []

        for field_name, field_info in mutable['entity_fields'].items():
            et = field_info['entity_type']
            count = len(entities_by_type.get(et, []))
            rows.append({
                'field': field_name,
                'entity_type': et,
                'account_type': None,
                'cim_field': field_info['cim_field'],
                'available_count': count,
                'type': 'entity',
            })

        for field_name, field_info in mutable['account_fields'].items():
            at = field_info['account_type']
            count = len(accounts_by_type.get(at, []))
            rows.append({
                'field': field_name,
                'entity_type': None,
                'account_type': at,
                'cim_field': field_info['cim_field'],
                'available_count': count,
                'type': 'account',
            })

        return rows
