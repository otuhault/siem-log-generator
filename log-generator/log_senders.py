"""
Sender Management and Log Generation Engine
"""

import json
import threading
import time
import uuid
import random
from datetime import datetime
from pathlib import Path

from store import JsonStore
from log_generators.registry import REGISTRY
from hec_sender import HECSender
from syslog_sender import SyslogSender
from configuration_manager import ConfigurationManager
from attack_generators import ATTACK_REGISTRY, AttackGeneratorFactory
from environment_manager import EnvironmentManager

_env_manager = EnvironmentManager()


class MultiSourceLogGenerator:
    """Wraps one or more generator instances behind a single generate() call."""

    def __init__(self, generator_or_list):
        if isinstance(generator_or_list, list):
            self._generators = generator_or_list
            self._multi = True
        else:
            self._generator = generator_or_list
            self._multi = False

    def generate(self):
        if self._multi:
            return random.choice(self._generators).generate()
        return self._generator.generate()


class SenderManager(JsonStore):
    """Manages log senders and their lifecycle."""

    def __init__(self, config_file='senders_config.json', config_mgr=None):
        super().__init__(config_file)
        self.senders = self._data           # alias for backward compatibility
        self.threads: dict = {}
        self._config_mgr = config_mgr or ConfigurationManager()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _build_syslog_sender(self, sender_config: dict) -> SyslogSender:
        """Return a ready SyslogSender from sender config fields."""
        return SyslogSender(
            host=sender_config['syslog_host'],
            port=sender_config.get('syslog_port', 514),
            protocol=sender_config.get('syslog_protocol', 'udp'),
        )

    def _build_hec_sender(self, config_id: str, sender_options: dict = None) -> HECSender:
        """Load a HEC config and return a ready HECSender, or raise ValueError.

        sender_options may contain hec_index, hec_sourcetype, hec_host, hec_source
        which override the values stored in the HEC destination config.
        """
        hec_config = self._config_mgr.get_configuration(config_id)
        if not hec_config:
            raise ValueError(f"Configuration {config_id} not found")
        opts = sender_options or {}
        return HECSender(
            url=hec_config['url'],
            port=hec_config['port'],
            token=hec_config['token'],
            index=opts.get('hec_index') or hec_config.get('index'),
            sourcetype=opts.get('hec_sourcetype') or hec_config.get('sourcetype'),
            host=opts.get('hec_host') or hec_config.get('host'),
            source=opts.get('hec_source') or hec_config.get('source'),
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_sender(self, name, log_type, frequency, enabled=False, options=None,
                      destination=None, destination_type='file', configuration_id=None,
                      syslog_host=None, syslog_port=514, syslog_protocol='udp',
                      attack_status=None):
        is_attack = log_type in ATTACK_REGISTRY

        if not is_attack and log_type not in REGISTRY:
            raise ValueError(f"Unknown log type: {log_type}")

        sender_id = str(uuid.uuid4())
        self._data[sender_id] = {
            'id':               sender_id,
            'name':             name,
            'log_type':         log_type,
            'destination':      destination,
            'destination_type': destination_type,
            'configuration_id': configuration_id,
            'syslog_host':      syslog_host,
            'syslog_port':      syslog_port,
            'syslog_protocol':  syslog_protocol,
            'frequency':        frequency,
            'enabled':          enabled,
            'created_at':       datetime.now().isoformat(),
            'logs_generated':   0,
            'options':          options or {},
            'attack_status':    attack_status if is_attack else None,
        }
        self._save()

        if enabled:
            self.start_sender(sender_id)

        return sender_id

    def update_sender(self, sender_id, data):
        if sender_id not in self._data:
            raise ValueError(f"Sender {sender_id} not found")

        was_enabled = self._data[sender_id]['enabled']
        self._data[sender_id].update(data)
        self._save()

        if was_enabled:
            self.stop_sender(sender_id)
            if self._data[sender_id]['enabled']:
                self.start_sender(sender_id)

    def delete_sender(self, sender_id):
        if sender_id not in self._data:
            raise ValueError(f"Sender {sender_id} not found")
        self.stop_sender(sender_id)
        del self._data[sender_id]
        self._save()

    def toggle_sender(self, sender_id):
        if sender_id not in self._data:
            raise ValueError(f"Sender {sender_id} not found")

        sender = self._data[sender_id]
        is_attack = sender['log_type'] in ATTACK_REGISTRY

        if is_attack:
            if sender.get('attack_status') == 'Running':
                sender['enabled'] = False
                sender['attack_status'] = 'Disabled'
                self._save()
                self.stop_sender(sender_id)
            else:
                sender['enabled'] = True
                self._save()
                self.start_sender(sender_id)
        else:
            enabled = not sender['enabled']
            sender['enabled'] = enabled
            self._save()
            if enabled:
                self.start_sender(sender_id)
            else:
                self.stop_sender(sender_id)

    def clone_sender(self, sender_id):
        if sender_id not in self._data:
            raise ValueError(f"Sender {sender_id} not found")

        original = self._data[sender_id].copy()
        new_id = str(uuid.uuid4())
        original.update({
            'id':             new_id,
            'name':           f"{original['name']} (copy)",
            'enabled':        False,
            'created_at':     datetime.now().isoformat(),
            'logs_generated': 0,
        })
        self._data[new_id] = original
        self._save()
        return new_id

    # ------------------------------------------------------------------
    # Thread management
    # ------------------------------------------------------------------

    def start_sender(self, sender_id):
        if sender_id in self.threads:
            return  # already running

        sender   = self._data[sender_id]
        log_type = sender['log_type']
        options  = sender.get('options', {})

        if log_type in ATTACK_REGISTRY:
            self._data[sender_id]['attack_status'] = 'Running'
            self._save()
            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._execute_attack,
                args=(sender_id, sender, stop_event),
                daemon=True,
            )
            self.threads[sender_id] = {'thread': thread, 'stop_event': stop_event}
            thread.start()
            return

        # Build the generator from the registry config
        generator_class = REGISTRY[log_type]
        config          = generator_class.SOURCETYPE_CONFIG
        param_value     = options.get(config['param_key'], config['defaults'])

        use_ai = options.get('use_assets_identities', False)
        ai_ratio = int(options.get('assets_identities_ratio', 100))

        if config.get('multi_instance'):
            extra_params = {
                k: options.get(k, default)
                for k, default in config.get('extra_params_keys', {}).items()
            }
            gen_instances = [
                generator_class(**{config['single_param_name']: val, **extra_params})
                for val in param_value
            ]
            if use_ai:
                for gi in gen_instances:
                    _env_manager.inject_into(gi, log_type, ratio=ai_ratio)
            generator = MultiSourceLogGenerator(gen_instances)
        else:
            gen_instance = generator_class(**{config['param_key']: param_value})
            if use_ai:
                _env_manager.inject_into(gen_instance, log_type, ratio=ai_ratio)
            generator = MultiSourceLogGenerator(gen_instance)

        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._generate_logs,
            args=(sender_id, generator, sender, stop_event),
            daemon=True,
        )
        self.threads[sender_id] = {'thread': thread, 'stop_event': stop_event}
        thread.start()

    def stop_sender(self, sender_id):
        if sender_id in self.threads:
            self.threads[sender_id]['stop_event'].set()
            self.threads[sender_id]['thread'].join(timeout=2)
            del self.threads[sender_id]

    # ------------------------------------------------------------------
    # Worker threads
    # ------------------------------------------------------------------

    def _execute_attack(self, sender_id, sender_config, stop_event):
        """Execute a finite attack: N events spread over a duration."""
        log_type = sender_config['log_type']
        options  = sender_config.get('options', {})

        events_count = min(max(int(options.get('attack_events_count', 100)), 1), 10000)
        duration     = min(max(int(options.get('attack_duration', 60)), 1), 3600)
        interval     = duration / events_count if events_count > 0 else 1.0

        print(f"[Attack] {sender_id}: {events_count} events over {duration}s (interval: {interval:.3f}s)")

        generator = AttackGeneratorFactory.get_generator(log_type, options)
        if not generator:
            self._fail_attack(sender_id, 'Error: No generator')
            return

        destination_type = sender_config.get('destination_type', 'file')
        events_sent = 0

        try:
            if destination_type == 'file':
                dest_path = Path(sender_config['destination'])
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with dest_path.open('a') as f:
                    while not stop_event.is_set() and events_sent < events_count:
                        f.write(generator.generate() + '\n')
                        f.flush()
                        events_sent += 1
                        self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)

            elif destination_type == 'configuration':
                config_id = sender_config.get('configuration_id')
                if not config_id:
                    self._fail_attack(sender_id, 'Error: No configuration')
                    return
                hec = self._build_hec_sender(config_id, sender_config.get('options', {}))
                try:
                    while not stop_event.is_set() and events_sent < events_count:
                        if hec.send_event(generator.generate()):
                            events_sent += 1
                            self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    hec.close()

            elif destination_type == 'syslog':
                syslog = self._build_syslog_sender(sender_config)
                try:
                    while not stop_event.is_set() and events_sent < events_count:
                        if syslog.send_event(generator.generate()):
                            events_sent += 1
                            self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    syslog.close()

            completion_time = datetime.now().strftime('%m/%d %H:%M:%S')
            print(f"[Attack] Done: {events_sent}/{events_count} events")
            self._data[sender_id]['attack_status'] = f'Done ({completion_time})'
            self._data[sender_id]['enabled'] = False
            self._save()

        except Exception as e:
            print(f"[Attack] Exception: {e}")
            self._data[sender_id]['attack_status'] = f'Error: {e}'
            self._data[sender_id]['enabled'] = False
            self._save()
        finally:
            self.threads.pop(sender_id, None)

    def _generate_logs(self, sender_id, generator, sender_config, stop_event):
        """Generate logs continuously at the configured frequency."""
        frequency = sender_config['frequency']
        interval  = 1.0 / frequency if frequency > 0 else 1.0
        destination_type = sender_config.get('destination_type', 'file')

        try:
            if destination_type == 'file':
                dest_path = Path(sender_config['destination'])
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with dest_path.open('a') as f:
                    while not stop_event.is_set():
                        f.write(generator.generate() + '\n')
                        f.flush()
                        self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)

            elif destination_type == 'configuration':
                config_id = sender_config.get('configuration_id')
                if not config_id:
                    print(f"[Sender] {sender_id}: No configuration_id")
                    return
                hec = self._build_hec_sender(config_id, sender_config.get('options', {}))
                try:
                    while not stop_event.is_set():
                        if hec.send_event(generator.generate()):
                            self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    hec.close()

            elif destination_type == 'syslog':
                syslog = self._build_syslog_sender(sender_config)
                try:
                    while not stop_event.is_set():
                        if syslog.send_event(generator.generate()):
                            self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    syslog.close()

        except Exception as e:
            print(f"[Sender] {sender_id}: Exception: {e}")

    def _fail_attack(self, sender_id, reason: str):
        """Mark an attack as failed and clean up."""
        print(f"[Attack] {sender_id}: {reason}")
        self._data[sender_id]['attack_status'] = reason
        self._data[sender_id]['enabled'] = False
        self._save()
        self.threads.pop(sender_id, None)

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_all_senders(self):
        return list(self._data.values())

    def get_sender(self, sender_id):
        return self._data.get(sender_id)

    def get_available_log_types(self):
        """Return metadata for all registered log types (driven by the registry)."""
        return {log_type: cls.METADATA for log_type, cls in REGISTRY.items()}
