"""
Simulation Manager
Orchestrates multiple senders to simulate a real infrastructure's log volume.
"""

import threading
import uuid
from datetime import datetime, timedelta, timezone
from store import JsonStore
from log_generators.registry import REGISTRY


class SimulationManager(JsonStore):
    """Manages infrastructure simulations"""

    def __init__(self, config_file='simulations_config.json'):
        super().__init__(config_file)
        self.simulations = self._data  # alias kept for backward compatibility

    #: Measured sizes, keyed by (log_type, options fingerprint). Sampling is
    #: cheap but not free, and a simulation form recalculates on every keystroke.
    _size_cache: dict = {}

    #: Enough lines to be stable without being slow — a Windows XML event and a
    #: cisco one-liner differ by an order of magnitude, but each is consistent.
    _SIZE_SAMPLE = 200

    @classmethod
    def average_log_size(cls, log_type, options=None):
        """Bytes per event, measured on the generator rather than declared.

        The generators carry an AVG_LOG_SIZE constant, and every one of them was
        wrong: windows and zscaler by +100%, active_directory by +62%, auditd by
        -42%. A simulation asked for 10 GB of Windows and produced 20. Sampling
        the generator costs a few milliseconds and cannot drift.

        `options` matters: the same generator emits a 400-byte classic Windows
        event or a 1200-byte XML one depending on render_format.
        """
        generator_cls = REGISTRY.get(log_type)
        if generator_cls is None:
            return 300

        options = options or {}
        config = generator_cls.SOURCETYPE_CONFIG
        key = (log_type, tuple(sorted(
            (k, tuple(v) if isinstance(v, list) else v)
            for k, v in options.items()
            if k == config['param_key'] or k in config.get('extra_params_keys', {})
        )))
        if key in cls._size_cache:
            return cls._size_cache[key]

        try:
            size = cls._measure(generator_cls, options)
        except Exception:
            size = getattr(generator_cls, 'AVG_LOG_SIZE', 300)
        cls._size_cache[key] = size
        return size

    @classmethod
    def _measure(cls, generator_cls, options):
        """Average byte length over a sample, built the way a sender builds it."""
        import random

        config = generator_cls.SOURCETYPE_CONFIG
        param_key = config['param_key']
        values = options.get(param_key) or config['defaults']
        if not isinstance(values, list):
            values = [values]
        extra = {k: options.get(k, default)
                 for k, default in config.get('extra_params_keys', {}).items()}

        if config.get('multi_instance'):
            instances = [generator_cls(**{config['single_param_name']: v, **extra})
                         for v in values]
        else:
            instances = [generator_cls(**{param_key: values, **extra})]

        total = 0
        for _ in range(cls._SIZE_SAMPLE):
            line = random.choice(instances).generate()
            total += len(line.encode('utf-8')) + 1      # the newline a sink adds
        return max(1, round(total / cls._SIZE_SAMPLE))

    def calculate_frequency(self, volume_bytes, duration_seconds, log_type,
                            options=None):
        """Return logs/sec needed to reach `volume_bytes` over `duration_seconds`."""
        if volume_bytes <= 0 or duration_seconds <= 0:
            return 0
        avg_size = self.average_log_size(log_type, options)
        freq = volume_bytes / (duration_seconds * avg_size)
        return max(1, min(10000, round(freq, 2)))

    @staticmethod
    def _duration_seconds(duration_seconds=None, duration_hours=None):
        """Seconds are canonical; hours are still accepted for stored records."""
        if duration_seconds is not None:
            return float(duration_seconds)
        return float(duration_hours or 0) * 3600

    @staticmethod
    def _entry_bytes(entry):
        """Bytes for an entry, whichever unit it was written with."""
        if entry.get('volume_bytes') is not None:
            return float(entry['volume_bytes'])
        return float(entry.get('volume_gb', 0)) * 1024 ** 3

    def create_simulation(self, name, sourcetypes, duration_seconds=None,
                          duration_hours=None, destination=None,
                          destination_type='file', configuration_id=None,
                          hec_index=None,
                          syslog_host=None, syslog_port=514, syslog_protocol='udp'):
        """
        Create a simulation.

        sourcetypes: list of dicts:
            { 'log_type': str, 'volume_bytes': float, 'options': dict }

        `hec_index` is stamped on every line, and only over HEC: a syslog
        collector assigns the index itself, so sending one would describe a
        routing decision SC4S has not made yet. A sourcetype entry may carry an
        `hec_index` of its own to override it for that source alone.
        """
        sim_id = str(uuid.uuid4())
        seconds = self._duration_seconds(duration_seconds, duration_hours)
        over_hec = destination_type == 'configuration'
        index = (hec_index or '').strip() if over_hec else None
        entries = self._build_entries(sourcetypes, seconds, index, over_hec)

        if not entries:
            raise ValueError("At least one sourcetype with volume > 0 is required.")

        self._data[sim_id] = {
            'id': sim_id,
            'name': name,
            'duration_seconds': seconds,
            'destination': destination,
            'destination_type': destination_type,
            'configuration_id': configuration_id,
            'hec_index': index,
            'syslog_host': syslog_host,
            'syslog_port': syslog_port,
            'syslog_protocol': syslog_protocol,
            'sourcetypes': entries,
            'status': 'stopped',
            'created_at': datetime.now().isoformat(),
        }
        self._save()
        return sim_id

    def _build_entries(self, sourcetypes, seconds, index, over_hec=None):
        """Turn a target volume per source into a rate, once.

        `index` is the simulation-wide HEC index, already None for any other
        destination. A row may name its own instead — one simulation can then
        split its sources across indexes — but a row cannot conjure an index
        where the destination has none, so an override on a file or syslog
        simulation is dropped with the rest.
        """
        if over_hec is None:
            over_hec = bool(index)
        entries = []
        for st in sourcetypes:
            log_type = st['log_type']
            volume_bytes = self._entry_bytes(st)
            if volume_bytes <= 0:
                continue
            options = dict(st.get('options', {}))
            row_index = (st.get('hec_index') or '').strip() if over_hec else ''
            effective_index = row_index or index
            if effective_index:
                options['hec_index'] = effective_index
            else:
                options.pop('hec_index', None)
            entries.append({
                'log_type': log_type,
                'volume_bytes': volume_bytes,
                'frequency': self.calculate_frequency(volume_bytes, seconds,
                                                      log_type, options),
                'avg_log_size': self.average_log_size(log_type, options),
                'hec_index': effective_index or None,
                'options': options,
                'sender_id': None,
            })
        return entries

    def update_simulation(self, sim_id, name, sourcetypes, duration_seconds=None,
                          duration_hours=None, destination=None,
                          destination_type='file', configuration_id=None,
                          hec_index=None,
                          syslog_host=None, syslog_port=514, syslog_protocol='udp'):
        """Rewrite a stopped simulation in place, keeping its id.

        Refused while running: the senders were created from the current rates,
        so changing them underneath would leave the simulation describing one
        thing and emitting another.
        """
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self._data[sim_id]
        if sim.get('status') == 'running':
            raise ValueError("Stop the simulation before editing it.")

        seconds = self._duration_seconds(duration_seconds, duration_hours)
        over_hec = destination_type == 'configuration'
        index = (hec_index or '').strip() if over_hec else None
        entries = self._build_entries(sourcetypes, seconds, index, over_hec)
        if not entries:
            raise ValueError("At least one sourcetype with volume > 0 is required.")

        sim.update({
            'name': name,
            'duration_seconds': seconds,
            'destination': destination,
            'destination_type': destination_type,
            'configuration_id': configuration_id,
            'hec_index': index,
            'syslog_host': syslog_host,
            'syslog_port': syslog_port,
            'syslog_protocol': syslog_protocol,
            'sourcetypes': entries,
        })
        self._save()
        return sim_id

    def start_simulation(self, sim_id, sender_manager):
        """Start all senders for a simulation."""
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self._data[sim_id]
        if sim['status'] == 'running':
            raise ValueError("Simulation is already running")

        with self._lifecycle_lock:
            self._start_senders(sim, sim_id, sender_manager)

    def _start_senders(self, sim, sim_id, sender_manager):
        for entry in sim['sourcetypes']:
            sender_id = sender_manager.create_sender(
                name=f"[SIM] {sim['name']} — {entry['log_type']}",
                log_type=entry['log_type'],
                frequency=entry['frequency'],
                enabled=True,
                options=entry.get('options', {}),
                destination=sim.get('destination'),
                destination_type=sim['destination_type'],
                configuration_id=sim.get('configuration_id'),
                syslog_host=sim.get('syslog_host'),
                syslog_port=sim.get('syslog_port', 514),
                syslog_protocol=sim.get('syslog_protocol', 'udp'),
            )
            entry['sender_id'] = sender_id

        # Same lock as the stop path, so a deadline firing mid-start cannot
        # tear down senders this call is still creating.
        started = datetime.now(timezone.utc)
        sim['status'] = 'running'
        sim['started_at'] = started.isoformat()
        # Absolute, so the deadline survives a restart: a timer cannot, and a
        # simulation left running because the process bounced would keep
        # sending for as long as nobody noticed.
        sim['ends_at'] = (started + timedelta(
            seconds=float(sim.get('duration_seconds') or 0))).isoformat()
        self._save()

        self._schedule_stop(sim_id, sender_manager)

    #: One timer per running simulation, so a stop can cancel its own deadline.
    _timers: dict = {}

    #: The deadline timer and a request can reach stop_simulation at the same
    #: instant. Without this they both delete the same senders and the loser
    #: raises on an id that has just gone.
    _lifecycle_lock = threading.RLock()

    def _schedule_stop(self, sim_id, sender_manager):
        """Stop the simulation when its window closes.

        The timer is the normal path; expire_finished() is the one that catches
        a restart, since a timer does not survive the process that made it.
        """
        self._cancel_timer(sim_id)
        remaining = self._seconds_remaining(self._data[sim_id])
        if remaining is None:
            return
        timer = threading.Timer(max(0.0, remaining),
                                self._on_deadline, args=(sim_id, sender_manager))
        timer.daemon = True
        self._timers[sim_id] = timer
        timer.start()

    def _on_deadline(self, sim_id, sender_manager):
        try:
            sim = self._data.get(sim_id)
            if sim and sim.get('status') == 'running':
                self.stop_simulation(sim_id, sender_manager)
        except Exception as exc:                                # pragma: no cover
            print(f"[Simulation] auto-stop failed for {sim_id}: {exc}")

    def _cancel_timer(self, sim_id):
        timer = self._timers.pop(sim_id, None)
        if timer:
            timer.cancel()

    @staticmethod
    def _seconds_remaining(sim):
        """Seconds until the window closes, or None when it is not running."""
        if sim.get('status') != 'running' or not sim.get('ends_at'):
            return None
        ends = datetime.fromisoformat(sim['ends_at'])
        if ends.tzinfo is None:
            ends = ends.replace(tzinfo=timezone.utc)
        return (ends - datetime.now(timezone.utc)).total_seconds()

    def expire_finished(self, sender_manager):
        """Stop any simulation whose window has closed.

        Called when the list is read: a timer dies with the process that created
        it, so after a restart this is what ends a simulation that outlived it.
        """
        for sim_id, sim in list(self._data.items()):
            remaining = self._seconds_remaining(sim)
            if remaining is not None and remaining <= 0:
                try:
                    self.stop_simulation(sim_id, sender_manager)
                except Exception as exc:                        # pragma: no cover
                    print(f"[Simulation] expiry failed for {sim_id}: {exc}")

    def stop_simulation(self, sim_id, sender_manager):
        """Stop and delete all senders for a simulation."""
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        with self._lifecycle_lock:
            sim = self._data[sim_id]
            if sim.get('status') != 'running':
                return                      # already stopped, by a deadline or a click

            for entry in sim['sourcetypes']:
                sender_id = entry.get('sender_id')
                entry['sender_id'] = None
                if not sender_id:
                    continue
                try:
                    sender_manager.delete_sender(sender_id)
                except Exception:
                    pass                    # gone already; nothing left to stop

            sim['status'] = 'stopped'
            sim.pop('started_at', None)
            sim.pop('ends_at', None)
            self._cancel_timer(sim_id)
            self._save()

    def reconcile_after_restart(self, sender_manager):
        """Stop every simulation the file calls running but nothing runs.

        A running simulation's senders and its deadline timer both live in the
        process, so after a restart it showed a countdown while sending nothing
        until `ends_at` came round. Stopping it removes its senders the same way
        a click does. Returns the ids it stopped.
        """
        stopped = []
        for sim_id, sim in list(self._data.items()):
            if sim.get('status') != 'running' or sim_id in self._timers:
                continue
            self.stop_simulation(sim_id, sender_manager)
            stopped.append(sim_id)
        return stopped

    def delete_simulation(self, sim_id, sender_manager):
        """Stop and remove a simulation."""
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self._data[sim_id]
        if sim['status'] == 'running':
            self.stop_simulation(sim_id, sender_manager)

        del self._data[sim_id]
        self._save()

    def get_all_simulations(self, sender_manager=None):
        """Every simulation, with the seconds left on any that is running."""
        if sender_manager is not None:
            self.expire_finished(sender_manager)

        out = []
        for sim in self._data.values():
            entry = dict(sim)
            remaining = self._seconds_remaining(sim)
            entry['seconds_remaining'] = (
                max(0, round(remaining)) if remaining is not None else None)
            out.append(entry)
        return out

    def get_simulation(self, sim_id):
        return self._data.get(sim_id)
