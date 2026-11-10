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
from attack_generators import (ATTACK_REGISTRY, AttackGeneratorFactory, attack_destinations,
                               spans_several_sources)
from environment_manager import EnvironmentManager

_env_manager = EnvironmentManager()


def environment_manager():
    """The environment senders and attacks read — the API must write to this one."""
    return _env_manager


def _emit(generator):
    """Return (line, sourcetype, source) from any generator.

    Attack generators and the plain doubles used in tests only expose
    generate() -> str; they carry no metadata attribution.
    """
    if hasattr(generator, 'generate_with_metadata'):
        return generator.generate_with_metadata()
    return generator.generate(), None, None


class AttackEvent:
    """One event of an attack plan: what to render, and where it is stamped."""

    __slots__ = ('kind', 'generator', 'sourcetype', 'source', 'identity')

    def __init__(self, kind, generator, sourcetype, source, identity=None):
        self.kind, self.generator = kind, generator
        self.sourcetype, self.source = sourcetype, source
        self.identity = identity or {}

    @property
    def host(self):
        """The machine the event happened on, when the attack named one.

        Only HEC can stamp it: a file is read by whatever reads it, which sets
        the host itself.
        """
        return self.identity.get('host')

    def render(self):
        """The event's line, with this event's environment values applied."""
        self.generator.use_identity(self.identity)
        return (self.generator.generate() if self.kind == 'attack'
                else self.generator.generate_noise())


class MultiSourceLogGenerator:
    """Wraps one or more generator instances behind a single generate() call.

    Each instance may be paired with the Splunk sourcetype it emits, so the HEC
    sink can stamp the right `sourcetype` on every event. `generate()` keeps
    returning a plain string; use `generate_with_sourcetype()` when the caller
    needs to know which sourcetype produced the line.
    """

    def __init__(self, generator_or_list, sourcetypes=None, sources=None):
        if isinstance(generator_or_list, list):
            self._generators = generator_or_list
            self._multi = True
        else:
            self._generators = [generator_or_list]
            self._multi = False
        count = len(self._generators)
        # Parallel lists; None means "no documented value for this instance".
        self._sourcetypes = list(sourcetypes) if sourcetypes else [None] * count
        self._sources = list(sources) if sources else [None] * count

    def generate(self):
        return self.generate_with_metadata()[0]

    def generate_with_sourcetype(self):
        """Return (line, sourcetype) — sourcetype is None when unattributed."""
        line, sourcetype, _source = self.generate_with_metadata()
        return line, sourcetype

    def generate_with_metadata(self):
        """Return (line, sourcetype, source); either may be None."""
        index = random.randrange(len(self._generators)) if self._multi else 0
        return (self._generators[index].generate(),
                self._sourcetypes[index],
                self._sources[index])


class SenderManager(JsonStore):
    """Manages log senders and their lifecycle."""

    def __init__(self, config_file='senders_config.json', config_mgr=None,
                 syslog_dests_mgr=None):
        super().__init__(config_file)
        self.senders = self._data           # alias for backward compatibility
        self.threads: dict = {}
        self._config_mgr = config_mgr or ConfigurationManager()
        # Lazily import to avoid hard dependency at import time
        if syslog_dests_mgr is None:
            from syslog_destinations import SyslogDestinationsManager
            syslog_dests_mgr = SyslogDestinationsManager()
        self._syslog_dests_mgr = syslog_dests_mgr

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _build_syslog_sender(self, sender_config: dict) -> SyslogSender:
        """Return a ready SyslogSender.

        Phase 4b: prefer `syslog_destination_id` (resolved against the persisted
        Syslog Destinations registry). Falls back to the legacy inline
        `syslog_host`/`syslog_port`/`syslog_protocol` fields for backward compat.
        """
        dest_id = sender_config.get('syslog_destination_id')
        if dest_id:
            dest = self._syslog_dests_mgr.get_destination(dest_id)
            if not dest:
                raise ValueError(f"Syslog destination {dest_id} not found")
            return SyslogSender(
                host=dest['host'],
                port=dest.get('port', 514),
                protocol=dest.get('protocol', 'udp'),
            )
        return SyslogSender(
            host=sender_config['syslog_host'],
            port=sender_config.get('syslog_port', 514),
            protocol=sender_config.get('syslog_protocol', 'udp'),
        )

    @staticmethod
    def _bridge_sourcetype(sources_meta, value):
        """Splunk sourcetype declared by a generator source id, or None."""
        for source in sources_meta:
            if source.get('id') == value:
                return source.get('sourcetype')
        return None

    @staticmethod
    def _apply_delivery_format(gen_instances, log_type, options, destination_type):
        """Wrap each generator so its lines leave in the delivery format that applies.

        The rules live in syslog_framing.apply_delivery_format(), shared with
        attacks. In short: HEC receives the event itself; a syslog destination
        frames a source that frames itself or has no forwarder path, and lets the
        others choose; a file holds whichever shape was chosen — a forwarder's
        input or a capture of the wire — defaulting to the shape the source
        already has, so an existing sender's output does not change.
        """
        from syslog_framing import apply_delivery_format
        return apply_delivery_format(gen_instances, log_type,
                                     options.get('delivery_format'), destination_type)

    @staticmethod
    def _registry_source(log_type, sourcetype_name, render_format=None):
        """The `source` metadata the registry documents for a sourcetype, or None.

        Windows keys it on render_format, because the TA derives `source` from the
        event body and the body shape is what render_format picks. TAs that emit
        one shape only carry a plain `hec_source`.
        """
        from ta_registry import wire_metadata
        return wire_metadata(log_type, sourcetype_name, render_format)[1]

    @staticmethod
    def _ta_default_sourcetype(log_type, render_format=None):
        """The TA's documented ingestion sourcetype, or None.

        Keyed on render_format for the same reason as _registry_source: the two
        Windows sourcetypes are the classic and the XML form of the same channel.
        """
        from ta_registry import get_ta
        ta = get_ta(log_type) or {}
        by_format = ta.get('hec_default_sourcetype_by_render_format')
        if by_format:
            return by_format.get(render_format or 'xml')
        return ta.get('hec_default_sourcetype')

    @staticmethod
    def _single_registry_sourcetype(log_type):
        """The lone Splunk sourcetype of an umbrella TA, or None if ambiguous."""
        from ta_registry import get_ta
        ta = get_ta(log_type) or {}
        sourcetypes = ta.get('sourcetypes', [])
        return sourcetypes[0]['name'] if len(sourcetypes) == 1 else None

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
                      syslog_destination_id=None,
                      syslog_host=None, syslog_port=514, syslog_protocol='udp',
                      attack_status=None, duration_seconds=0):
        is_attack = log_type in ATTACK_REGISTRY

        if not is_attack and log_type not in REGISTRY:
            raise ValueError(f"Unknown log type: {log_type}")

        if is_attack:
            self._check_attack_destination(log_type, destination_type)

        sender_id = str(uuid.uuid4())
        self._data[sender_id] = {
            'id':                    sender_id,
            'name':                  name,
            'log_type':              log_type,
            'destination':           destination,
            'destination_type':      destination_type,
            'configuration_id':      configuration_id,
            'syslog_destination_id': syslog_destination_id,
            'syslog_host':           syslog_host,
            'syslog_port':           syslog_port,
            'syslog_protocol':       syslog_protocol,
            'frequency':             frequency,
            # How long it keeps going once started; 0 runs until stopped by hand.
            # An attack carries its own duration in its options.
            'duration_seconds':      max(0, int(duration_seconds or 0)),
            'enabled':               enabled,
            'created_at':            datetime.now().isoformat(),
            'logs_generated':        0,
            'options':               options or {},
            'attack_status':         attack_status if is_attack else None,
        }
        self._save()

        if enabled:
            self.start_sender(sender_id)

        return sender_id

    @staticmethod
    def _check_attack_destination(attack_type, destination_type):
        definition = ATTACK_REGISTRY[attack_type]
        if destination_type in attack_destinations(definition):
            return
        from attack_generators import spans_several_sources
        reason = ('spans several sourcetypes' if spans_several_sources(definition)
                  else 'is not a source syslog collects')
        raise ValueError(f"{definition['name']} {reason} and is sent over HEC or to a file only")

    def update_sender(self, sender_id, data):
        if sender_id not in self._data:
            raise ValueError(f"Sender {sender_id} not found")

        merged = {**self._data[sender_id], **data}
        if merged.get('log_type') in ATTACK_REGISTRY:
            self._check_attack_destination(merged['log_type'], merged.get('destination_type', 'file'))

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
            # When it last ran, which the table shows. Stamped as it starts, so
            # an attack under way already says when it began rather than still
            # showing the run before it.
            self._data[sender_id]['last_run_at'] = datetime.now().isoformat()
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

        # Lazy import to avoid circular dep
        from network_pools import NetworkPoolManager as _NPM
        if not hasattr(self, '_network_pool_mgr'):
            self._network_pool_mgr = _NPM()

        extra_params = {
            k: options.get(k, default)
            for k, default in config.get('extra_params_keys', {}).items()
        }
        values = param_value if isinstance(param_value, list) else [param_value]
        sources_meta = generator_class.METADATA.get('sources', [])
        # A TA is "bridged" when every generator source declares the Splunk
        # sourcetype it produces (METADATA.sources[].sourcetype).
        bridged = bool(sources_meta) and all(s.get('sourcetype') for s in sources_meta)

        if config.get('multi_instance'):
            # One instance per source; the constructor takes a single value.
            gen_instances = [
                generator_class(**{config['single_param_name']: val, **extra_params})
                for val in values
            ]
            # multi_instance and bridged are independent: windows splits per channel
            # AND names each one, while apache / zscaler split per category without
            # declaring a sourcetype for any of them. Falling through to the umbrella
            # value keeps those TAs from emitting no sourcetype at all.
            umbrella = self._single_registry_sourcetype(log_type)
            raw_sourcetypes = [
                self._bridge_sourcetype(sources_meta, val) or umbrella
                for val in values
            ]
        elif bridged:
            # Constructor takes a list, but the TA maps each value to its own
            # Splunk sourcetype: split so every event can be attributed.
            gen_instances = [
                generator_class(**{config['param_key']: [val], **extra_params})
                for val in values
            ]
            raw_sourcetypes = [self._bridge_sourcetype(sources_meta, val) for val in values]
        else:
            # Umbrella TA: a single Splunk sourcetype covers every category, and
            # the generator applies its own weighting across them — keep one
            # instance holding the full list so that distribution is preserved.
            gen_instances = [generator_class(**{config['param_key']: values, **extra_params})]
            raw_sourcetypes = [self._single_registry_sourcetype(log_type)]

        # Resolution order for the sourcetype stamped on each event:
        #   per-sourcetype override typed in the form
        #   > the TA's documented ingestion sourcetype (e.g. pan:log, split at
        #     index time by the TA's TRANSFORMS)
        #   > the sourcetype's own name
        # The TA default applies to senders persisted before the override map
        # existed, so they follow the vendor-documented path too.
        overrides = options.get('hec_sourcetype_map') or {}
        render_format = options.get('render_format')
        ta_default = self._ta_default_sourcetype(log_type, render_format)
        sourcetypes = [
            (overrides.get(st) or ta_default or st) if st
            else (options.get('hec_sourcetype') or None)
            for st in raw_sourcetypes
        ]

        # Same ladder for `source`, which the Windows TA classifies on:
        #   per-sourcetype override > registry value > nothing.
        # There is no "sourcetype name" fallback here: a source we cannot source
        # from the registry is a source we must not invent, so it stays unset.
        source_overrides = options.get('hec_source_map') or {}
        sources = [
            (source_overrides.get(st)
             or self._registry_source(log_type, st, render_format)) if st
            else (options.get('hec_source') or None)
            for st in raw_sourcetypes
        ]

        if use_ai:
            for gi in gen_instances:
                _env_manager.inject_into(gi, log_type, ratio=ai_ratio)
                _env_manager.inject_network_pools_into(gi, log_type, options, self._network_pool_mgr)

        # Delivery format: a forwarder ships the file's own bytes, a syslog
        # collector needs RFC 3164 framing around them. Applied after injection
        # so the header's hostname is the A&I entity the event is already about.
        gen_instances = self._apply_delivery_format(
            gen_instances, log_type, options,
            sender.get('destination_type', 'file'))

        generator = MultiSourceLogGenerator(gen_instances, sourcetypes, sources)

        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._generate_logs,
            args=(sender_id, generator, sender, stop_event),
            daemon=True,
        )
        self.threads[sender_id] = {'thread': thread, 'stop_event': stop_event}
        thread.start()

    #: Written on an attack the process died under, so its row says what
    #: happened instead of looking like one that was never started.
    INTERRUPTED = 'Interrupted (application restarted)'

    def reconcile_after_restart(self):
        """Mark as stopped every sender the file calls enabled but nothing runs.

        `enabled` is persisted; the thread that honours it is not. After any
        restart — a manual one, or Flask's reloader reacting to a changed .py —
        a sender used to come back listed as active with a pause button while
        generating nothing, and the first click stopped it rather than starting
        it. Resuming them all instead would start pushing events into Splunk the
        moment the application launches, which nobody asked for.

        Safe to call at any time: a sender with a live thread is left alone.
        Returns the ids it changed.
        """
        changed = []
        for sender_id, sender in self._data.items():
            if not sender.get('enabled') or sender_id in self.threads:
                continue
            sender['enabled'] = False
            if sender.get('attack_status') == 'Running':
                sender['attack_status'] = self.INTERRUPTED
            changed.append(sender_id)
        if changed:
            self._save()
        return changed

    def stop_sender(self, sender_id):
        if sender_id in self.threads:
            self.threads[sender_id]['stop_event'].set()
            self.threads[sender_id]['thread'].join(timeout=2)
            del self.threads[sender_id]

    # ------------------------------------------------------------------
    # Worker threads
    # ------------------------------------------------------------------

    #: Bounds shared by every attack.
    MAX_ATTACK_EVENTS = 10000
    MAX_ATTACK_DURATION = 3600

    @staticmethod
    def attack_plan(attack_type, options, destination_type='configuration'):
        """What an attack will send: one AttackEvent per event, in sending order.

        The count asked for is the count sent. With several sourcetypes selected
        the events are spread evenly between them — each probe recorded by one
        device, the way a real path puts a destination behind one firewall — not
        replayed once per sourcetype. The detections these attacks exercise
        aggregate over the datamodel, not per sourcetype: their `rule` sits in the
        inner tstats BY but never in the outer grouping, so rows from different
        firewalls still merge into one group and the totals are unchanged.

        The environment ratio is applied per event. Of the attack events, as close
        to that share as whole events allow draw their user and host from the
        environment; the rest keep the generator's defaults. The noise gets its
        own draw at the same ratio. A value typed in the form wins everywhere.
        """
        from attack_generators import draw_environment_identity, environment_flags
        from syslog_framing import apply_delivery_format
        from ta_registry import wire_metadata

        definition = ATTACK_REGISTRY[attack_type]
        declared = definition['data_sources']
        defaults = definition.get('defaults', {})

        selections = []
        for chosen in options.get('attack_sources') or []:
            match = next((d for d in declared
                          if d['log_type'] == chosen.get('log_type')
                          and d['sourcetype'] == chosen.get('sourcetype')), None)
            if match:
                fmt = chosen.get('render_format')
                selections.append((match, fmt if fmt in match['formats'] else match['formats'][0],
                                   chosen.get('delivery_format')))
        if not selections:
            selections = [(declared[0], declared[0]['formats'][0], None)]

        def bounded(key, default, low, high):
            try:
                value = int(options.get(key, default))
            except (TypeError, ValueError):
                value = default
            return max(low, min(high, value))

        attacks = bounded('attack_events_count', defaults.get('events', 5), 1, SenderManager.MAX_ATTACK_EVENTS)
        noise = (bounded('attack_noise_count', defaults.get('noise_events', 20), 0, SenderManager.MAX_ATTACK_EVENTS)
                 if options.get('attack_noise') else 0)

        behaviors = definition.get('field_behaviors', {})
        field_defaults = definition['generator_class'].FIELD_DEFAULTS
        typed = {field: options[f'target_{field}'] for field in behaviors
                 if options.get(f'target_{field}')}
        use_environment = bool(options.get('use_assets_identities'))
        environment = (_env_manager.attack_environment(definition.get('ai_fields', {}))
                       if use_environment else {})
        ratio = bounded('assets_identities_ratio', 100, 0, 100) if use_environment else 0

        def identities(count):
            """Every event's values, resolved once so all sources render the same ones.

            A typed value pins the field for every event. Otherwise an event drawn
            for the environment takes its values from there; a rotating field it
            does not fill draws from the generator's pool. Fixed fields are left
            to the generator's one value for the run.
            """
            out = []
            for drawn in environment_flags(count, ratio):
                identity = dict(typed)
                if drawn:
                    identity.update(draw_environment_identity(environment, skip=set(typed)))
                for field, behavior in behaviors.items():
                    if field not in identity and behavior == 'rotating':
                        identity[field] = field_defaults[field]()
                out.append(identity)
            return out

        planner = getattr(definition['generator_class'], 'plan_identities', None)
        if planner:
            # The attack decides its own events: a port scan is one source and
            # many distinct destinations, which no per-event ratio describes.
            choices = options.get('attack_identity')
            choices = choices if isinstance(choices, dict) else {}
            wants_environment = any(c.get('mode') in ('environment', 'ai') or c.get('environment')
                                    for c in choices.values() if isinstance(c, dict))
            environment = (_env_manager.attack_environment(definition.get('ai_fields', {}))
                           if wants_environment else {})
            attack_identities, noise_identities = planner(definition, options, attacks, noise, environment)
        else:
            attack_identities, noise_identities = identities(attacks), identities(noise)

        devices, shared = [], {}
        for source, fmt, delivery in selections:
            generator_options = {**options, **shared, 'render_format': fmt,
                                 'source_log_type': source['log_type']}
            generator = AttackGeneratorFactory.get_generator(attack_type, generator_options)
            if not shared:
                shared = {f'target_{field}': value
                          for field, value in generator._fixed_values.items()}
            generator = apply_delivery_format([generator], source['log_type'],
                                              delivery, destination_type)[0]
            sourcetype, wire_source = wire_metadata(source['log_type'], source['sourcetype'], fmt)
            devices.append((generator, sourcetype, wire_source))

        def spread(kind, identities, over):
            """One event per identity, dealt round-robin over `over` devices.

            Shuffled first so which device records a given probe is arbitrary
            rather than following the order the identities were planned in.
            """
            if not over:
                return []
            identities = list(identities)
            random.shuffle(identities)
            return [AttackEvent(kind, *over[index % len(over)], identity)
                    for index, identity in enumerate(identities)]

        plan = spread('attack', attack_identities, devices)
        if noise:
            plan += spread('noise', noise_identities,
                           [d for d in devices if hasattr(d[0], 'generate_noise')])

        random.shuffle(plan)
        return plan

    def _execute_sourced_attack(self, sender_id, sender_config, stop_event):
        """An attack that declares its data sources: sourcetype and source forced."""
        attack_type = sender_config['log_type']
        options = sender_config.get('options', {})
        defaults = ATTACK_REGISTRY[attack_type].get('defaults', {})
        if sender_config.get('destination_type', 'file') not in attack_destinations(ATTACK_REGISTRY[attack_type]):
            self._fail_attack(sender_id, 'Error: this attack is sent over HEC or to a file only')
            return

        # Several sourcetypes: one shape everywhere, the one HEC sends — a file
        # gets the same event bodies, not a delivery format per source.
        several = spans_several_sources(ATTACK_REGISTRY[attack_type])
        plan = self.attack_plan(attack_type, options,
                                'configuration' if several else sender_config.get('destination_type', 'file'))
        try:
            duration = int(options.get('attack_duration', defaults.get('duration', 1)))
        except (TypeError, ValueError):
            duration = defaults.get('duration', 1)
        duration = max(0, min(self.MAX_ATTACK_DURATION, duration))
        interval = duration / len(plan) if duration and plan else 0.0

        destination_type = sender_config.get('destination_type', 'file')
        # The sourcetype and source come from the selection, never from a typed
        # override: one override cannot be right for several sourcetypes, and the
        # Windows add-on classifies on `source`.
        hec_options = {k: v for k, v in options.items()
                       if k not in ('hec_sourcetype', 'hec_source',
                                    'hec_sourcetype_map', 'hec_source_map')}
        sent = 0

        try:
            if destination_type == 'file':
                dest_path = Path(sender_config['destination'])
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with dest_path.open('a', encoding='utf-8') as f:
                    for event in plan:
                        if stop_event.is_set():
                            break
                        line = event.render()
                        if several:
                            line = HECSender._parse_syslog(line)[1]
                        f.write(line + '\n')
                        f.flush()
                        sent += 1
                        self._data[sender_id]['logs_generated'] += 1
                        if interval:
                            time.sleep(interval)

            elif destination_type == 'configuration':
                config_id = sender_config.get('configuration_id')
                if not config_id:
                    self._fail_attack(sender_id, 'Error: No configuration')
                    return
                hec = self._build_hec_sender(config_id, hec_options)
                try:
                    for event in plan:
                        if stop_event.is_set():
                            break
                        if hec.send_event(event.render(), sourcetype=event.sourcetype,
                                          source=event.source, host=event.host):
                            sent += 1
                            self._data[sender_id]['logs_generated'] += 1
                        if interval:
                            time.sleep(interval)
                finally:
                    hec.close()

            elif destination_type == 'syslog':
                syslog = self._build_syslog_sender(sender_config)
                try:
                    for event in plan:
                        if stop_event.is_set():
                            break
                        if syslog.send_event(event.render()):
                            sent += 1
                            self._data[sender_id]['logs_generated'] += 1
                        if interval:
                            time.sleep(interval)
                finally:
                    syslog.close()

            completion_time = datetime.now().strftime('%m/%d %H:%M:%S')
            print(f"[Attack] Done: {sent}/{len(plan)} events")
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

    def _execute_attack(self, sender_id, sender_config, stop_event):
        """Execute a finite attack: N events spread over a duration."""
        log_type = sender_config['log_type']
        options  = sender_config.get('options', {})

        # Attacks migrated to declared data sources take the new path; the rest
        # keep this one until they are reworked.
        if ATTACK_REGISTRY.get(log_type, {}).get('data_sources'):
            return self._execute_sourced_attack(sender_id, sender_config, stop_event)

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
                with dest_path.open('a', encoding='utf-8') as f:
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
                        line, sourcetype, source = _emit(generator)
                        if hec.send_event(line, sourcetype=sourcetype, source=source):
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

    @staticmethod
    def _still_running(stop_event, deadline):
        """Whether the loop goes round again: nobody stopped it, and time is left.

        The stop event is checked first and on every pass, so a sender with a
        duration can still be stopped by hand before it runs out.
        """
        return not stop_event.is_set() and (deadline is None or time.monotonic() < deadline)

    def _generate_logs(self, sender_id, generator, sender_config, stop_event):
        """Generate logs at the configured frequency, for the configured time."""
        frequency = sender_config['frequency']
        interval  = 1.0 / frequency if frequency > 0 else 1.0
        destination_type = sender_config.get('destination_type', 'file')
        duration = max(0, int(sender_config.get('duration_seconds') or 0))
        deadline = time.monotonic() + duration if duration else None

        try:
            if destination_type == 'file':
                dest_path = Path(sender_config['destination'])
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with dest_path.open('a', encoding='utf-8') as f:
                    while self._still_running(stop_event, deadline):
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
                    while self._still_running(stop_event, deadline):
                        line, sourcetype, source = _emit(generator)
                        if hec.send_event(line, sourcetype=sourcetype, source=source):
                            self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    hec.close()

            elif destination_type == 'syslog':
                syslog = self._build_syslog_sender(sender_config)
                try:
                    while self._still_running(stop_event, deadline):
                        if syslog.send_event(generator.generate()):
                            self._data[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    syslog.close()

        except Exception as e:
            print(f"[Sender] {sender_id}: Exception: {e}")
        finally:
            # Ran its time rather than being stopped: put the sender back down,
            # so the page shows what is true and the toggle starts it again.
            if deadline is not None and not stop_event.is_set():
                sender = self._data.get(sender_id)
                if sender:
                    sender['enabled'] = False
                    self._save()
                self.threads.pop(sender_id, None)

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
        """Return metadata for all registered log types (driven by the registry).

        `avg_log_size` is measured on the generator, not read off its
        AVG_LOG_SIZE constant — every one of those was wrong, some by 100%. The
        simulation form reads it from here rather than keeping its own copy.
        """
        from simulation_manager import SimulationManager

        out = {}
        for log_type, cls in REGISTRY.items():
            meta = dict(cls.METADATA)
            meta['avg_log_size'] = SimulationManager.average_log_size(log_type)
            out[log_type] = meta
        return out
