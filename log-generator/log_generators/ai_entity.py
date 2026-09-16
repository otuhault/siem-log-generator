"""Keep the fields of one A&I entity together inside one event.

EnvironmentManager used to flatten entities into one list per field — hostnames
here, IP addresses there — and generators drew from each list independently. An
event could then claim the hostname of one machine with the IP of another, which
breaks any correlation on host/IP/MAC even though A&I holds the right pairing.

The roster keeps a record per entity instead, grouped by the part that entity
plays: `src`, `dest`, or `device`. A generator picks one record per group at the
top of each event and reads every field from the right one — so a web request can
name a real client and a real server at once, instead of forcing both ends to be
the same host or drawing each field from an unrelated one.
"""

import random


class AIEntityMixin:
    """Draw the entities an event is about, then read every field from them.

    `_ai_entity_roster` is set by EnvironmentManager.inject_into() as
    `{side: [record, ...]}`. It already carries the environment ratio: empty
    records stand for "use the generator's own defaults here", so a generator
    never has to know about mixing.

    Most pools belong to one side and resolve on their own. A pool used on both —
    a firewall reading `internal_ips` for the client and again for the server —
    is ambiguous, and the call site must say which end it means.
    """

    #: Class-level defaults, so a generator built without an environment works.
    _ai_entity_roster = {}
    _ai_pool_sides = {}

    def _new_entity(self):
        """Pick the entities this event is about. Call once, before building it."""
        roster = getattr(self, '_ai_entity_roster', None) or {}
        self._ai_entities = {side: (random.choice(records) if records else None)
                             for side, records in roster.items()}
        # Kept for callers that only ever meant "the machine the actor is on".
        self._ai_entity = self._ai_entities.get('src')
        return self._ai_entities

    def _entity_field(self, pool_name, fallback, side=None):
        """A field of the entity on `side`, or `fallback()` when there is none.

        `side` is optional while the pool belongs to one end only, which is the
        common case; pass it for a pool read on both. `fallback` is a callable so
        the generator's own random value is only computed when it is needed.
        """
        side = side or getattr(self, '_ai_pool_sides', {}).get(pool_name)
        if side:
            entity = (getattr(self, '_ai_entities', None) or {}).get(side)
            if entity:
                value = entity.get(pool_name)
                if value:
                    return value
        return fallback()
