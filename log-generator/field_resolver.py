"""
Field Value Resolver for Attack Generators

Resolves field values based on override configuration:
- default: use the generator's built-in random logic
- static: pick from user-provided values
- list: pick from a reusable list managed in ListsManager
"""

import random


class FieldValueResolver:
    """Resolves field values from different sources based on override config"""

    def __init__(self, field_overrides, lists_manager=None):
        self.overrides = field_overrides or {}
        self.lists_manager = lists_manager
        self._fixed_cache = {}

    def resolve(self, field_name, default_fn):
        """
        Resolve a field value (called per event for varying fields).

        Args:
            field_name: Name of the field (e.g., 'user', 'src_ip')
            default_fn: Callable that returns the default value
        Returns:
            Resolved value
        """
        override = self.overrides.get(field_name)
        if not override or override.get('mode') == 'default':
            return default_fn()

        if override['mode'] == 'static':
            values = override.get('values', [])
            return random.choice(values) if values else default_fn()

        if override['mode'] == 'list':
            list_id = override.get('list_id')
            if list_id and self.lists_manager:
                lst = self.lists_manager.get_list(list_id)
                if lst and lst.get('values'):
                    return random.choice(lst['values'])
            return default_fn()

        return default_fn()

    def resolve_fixed(self, field_name, default_fn):
        """
        Resolve a field value that should be fixed once for the attack session.
        Used for 'same_*' mode fields (e.g., fixed user, fixed IP).

        Args:
            field_name: Name of the field
            default_fn: Callable that returns the default value
        Returns:
            Cached resolved value (same value on every call)
        """
        if field_name not in self._fixed_cache:
            self._fixed_cache[field_name] = self.resolve(field_name, default_fn)
        return self._fixed_cache[field_name]
