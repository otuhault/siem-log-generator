"""Test helpers: generator construction, category coverage, and add-on regexes.

Rather than sniffing the emitted text to work out which category produced an
event (brittle), each generator family is instrumented at the dispatch seam it
already exposes. Nothing in the application is modified: the wrappers are set on
the *instance*, shadowing the class attribute for the lifetime of that instance.
"""

import re

from log_generators.registry import REGISTRY

#: An inline flag group — `(?i)` and friends, but not the scoped `(?i:…)` form.
_INLINE_FLAGS = re.compile(r"\(\?([aiLmsux]+)\)")


def pcre_to_python(pattern):
    """A Splunk regex, spelled the way Python's `re` will take it.

    Splunk runs PCRE. Two differences matter when replaying an add-on's own
    extractions over the events we generate:

    * a named group is `(?<name>…)` in PCRE and `(?P<name>…)` in Python;
    * an inline flag group like `(?i)` is legal anywhere in PCRE, applying from
      that point on. Python accepted it anywhere until 3.10, warned from 3.6,
      and since 3.11 raises "global flags not at the start of the expression".
      Splunk_TA_nix ships one mid-pattern, in [sshd-session-login-failed].

    Hoisting the flag to the front is the closest Python offers. It applies to
    the whole pattern rather than the tail, which can only make the match more
    permissive — enough for asking whether an extraction fires, which is all
    these tests ask.
    """
    converted = re.sub(r"\(\?<(?![=!])", "(?P<", pattern)
    flags = "".join(sorted(set("".join(_INLINE_FLAGS.findall(converted)))))
    if flags:
        converted = f"(?{flags}){_INLINE_FLAGS.sub('', converted)}"
    return converted


def compile_pcre(pattern):
    """`pcre_to_python`, compiled."""
    return re.compile(pcre_to_python(pattern))


def build_default_instances(log_type):
    """Instantiate a generator from its own SOURCETYPE_CONFIG defaults.

    Returns a list of (instance, fixed_category) pairs.
    `fixed_category` is the source name for multi-instance generators (one
    instance per source), and None when a single instance handles every
    category internally.
    """
    cls = REGISTRY[log_type]
    cfg = cls.SOURCETYPE_CONFIG
    defaults = cfg["defaults"]

    if cfg.get("multi_instance"):
        extra = cfg.get("extra_params_keys") or {}
        return [
            (cls(**{cfg["single_param_name"]: value}, **dict(extra)), value)
            for value in defaults
        ]

    return [(cls(**{cfg["param_key"]: list(defaults)}), None)]


def default_categories(log_type):
    return list(REGISTRY[log_type].SOURCETYPE_CONFIG["defaults"])


def install_category_spy(instance, log_type):
    """Record which default category produced each generate() call.

    Returns a set that fills in as generate() is called.
    """
    seen = set()

    if log_type == "paloalto":
        for category in ("traffic", "threat", "system"):
            _wrap_method(instance, f"_generate_{category}_log", category, seen)

    elif log_type in ("ssh", "cisco_ios"):
        _wrap_ssh_style_dispatch(instance, seen)

    elif log_type == "cisco_asa":
        for category in default_categories(log_type):
            _wrap_method(instance, f"_gen_{category}", category, seen)

    elif log_type == "active_directory":
        _wrap_ad_event_generators(instance, seen)

    elif log_type in ("auditd", "fortigate", "sysmon", "powershell"):
        # Dispatch is a dict of bound builders, so wrap the entries in place.
        for category, builder in list(instance._builders.items()):
            instance._builders[category] = _recording(builder, category, seen)

    else:
        raise AssertionError(
            f"{log_type} is multi-instance; category coverage comes from the "
            f"instance list, no spy needed"
        )

    return seen


def _recording(func, category, seen):
    """Wrap a zero-arg builder so calling it records its category."""
    def wrapped(*args, **kwargs):
        seen.add(category)
        return func(*args, **kwargs)
    return wrapped


def _wrap_method(instance, method_name, category, seen):
    original = getattr(instance, method_name)

    def wrapper(*args, **kwargs):
        seen.add(category)
        return original(*args, **kwargs)

    setattr(instance, method_name, wrapper)


def _wrap_ssh_style_dispatch(instance, seen):
    """ssh / cisco_ios both funnel through _generate_event(event_type).

    `all_event_types` maps category -> [(event_type, weight), ...], so the
    reverse lookup gives the category for the type that was dispatched.
    """
    type_to_category = {
        event_type: category
        for category, entries in instance.all_event_types.items()
        for event_type, _weight in entries
    }
    original = instance._generate_event

    def wrapper(event_type, *args, **kwargs):
        category = type_to_category.get(event_type)
        if category is not None:
            seen.add(category)
        return original(event_type, *args, **kwargs)

    instance._generate_event = wrapper


def _wrap_ad_event_generators(instance, seen):
    """active_directory picks a category then a weighted function inside it."""
    rebuilt = {}
    for category, entries in instance._event_generators.items():
        wrapped_entries = []
        for func, weight in entries:
            wrapped_entries.append((_make_recording_func(func, category, seen), weight))
        rebuilt[category] = wrapped_entries
    instance._event_generators = rebuilt


def _make_recording_func(func, category, seen):
    def wrapper(*args, **kwargs):
        seen.add(category)
        return func(*args, **kwargs)

    return wrapper
