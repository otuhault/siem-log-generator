"""Coherence between the generator registry, the package exports and TA_REGISTRY."""

import importlib

import log_generators
from log_generators.registry import GENERATORS, REGISTRY
from ta_registry import TA_REGISTRY, list_tas

EXPECTED_LOG_TYPES = {
    "active_directory", "apache",
    "auditd", "cisco_asa", "cisco_ios",
    "fortigate", "paloalto", "powershell", "ssh", "sysmon", "windows",
    "zscaler",
}

EXPECTED_CLASS_NAMES = {
    "ActiveDirectoryLogGenerator", "ApacheLogGenerator",
    "AuditdLogGenerator", "CiscoASALogGenerator",
    "CiscoIOSLogGenerator",
    "PaloAltoLogGenerator", "SSHAuthLogGenerator", "WindowsEventLogGenerator",
    "ZscalerLogGenerator",
    "FortiGateLogGenerator", "SysmonLogGenerator", "PowerShellLogGenerator",
}


def test_registry_and_generators_hold_the_same_classes():
    """REGISTRY is derived from GENERATORS and must not drift from it."""
    assert set(REGISTRY.values()) == set(GENERATORS)
    assert len(REGISTRY) == len(GENERATORS) == 12
    assert set(REGISTRY) == EXPECTED_LOG_TYPES
    assert {cls.__name__ for cls in GENERATORS} == EXPECTED_CLASS_NAMES


def test_registry_keys_match_each_class_log_type():
    for log_type, cls in REGISTRY.items():
        assert cls.LOG_TYPE == log_type, (
            f"REGISTRY key {log_type!r} disagrees with {cls.__name__}.LOG_TYPE={cls.LOG_TYPE!r}"
        )


def test_every_generator_declares_the_contract_log_senders_relies_on():
    for log_type, cls in REGISTRY.items():
        assert hasattr(cls, "LOG_TYPE"), f"{log_type}: missing LOG_TYPE"
        assert hasattr(cls, "AVG_LOG_SIZE"), f"{log_type}: missing AVG_LOG_SIZE"
        assert hasattr(cls, "SOURCETYPE_CONFIG"), f"{log_type}: missing SOURCETYPE_CONFIG"
        assert hasattr(cls, "METADATA"), f"{log_type}: missing METADATA"

        cfg = cls.SOURCETYPE_CONFIG
        assert isinstance(cfg.get("defaults"), list) and cfg["defaults"]
        if cfg.get("multi_instance"):
            assert cfg.get("single_param_name"), (
                f"{log_type}: multi_instance requires single_param_name"
            )


def test_every_generator_is_importable_from_package_root():
    """`from log_generators import <AnyGenerator>` works for each one (audit §8.8)."""
    module = importlib.reload(log_generators)
    missing = sorted(name for name in EXPECTED_CLASS_NAMES if not hasattr(module, name))
    assert not missing, f"not exported from log_generators: {missing}"


def test_package_all_matches_what_the_package_actually_exports():
    """Whatever __all__ advertises must genuinely be importable."""
    for name in getattr(log_generators, "__all__", []):
        assert hasattr(log_generators, name), f"__all__ advertises missing {name!r}"


def test_every_ta_registry_entry_maps_to_a_known_log_type():
    """Each TA key is a REGISTRY log_type, so a sourcetype is always reachable."""
    unknown = sorted(set(list_tas()) - set(REGISTRY))
    assert not unknown, f"TA_REGISTRY keys with no generator: {unknown}"


def test_every_sourcetype_is_reachable_from_a_log_type():
    """Walk TA -> sourcetypes and confirm the owning generator exists."""
    reachable = 0
    for ta_name, ta in TA_REGISTRY.items():
        assert ta_name in REGISTRY, f"{ta_name} has no generator"
        sourcetypes = ta.get("sourcetypes", [])
        assert sourcetypes, f"{ta_name} declares no sourcetype"
        for sourcetype in sourcetypes:
            assert sourcetype.get("name"), f"{ta_name} has an unnamed sourcetype"
            assert isinstance(sourcetype.get("datamodels", []), list)
            reachable += 1
    assert reachable == 22, f"expected 22 sourcetypes in the registry, found {reachable}"


def test_generator_declared_sourcetypes_exist_in_ta_registry():
    """When METADATA.sources declares a `sourcetype`, the TA must know it."""
    checked = 0
    for log_type, cls in REGISTRY.items():
        declared = {
            source["sourcetype"]
            for source in cls.METADATA.get("sources", [])
            if source.get("sourcetype")
        }
        if not declared:
            continue                     # bridge not populated yet (audit §8.18)
        known = {st["name"] for st in TA_REGISTRY[log_type]["sourcetypes"]}
        unknown = sorted(declared - known)
        assert not unknown, f"{log_type}: generator claims sourcetypes absent from TA_REGISTRY: {unknown}"
        checked += len(declared)
    assert checked > 0, "no generator declares a sourcetype bridge at all"
