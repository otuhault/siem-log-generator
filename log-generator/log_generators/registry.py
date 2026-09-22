"""
Generator registry — single source of truth for all log types.

To add a new generator:
  1. Create log_generators/<name>.py with a class that defines
     LOG_TYPE, AVG_LOG_SIZE, SOURCETYPE_CONFIG, METADATA, and generate().
  2. Import the class here and add it to the GENERATORS list below.
"""

from .apache import ApacheLogGenerator
from .windows import WindowsEventLogGenerator
from .ssh import SSHAuthLogGenerator
from .paloalto import PaloAltoLogGenerator
from .active_directory import ActiveDirectoryLogGenerator
from .cisco_ios import CiscoIOSLogGenerator
from .cisco_asa import CiscoASALogGenerator
from .auditd import AuditdLogGenerator
from .zscaler import ZscalerLogGenerator
from .fortigate import FortiGateLogGenerator
from .sysmon import SysmonLogGenerator

# Ordered list of all generator classes.
GENERATORS = [
    ApacheLogGenerator,
    WindowsEventLogGenerator,
    SSHAuthLogGenerator,
    PaloAltoLogGenerator,
    ActiveDirectoryLogGenerator,
    CiscoIOSLogGenerator,
    CiscoASALogGenerator,
    ZscalerLogGenerator,
    AuditdLogGenerator,
    FortiGateLogGenerator,
    SysmonLogGenerator,
]

# log_type -> generator class
REGISTRY: dict = {cls.LOG_TYPE: cls for cls in GENERATORS}
