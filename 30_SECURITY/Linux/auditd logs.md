Enable the EXEC monitoring to have the execv_command field, so you can then enable rules based on this field:  
NOT PERMANENT: sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_log  
PERSISTANT: **/etc/audit/rules.d/audit.rules**

-a always,exit -F arch=b64 -S execve -k exec_log  
-a always,exit -F arch=b32 -S execve -k exec_log

Same for chmod monitoring:  
 

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod