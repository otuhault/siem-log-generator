I need to make something clear on UEBA, it is not a replacement for UBA, it is a black box tool that provides a very specific set of use cases based on a very specific set of data sources. We do not provide workarounds for it, we cannot customise it, any changes made to it will effectively break the support of UEBA.

This is a different type of tool that needs a different mindset, it is not a pull it apart and make it work Splunk tool, it is a Cisco appliance designed to do a specific function, and it should not be used or sold as anything but that.

If UEBA has been described to "X" customer in any other way the above, that will need correcting. Let me know if you need further clarification.

![[Pasted image 20260902172623.png]]

On-prem and Cloud are 2 different products.

UEBA:
1. summary gen feeds ueba_summaries
2. searches run on ueba_summaries and add context/risk scoring
3. ers search + ueba searches to create intermediate findings


DA-ESS-UEBA App for checking health
**ERS execution**
Percentage of successful ERS execution can't be 100% on SHC.
Average ERS search run time (last 7 days): over 20s starts to be important

Entity list is a lookup used in UEBA dashboard - Display
A rule removes it from the Risk -


Macros to put data into the summary indexes - (don't exist on cloud).
Can't touch the UEBA saved searches -
Risk exclusion rules - service account
if user_category not in summary -


Golden Rules Before You Touch Anything  
1. **Don't edit detections directly** — especially in Cloud/CMP. Direct edits break upgrade paths. Always use the designated macros. But I have seen that some of the Authentication based detections do not cover the login_type for Authentication data model, so you may need to validate that by checking feature gen search.
2. **Respect the baseline** — if a detection hasn't completed its learning period, noisy output is _expected_, not a tuning target. Tune too early and you'll mask real threats later. But it depends that how much days it has been for your customer since the detections were enabled.
3. **Work in layers** — Pre-detection filtering → Post-detection filtering → Risk exclusion rules. Move from surgical to broad.

- **Specific detection generating FPs for known-benign users/devices -->** Use the `<detection_name>_filter` macro (e.g., `aws_compromised_account_filter`). Find it in Settings → All Configurations, Owner=Any, App=`DA-ESS-UEBAContent`
- Scores staying too low or too flat --> Check entity cardinality per bunit — peer groups need ≥5 members to produce meaningful statistical outliers
- **Service accounts** — if they're generating behavioral anomalies, exclude them from UEBA via A&I (set `category=service_account`) rather than suppressing individual detections one by one
- **VPN/proxy IPs** — common source of "unusual access" FPs; add to the relevant filter macro
- **Recently onboarded users** — they'll naturally fire "first-time" detections; consider a 30-day grace window via risk exclusion rules before scoring new hires
- **Check enabled vs. useful** — disable detections that don't have the required data sources feeding them (they produce empty/garbage output that still counts against ERS success metrics)


