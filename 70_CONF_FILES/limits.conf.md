batch_search_max_pipeline : permet d'utiliser plusieurs coeurs cpu pour une Search (au lieu de 1 cpu par search)
[https://docs.splunk.com/Documentation/SplunkCloud/latest/Knowledge/Configurebatchmodesearch#Configure_batch_mode_search_parallelization](https://docs.splunk.com/Documentation/SplunkCloud/latest/Knowledge/Configurebatchmodesearch#Configure_batch_mode_search_parallelization)

```
[search]
max_searches_per_cpu = <int> # default: 1
base_max_searches = <int> # default: 6

[scheduler]
max_searches_perc = <int> # default: 50

auto_summary_perc = <int> # default: 50
# Max nb of concurrent searches to be allocated for auto summarization, as a % of the concurrent searches that the scheduler can run.
# Includes:
- searches for Report Acceleration Feature
- searches for Data Model Acceleration
# User scheduled searches take precedence over auto summary searches.
```

**Example**
max_searches_per_cpu = 1
number_of_cpus = 16
base_max_searches = 6
max_searches_perc = 50
auto_summary_perc = 50

1 ( 16 ) + 6 = 22 max concurrent searches
50% of 22 = 11 max scheduled searches
50% of 11 = 5 max autosummary searches

