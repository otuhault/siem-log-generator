### ◆◆◆ Stretched SHC
- SHC is not built for High Availability but for High Performance. It will fail for one of the following reasons:
	- Latency>100ms will kill the KV Store
	- KV Store size. As it increases, higher chance of errors or interference on the network when transferring large KV Store.
	- Search load. If several searches are spread across multiple sites and a site goes down, all those searches get dumped on the remaining site. In the workst case, the captain election will occur at the same time, then all the users will be overloaded, amd problems will chained together.
- Splunk does not support a stretched SHC.
#### Recommendations
Latency between 2 sites should be around or less than 30ms. This is usually achievable on single site SHC and is likely fine on AWS as well.
A large KV Store will involve a poor replication, added to a low latency will make Splunk to fail.
Documentation about the stretched Search Head Cluster can be found [here](https://help.splunk.com/en/splunk-enterprise-security-8/install/8.4/installation/install-splunk-enterprise-security-in-a-search-head-cluster-environment).

