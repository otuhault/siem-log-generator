## Pre-Requisites for a Successful EP Deployment
https://help.splunk.com/en/splunk-cloud-platform/process-data-at-the-edge/use-edge-processors-for-splunk-cloud-platform/administer-edge-processors/installation-requirements-for-edge-processors

The following are detailed technical pre-requisites for a successful deployment of Edge Processor:
- Either a virtual machine or a hardware machine running a supported version of linux (
- Destination indexes (whether customer-managed Enterprise or SplunkCloud)
- Network connections between and among the various network entities
- Healthy Splunk environment (Cloud or CMP) with data flowing into indexes from existing sources

At least 20 GB, plus an additional amount of disk space per destination that the Edge Processor is configured to send data to. This additional disk space is required because Edge Processors can store queued data on the hard drive of the host machine in order to prevent data loss.

For Edge Processor instances on version 1.11.0 or higher:
- Queued data is stored in the **/splunk-edge/var/data** directory, and the queue size is determined by the Storage size configuration setting on the Edge Processor.
- You need to calculate the amount of additional disk space required by multiplying the queue size with the number of destinations.
- For example, if an Edge Processor sends data to 3 destinations and uses the default queue size of 5 GB, then you must allocate 35 GB of disk space in total. If you adjust the queue size to 7 GB, then you would need to allocate 41 GB of disk space. 

Get queue size:
```
| mstats latest(queue_max_bytes) as max_queue_size latest(queue_size_bytes) as current_queue_size
  where index=_metrics sourcetype="edge-metrics" by host, dir
| eval max_queue_MB=round(max_queue_size/1024/1024,0)
```

