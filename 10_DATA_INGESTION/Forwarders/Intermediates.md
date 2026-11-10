# Intermediate Universal Forwarder a bad practice
Using Universal forwarder as intermediate forwarder for source universal forwarders can cause
- Wrongly merged events(data munging)
- Missing events
- Endless event duplication loop(same event duplicated endlessly  until IUF is stopped).
- Permanently blocked tcpout queue.
- Blocked replication queues( for hours no thruput ) due to IUF corrupting pipeline channels.

Few scenarios explained in .conf19 slides.
[https://conf.splunk.com/files/2019/slides/FN1570.pdf](https://conf.splunk.com/files/2019/slides/FN1570.pdf "https://conf.splunk.com/files/2019/slides/FN1570.pdf")

Reason for all these issues, intermediate  universal forwarder is not  designed to handle partial events and that causes several hard to troubleshoot problems.

Solution is to use UF->HF→IDX OR UF→IDX topology.