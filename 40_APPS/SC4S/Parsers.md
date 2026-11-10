Simple example:
`/opt/sc4s/local/config/app_parsers/ibm_cos.conf`
```conf
block parser ibm_cos-custom-parser() {
    channel {
        rewrite {
            r_set_splunk_dest_default(
                index("ibm_cos")
                sourcetype("ibm:cos:syslog")
                vendor("IBM")
                product("COS")
            );
        };
    };
};

application ibm_cos-custom-parser[sc4s-network-source] {
    filter {
        program("dsnet" type(string))
        and host("S3OSLSAC" type(string) flags(prefix))
    };
    parser { ibm_cos-custom-parser(); };
};
```
If *dnsnet* is found in event and host is *S3OSLSAC*, values from **rewrite** are set.

