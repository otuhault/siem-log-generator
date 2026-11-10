```
KV Store changed status to failed. Failed to start KV Store process. See mongod.log and splunkd.log for details..

Failed to start KV Store process. See mongod.log and splunkd.log for details.
```

https://splunk.my.site.com/customer/s/article/ERROR-KV-Store-changed-status-to-failed
https://splunk.my.site.com/customer/s/article/Migration-of-KVstore-to-Wired-Tiger-status-got-failed

```
chmod -R 400 $SPLUNK_HOME/var/lib/splunk/kvstore/mongo/splunk.key
```
```
openssl x509 -enddate -noout -in ./server.pem
```


```bash
$SPLUNK_HOME/bin/splunk btool server list --debug | grep -i -E "serverCert|sslKeysPath|sslRootCAPath|caCertFile"


openssl x509 -in <chemin_du_pem> -noout -ext extendedKeyUsage,keyUsage,subjectAltName

```
Si la sortie donne uniquement `TLS Web Server Authentication` → cause confirmée.


```none
$SPLUNK_HOME/bin/splunk btool server list sslConfig --debug | grep -i serverCert
$SPLUNK_HOME/bin/splunk show kvstore-status | grep -w status
```

KV Store issue on DS01 and LM01

Following the investigation of the KV Store errors ("KV Store changed status to failed" / "Failed to start KV Store process"), here is a summary of the findings.

The mongod process (KV Store) starts correctly, but splunkd cannot authenticate to it over TLS on port 8191:

SSLHandshakeFailed: SSL peer certificate validation failed: unsuitable certificate purpose

The certificate currently configured under [sslConfig] serverCert (/opt/splunk/etc/auth/snfcerts/combinedcert.pem) has the following Extended Key Usage:

X509v3 Extended Key Usage:  
    TLS Web Server Authentication

MongoDB requires TLS Web Client Authentication (clientAuth) on the certificate that splunkd presents when it connects to the KV Store as a client. With serverAuth only, mongod rejects every connection. There is no Splunk or mongod option to bypass this check.

Secondary (non-blocking) issue: the certificate SAN does not include localhost / 127.0.0.1, which produces the warning "The server certificate does not match the remote host name".

Why SH01 works and DS01 / LM01 do not:

The certificate file is present on all three servers, but it is not actually applied on SH01 — the two lines are commented out in /opt/splunk/etc/system/local/server.conf:

[sslConfig]

sslPassword = $7$PdEOr9luNMn3AdHhYub1vilD7M9ctBNFPt3eKgRtBxu1NHM7hDuE/A==

# PS Splunk 24/11/2025 Add serverCert and caCertFile

#serverCert = /opt/splunk/etc/auth/snfcerts/combinedcert.pem

#caCertFile = /opt/splunk/etc/auth/snfcerts/rootcert.pem

#sslPassword =

The Splunk default certificate (server.pem) contains no EKU extension at all, which means all usages are implicitly allowed — this is why mongod accepts it.

The correlation is exact and reproducible: SNF certificate active in [sslConfig] → KV Store fails.

Recommended fix (target solution):

Have the SNF PKI re-issue the certificate with the correct attributes:

Copy Code

extendedKeyUsage = serverAuth, clientAuth  
keyUsage         = critical, digitalSignature, keyEncipherment  
subjectAltName   = DNS:*.snfchina.com, DNS:splunk.snfchina.com, DNS:localhost, IP:127.0.0.1  
basicConstraints = CA:FALSE

A CSR can be generated from the existing private key. Please note that many CAs override the CSR extensions with their own template values — the request must therefore explicitly specify both serverAuth and clientAuth (in AD CS, a "Computer" style template rather than "Web Server").

Once the new certificate is in place, the configuration can be re-enabled on all three nodes and the SNF certificate will finally be active on port 8089 everywhere.

Interim workaround and its consequences:

To restore the KV Store immediately on DS01 and LM01, the two lines can be commented out (same state as SH01), then restart Splunk. This takes a couple of minutes and reliably brings the KV Store back to ready.

Consequences to be accepted if we go this route:

- Management port 8089 reverts to the Splunk self-signed certificate on those nodes. Any client validating the server certificate (sslVerifyServerCert = true) will fail — this affects forwarders, deployment clients, and external API / monitoring integrations.
- Certificate name validation against *.snfchina.com no longer applies on 8089; any tooling pinned to that name or to the SNF root CA must be reviewed.
- The compliance objective of the 24/11/2025 change (no self-signed certificates on internal Splunk communications) is not met — this should be documented as a temporary deviation, not a permanent state.
- Splunk Web is not affected: it uses its own certificate declared in web.conf (snfchina.com.pem / snfchina.com.key), which is independent from [sslConfig].
- The workaround must be reverted once the corrected certificate is available, otherwise the two configurations will drift apart across nodes again.

