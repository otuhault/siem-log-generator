
# Fix SOAR - ES pairing SSL error (self-signed CA)
```
# 1. Extraire le CA SOAR depuis la chaîne TLS
openssl s_client -connect 192.168.1.223:8443 -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/{i++} i==2' > /tmp/soar_ca.pem

openssl x509 -in /tmp/soar_ca.pem -noout -subject -issuer -dates

# 2. Valider que ce CA suffit  -> attendu: Verify return code: 0 (ok)
openssl s_client -connect 192.168.1.223:8443 -CAfile /tmp/soar_ca.pem </dev/null 2>/dev/null \
  | grep "Verify return code"

# 3. Identifier le bundle réellement utilisé par requests (en user splunk)
su - splunk -c '/opt/splunk/bin/splunk cmd python3 -c "
import ssl,certifi,os
print(certifi.where())
print(os.environ.get(\"SSL_CERT_FILE\"), os.environ.get(\"REQUESTS_CA_BUNDLE\"))"'

# 4. Ajouter le CA dans certifi (en root, droits w manquants)
SPLUNK_HOME=/opt/splunk
CERTIFI=$SPLUNK_HOME/lib/python3.13/site-packages/certifi/cacert.pem
chmod u+w "$(dirname "$CERTIFI")" "$CERTIFI"
cp "$CERTIFI" "$CERTIFI.bak"
{ echo; cat /tmp/soar_ca.pem; } >> "$CERTIFI"
chown splunk:splunk "$CERTIFI" "$CERTIFI.bak"

# 5. Créer le fichier attendu par SSL_CERT_FILE (absent par défaut)
mkdir -p $SPLUNK_HOME/openssl
cp "$CERTIFI" $SPLUNK_HOME/openssl/cert.pem
chown -R splunk:splunk $SPLUNK_HOME/openssl

# 6. (optionnel) bundles ES
cp $SPLUNK_HOME/etc/auth/cacert.pem{,.bak} && { echo; cat /tmp/soar_ca.pem; } >> $SPLUNK_HOME/etc/auth/cacert.pem
cp $SPLUNK_HOME/etc/auth/appsCA.pem{,.bak} && { echo; cat /tmp/soar_ca.pem; } >> $SPLUNK_HOME/etc/auth/appsCA.pem

# 7. Vérifier l'ajout  -> 2 matches (subject+issuer, CA auto-signé) = OK
openssl crl2pkcs7 -nocrl -certfile "$CERTIFI" | openssl pkcs7 -print_certs -noout | grep -c "CN *= *SoarCA"

# 8. Test  -> attendu 200 ou 401
su - splunk -c '/opt/splunk/bin/splunk cmd python3 -c "import requests;print(requests.get(\"https://192.168.1.223:8443/rest/version\").status_code)"'

# 9. Restart puis relancer le pairing
su - splunk -c '/opt/splunk/bin/splunk restart'
```
