# Export keys and certificates

## Export client key and cert in PEM format

From https://security.stackexchange.com/a/66865

$ cd certsFromUtils

$ openssl pkcs12 -in client.p12 -nokeys -out client_cert.pem
Enter Import Password:
MAC verified OK

$ openssl pkcs12 -in client.p12 -nodes -nocerts -out client_key.pem
Enter Import Password:
MAC verified OK

### The same for BC160 example

$ cd certsFromUtils2
$ openssl pkcs12 -in client2.p12 -nokeys -out client_cert2.pem
$ openssl pkcs12 -in client2.p12 -nodes -nocerts -out client_key2.pem

##  Export server cert in PEM format

From https://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html#keytool_option_exportcert

Or, from 
https://www.cloudera.com/documentation/enterprise/5-10-x/topics/cm_sg_openssl_jks.html#convert_der_cert
https://www.cloudera.com/documentation/enterprise/5-10-x/topics/cm_sg_openssl_jks.html#concept_ek3_sdl_rp

$ keytool -exportcert -keystore trustStore.jks -alias trust -storepass trustPassword -file trust.pem -rfc
Certificate stored in file <trust.pem>

### The same for BC160 example

$ keytool -exportcert -keystore trustStore2.jks -alias trust2 -storepass trustPassword2 -file trust2.pem -rfc
Certificate stored in file <trust.pem>

# Useful programs

## Wiremock
$ java -jar wiremock-standalone-2.18.0.jar --port=0 --https-port=9443 --https-keystore=certsBC/server.jks --keystore-password=serverPassword --https-truststore=certsBC/trustStore.jks --truststore-password=trustPassword --https-require-client-cert=true

## Curl
$ curl https://localhost:9443/hello/world --cert ./certsBC/client_cert.pem  --key ./certsBC/client_key.pem --cacert ./certsBC/trust.pem -v

# Notes:
https://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html#CHDGGFEG
https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SupportClasses
https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#TrustManagerFactory

https://isc.sans.edu/diary/Manual+Verification+of+SSLTLS+Certificate+Trust+Chains+using+Openssl/8686

https://curl.haxx.se/docs/manpage.html
http://wiremock.org/docs/running-standalone/


