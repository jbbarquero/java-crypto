# SSL Server and client

$ java -Djavax.net.ssl.keyStore=certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword com.malsolo.crypto.book.tls

$ java -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLClientExample

# SSL Server and client with client authentication

$ java -Djavax.net.ssl.keyStore=certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLServerWithClientAuthExample

$ java -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLClientWithClientAuthExample 

# SSL client with client authentication and trust manager info

As before
$ java -Djavax.net.ssl.keyStore=certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLServerWithClientAuthExample

$ java com.malsolo.crypto.book.tls.SSLClientWithClientAuthTrustExample 

# SSL client with client authentication and trust manager info, SSL Server with trust manager info and managing SSLSession info

As before
$ java com.malsolo.crypto.book.tls.SSLServerWithClientAuthIdExample

$ java com.malsolo.crypto.book.tls.SSLClientWithClientAuthTrustExample 
