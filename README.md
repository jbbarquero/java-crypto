# SSL Server and client

$ java -Djavax.net.ssl.keyStore=certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword com.malsolo.crypto.book.tls

$ java -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLClientExample

# SSL Server and client with client authentication

$ java -Djavax.net.ssl.keyStore=certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLServerWithClientAuthExample

$ java -Djavax.net.ssl.trustStore=certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLClientWithClientAuthExample 
