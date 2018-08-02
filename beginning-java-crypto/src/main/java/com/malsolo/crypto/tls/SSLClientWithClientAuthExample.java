package com.malsolo.crypto.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * SSL Client with client-side authentication.
 * Usage:
 * java -Djavax.net.ssl.trustStorePassword=beginning-java-crypto/certsFromUtils/trustStore.jks com.malsolo.crypto.book.tls.SSLClientWithClientAuthExample
 */
public class SSLClientWithClientAuthExample extends SSLClientExample {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromUtils";

    /**
     * Create an SSL context with a KeyManager providing our identity
     */
    private static SSLContext createSSLContext(File clientStoreFile, String clientStoreType) throws Exception {
        // set up a key manager for our local credentials
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore clientStore = KeyStore.getInstance(clientStoreType);

        clientStore.load(new FileInputStream(clientStoreFile), Utils.CLIENT_PASSWORD);

        mgrFact.init(clientStore, Utils.CLIENT_PASSWORD);

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(mgrFact.getKeyManagers(), null, null);

        return sslContext;
    }

    public static void main(String[] args) throws Exception {
        UtilsCertificates.print("JKS", System.getProperty("javax.net.ssl.trustStore"), "trustPassword");

        SSLContext sslContext = createSSLContext(Paths.get(CERTS_PATH + "/client.p12").toFile(), "PKCS12");
        SSLSocketFactory fact = sslContext.getSocketFactory();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Constants.HOST, Constants.PORT_NO);

        doProtocol(cSock);
    }
}
