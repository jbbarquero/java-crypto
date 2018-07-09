package com.malsolo.crypto.book.tls;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * SSL Client with client-side authentication.
 */
public class SSLClientWithClientAuthTrustExample extends SSLClientExample {
    /**
     * Create an SSL context with both identity and trust store
     */
    private static SSLContext createSSLContext(File clientStoreP12File, File trustoreFile) throws Exception {
        // set up a key manager for our local credentials
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore clientStore = KeyStore.getInstance("PKCS12");

        clientStore.load(new FileInputStream(clientStoreP12File), Utils.CLIENT_PASSWORD);

        mgrFact.init(clientStore, Utils.CLIENT_PASSWORD);

        // set up a trust manager so we can recognize the server
        TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
        KeyStore            trustStore = KeyStore.getInstance("JKS");

        trustStore.load(new FileInputStream(trustoreFile), Utils.TRUST_STORE_PASSWORD);

        trustFact.init(trustStore);

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);

        return sslContext;
    }

    public static void main(String[] args) throws Exception {
        SSLContext       sslContext = createSSLContext(
                Paths.get("certsFromUtils/client.p12").toFile(),
                Paths.get("certsFromUtils/trustStore.jks").toFile());
        SSLSocketFactory fact = sslContext.getSocketFactory();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Constants.HOST, Constants.PORT_NO);

        doProtocol(cSock);

    }

}
