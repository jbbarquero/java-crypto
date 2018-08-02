package com.malsolo.crypto.tls;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;

import static com.malsolo.crypto.tls.UtilsCertificates.viewCertificates;

/**
 * SSL Client with client-side authentication.
 * Usage:
 * java com.malsolo.crypto.book.tls.SSLClientWithClientAuthTrustExample
 */
public class SSLClientWithClientAuthTrustExample extends SSLClientExample {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromUtils/";
    private static final String KEYSTORE_FILE_NAME = "client.p12";
    private static final char[] KEYSTORE_PASSWORD = Utils.CLIENT_PASSWORD;
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String TRUSTSTORE_FILE_NAME = "trustStore.jks";

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
                Paths.get(CERTS_PATH + KEYSTORE_FILE_NAME).toFile(),
                Paths.get(CERTS_PATH + TRUSTSTORE_FILE_NAME).toFile());
        SSLSocketFactory fact = sslContext.getSocketFactory();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Constants.HOST, Constants.PORT_NO);

        cSock.startHandshake();

        viewCertificates(cSock.getSession());

        doProtocol(cSock);

    }

}
