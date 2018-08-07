package com.malsolo.crypto.tls;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;

import static com.malsolo.crypto.tls.UtilsCertificates.viewCertificates;

/**
 * SSL Client with client-side authentication.
 * Usage:
 * java com.malsolo.crypto.book.tls.SSLClientWithClientAuthTrustExample
 */
public class SSLClientWithClientAuthTrustExample extends SSLClientExample {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromUtils2/";
    private static final String KEYSTORE_FILE_NAME = Utils2.CLIENT_NAME + ".p12";
    private static final char[] KEYSTORE_PASSWORD = Utils2.CLIENT_PASSWORD;
    private static final String KEYSTORE_KEY_ALIAS = Utils2.CLIENT_NAME;
    private static final char[] KEYSTORE_KEY_PASSWORD = Utils2.CLIENT_PASSWORD;
    private static final String TRUSTSTORE_FILE_NAME = Utils2.TRUST_STORE_NAME + ".jks";
    private static final char[] TRUSTSTORE_PASSWORD = Utils2.TRUST_STORE_PASSWORD;

    /**
     * Create an SSL context with both identity and trust store
     */
    private static SSLContext createSSLContext(File clientStoreP12File, char[] keystorePassword, char[] keystoreKeyPasword,
                                               File trustoreFile, char[] truststorePassword) throws Exception {
        // set up a key manager for our local credentials
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore clientStore = KeyStore.getInstance("PKCS12");

        clientStore.load(new FileInputStream(clientStoreP12File), keystorePassword);

        mgrFact.init(clientStore, keystoreKeyPasword);

        // set up a trust manager so we can recognize the server
        TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
        KeyStore            trustStore = KeyStore.getInstance("JKS");

        trustStore.load(new FileInputStream(trustoreFile), truststorePassword);

        trustFact.init(trustStore);

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);

        return sslContext;
    }

    public static void main(String[] args) throws Exception {
        Path keyStorePath = Paths.get(CERTS_PATH + KEYSTORE_FILE_NAME);
        Path trustStorePath = Paths.get(CERTS_PATH + TRUSTSTORE_FILE_NAME);

        SSLContext       sslContext = createSSLContext(
                keyStorePath.toFile(), KEYSTORE_PASSWORD, KEYSTORE_KEY_PASSWORD,
                trustStorePath.toFile(), TRUSTSTORE_PASSWORD);

        System.out.println("Client key stores being used:");
        UtilsCertificates.viewKeyStoreEntries("PKCS12", keyStorePath, KEYSTORE_PASSWORD,
                new HashMap<String, String>() {{ put(KEYSTORE_KEY_ALIAS, new String(KEYSTORE_KEY_PASSWORD)); }}); //See CreateKeyStores2
        UtilsCertificates.viewKeyStoreEntries("JKS", trustStorePath, TRUSTSTORE_PASSWORD, new HashMap<>());

        System.out.println("Client: create the Socket");
        SSLSocketFactory fact = sslContext.getSocketFactory();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Constants.HOST, Constants.PORT_NO);

        //System.out.println("Server: enabled cipher suites");
        //Arrays.stream(cSock.getEnabledCipherSuites()).forEach(System.out::println);

        System.out.println("Client: start handshake");
        cSock.startHandshake();

        System.out.println("Client: processing...");

        viewCertificates(cSock.getSession());

        doProtocol(cSock);

        System.out.println("Client: processing. Done.");
    }

}
