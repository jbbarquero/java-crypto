package com.malsolo.crypto.tls;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Principal;

import static com.malsolo.crypto.tls.UtilsCertificates.viewCertificates;

/**
 * Basic SSL Server with client authentication and id checking.
 * Usage:
 * java com.malsolo.crypto.book.tls.SSLServerWithClientAuthIdExample
 */
public class SSLServerWithClientAuthIdExample extends SSLServerExample {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromUtils/";
    private static final String KEYSTORE_FILE_NAME = Utils.SERVER_NAME + ".jks";
    private static final char[] KEYSTORE_PASSWORD = Utils.SERVER_PASSWORD;
    private static final char[] KEYSTORE_KEY_PASSWORD = Utils.SERVER_PASSWORD;
    private static final String TRUSTSTORE_FILE_NAME = Utils.TRUST_STORE_NAME + ".jks";
    private static final char[] TRUSTSTORE_PASSWORD = Utils.TRUST_STORE_PASSWORD;
    private static final String EXPECTED_ENTITY_NAME = Utils.END_ENTITY_CERTIFICATE_SUBJECT_DN;

    /**
     * Check that the principal we have been given is for the end entity.
     */
    private static boolean isEndEntity(SSLSession session) throws SSLPeerUnverifiedException {
        Principal id = session.getPeerPrincipal();
        if (id instanceof X500Principal) {
            X500Principal x500 = (X500Principal)id;

            System.out.println(x500.getName());
            return x500.getName().equals(EXPECTED_ENTITY_NAME);
        }

        return false;
    }

    /**
     * Create an SSL context with identity and trust stores in place
     */
    private static SSLContext createSSLContext(File keystoreFile, char[] keystorePassword, char[] keystoreKeyPasword,
                                               File trustoreFile, char[] truststorePassword) throws Exception {
        // set up a key manager for our local credentials
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore serverStore = KeyStore.getInstance("JKS");

        serverStore.load(new FileInputStream(keystoreFile), keystorePassword);

        mgrFact.init(serverStore, keystoreKeyPasword);

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
        SSLContext sslContext = createSSLContext(
                Paths.get(CERTS_PATH + KEYSTORE_FILE_NAME).toFile(), KEYSTORE_PASSWORD, KEYSTORE_KEY_PASSWORD,
                Paths.get(CERTS_PATH + TRUSTSTORE_FILE_NAME).toFile(), TRUSTSTORE_PASSWORD);

        // create the server socket
        SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Constants.PORT_NO);

        sSock.setNeedClientAuth(true);

        SSLSocket sslSock = (SSLSocket)sSock.accept();

        sslSock.startHandshake();

        // process if principal checks out
        SSLSession sslSession = sslSock.getSession();
        viewCertificates(sslSession);
        if (isEndEntity(sslSession)) {
            System.out.println("doProtocol");
            doProtocol(sslSock);
        }

    }

}
