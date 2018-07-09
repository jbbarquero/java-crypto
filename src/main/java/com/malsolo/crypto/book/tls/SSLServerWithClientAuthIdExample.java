package com.malsolo.crypto.book.tls;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

/**
 * Basic SSL Server with client authentication and id checking.
 */
public class SSLServerWithClientAuthIdExample extends SSLServerExample {


    private static String printX509Certificate(X509Certificate x509Certificate) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] der = x509Certificate.getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            String digestHex = DatatypeConverter.printHexBinary(digest);
            return digestHex.toLowerCase();
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * View certificates exchanged during the handshake.
     */
    private static void viewCertificates(SSLSession sslSession) {
        System.out.println("Certificate chain sent to the peer during the handshake");
        Certificate[] localCertificates = sslSession.getLocalCertificates();
        Arrays.stream(localCertificates)
                .map(c -> (X509Certificate) c)
                .map(SSLServerWithClientAuthIdExample::printX509Certificate)
                .forEach(System.out::println);

        System.out.println("Certificate chain received from the peer during the handshake");
        try {
            Certificate[] peerCertificates = sslSession.getPeerCertificates();
            Arrays.stream(peerCertificates)
                    .map(c -> (X509Certificate) c)
                    .map(SSLServerWithClientAuthIdExample::printX509Certificate)
                    .forEach(System.out::println);
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * Check that the principal we have been given is for the end entity.
     */
    private static boolean isEndEntity(SSLSession session) throws SSLPeerUnverifiedException {
        Principal id = session.getPeerPrincipal();
        if (id instanceof X500Principal) {
            X500Principal x500 = (X500Principal)id;

            System.out.println(x500.getName());
            return x500.getName().equals("CN=Test End Certificate");
        }

        return false;
    }

    /**
     * Create an SSL context with identity and trust stores in place
     */
    private static SSLContext createSSLContext(File serverJksFile, File trustoreFile) throws Exception {
        // set up a key manager for our local credentials
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore serverStore = KeyStore.getInstance("JKS");

        serverStore.load(new FileInputStream(serverJksFile), Utils.SERVER_PASSWORD);

        mgrFact.init(serverStore, Utils.SERVER_PASSWORD);

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
        SSLContext sslContext = createSSLContext(
                Paths.get("certsFromUtils/server.jks").toFile(),
                Paths.get("certsFromUtils/trustStore.jks").toFile());

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
