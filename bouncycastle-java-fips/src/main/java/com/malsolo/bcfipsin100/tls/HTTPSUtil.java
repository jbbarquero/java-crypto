package com.malsolo.bcfipsin100.tls;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Stream;

@SuppressWarnings("WeakerAccess")
public class HTTPSUtil {

    public static final String CERTS_PATH = "bouncycastle-java-fips/certsFromUtils0/";

    public static SSLContext createSSLContext(File keyStoreFile, char[] keyStorePassword, String keyStoreType,
                                               File trustStoreFile, char[] trustStorePassword, String trustStoreType) throws Exception {
        // First initialize the key and trust material
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
            keyStore.load(fis, keyStorePassword);
        }

        KeyStore trustStore = KeyStore.getInstance(trustStoreType);
        try (FileInputStream fis = new FileInputStream(trustStoreFile)) {
            trustStore.load(fis, trustStorePassword);
        }

        // KeyManagers decide which key material to use
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, keyStorePassword);

        // TrustManagers decide whether to allow connections
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null); //SecureRandom.getInstance("DEFAULT", Setup.PROVIDER);

        return sslContext;
    }

    public static void viewCertificates(SSLSession sslSession) {
        System.out.println("\n>>>>> Certificate chain sent to the peer during the handshake");
        Certificate[] localCertificates = sslSession.getLocalCertificates();
        if (localCertificates == null) {
            System.out.println("No certificates were sent to the peer during handshake");
        }
        else {
            Stream.of(localCertificates)
                    .map(c -> (X509Certificate) c)
                    .map(HTTPSUtil::printX509Certificate)
                    .forEach(System.out::println);
        }

        System.out.println("\n>>>>> Certificate chain received from the peer during the handshake");
        try {
            Certificate[] peerCertificates = sslSession.getPeerCertificates();
            if (peerCertificates == null) {
                throw new RuntimeException("No certificates were received from the peer during handshake");
            }
            Arrays.stream(peerCertificates)
                    .map(c -> (X509Certificate) c)
                    .map(HTTPSUtil::printX509Certificate)
                    .forEach(System.out::println);
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            //throw new RuntimeException(e);
        }
    }

    private static String printX509Certificate(X509Certificate x509Certificate) {
        return String.format("[Serial: %s] Owner: %s, Issuer: %s\n\tSignature Algorithm: %s [OID = %s]",
                x509Certificate.getSerialNumber().toString(),
                x509Certificate.getSubjectX500Principal().toString(),
                x509Certificate.getIssuerX500Principal().toString(),
                x509Certificate.getSigAlgName(),
                x509Certificate.getSigAlgOID()
        );

    }

    }
