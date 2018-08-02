package com.malsolo.crypto.tls;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

public class UtilsCertificates {
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
    static void viewCertificates(SSLSession sslSession) {
        System.out.println("Certificate chain sent to the peer during the handshake");
        Certificate[] localCertificates = sslSession.getLocalCertificates();
        if (localCertificates == null) {
            System.out.println("Server doesn't require client authentication");
        }
        else {
            Arrays.stream(localCertificates)
                    .map(c -> (X509Certificate) c)
                    .map(UtilsCertificates::printX509Certificate)
                    .forEach(System.out::println);
        }

        System.out.println("Certificate chain received from the peer during the handshake");
        try {
            Certificate[] peerCertificates = sslSession.getPeerCertificates();
            if (peerCertificates == null) {
                throw new RuntimeException("Server doesn't send certificates");
            }
            Arrays.stream(peerCertificates)
                    .map(c -> (X509Certificate) c)
                    .map(UtilsCertificates::printX509Certificate)
                    .forEach(System.out::println);
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static void print(String storeType, String storePath, String storePassword) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(storeType);
        try (InputStream in = Files.newInputStream(Paths.get(storePath))) {
            keyStore.load(in, storePassword.toCharArray());
        }
        Collections.list(keyStore.aliases()).forEach(System.out::println);
    }

}
