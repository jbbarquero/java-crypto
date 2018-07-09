package com.malsolo.crypto.book.tls;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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
    public static void viewCertificates(SSLSession sslSession) {
        System.out.println("Certificate chain sent to the peer during the handshake");
        Certificate[] localCertificates = sslSession.getLocalCertificates();
        Arrays.stream(localCertificates)
                .map(c -> (X509Certificate) c)
                .map(UtilsCertificates::printX509Certificate)
                .forEach(System.out::println);

        System.out.println("Certificate chain received from the peer during the handshake");
        try {
            Certificate[] peerCertificates = sslSession.getPeerCertificates();
            Arrays.stream(peerCertificates)
                    .map(c -> (X509Certificate) c)
                    .map(UtilsCertificates::printX509Certificate)
                    .forEach(System.out::println);
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

}
