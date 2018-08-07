package com.malsolo.crypto.tls;

import org.bouncycastle.util.encoders.Base64;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

public class UtilsCertificates {
    private static String printX509Certificate(X509Certificate x509Certificate) {
        try {
            byte[] digest = digestFromX509Certificate(x509Certificate, "MD5");
            String digestHex = DatatypeConverter
                    .printHexBinary(digestFromX509Certificate(x509Certificate, "SHA-1"))
                    .toUpperCase();

            //From https://stackoverflow.com/a/1271148
            //From http://www.javased.com/?post=1270703
            //Should try https://stackoverflow.com/a/5470268

            return String.format("[Serial: %s] MD5: %s (SHA1: %s). Owner: %s, Issuer: %s\n\tSignature Algorithm: %s [OID = %s]",
                    x509Certificate.getSerialNumber().toString(),
                    hexify(digest).toUpperCase(),
                    digestHex,
                    x509Certificate.getSubjectX500Principal().toString(),
                    x509Certificate.getIssuerX500Principal().toString(),
                    x509Certificate.getSigAlgName(),
                    x509Certificate.getSigAlgOID()
                    );
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static byte[] digestFromX509Certificate(X509Certificate x509Certificate, String algorithm) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] der = x509Certificate.getEncoded();
        md.update(der);
        return md.digest();
    }

    private static String hexify(byte bytes[]) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
            buf.append(":");
        }

        return buf.subSequence(0, buf.length()-1).toString();
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

    public static void viewKeyStoreEntries(String keyStoreType, Path keyStorePath, char[] keyStorePassword, Map<String, String> aliasAndPasswordsMap) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        System.out.printf("Key store entries for type %s at %s\n", keyStoreType, keyStorePath.toString());

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);

        try (InputStream in = Files.newInputStream(keyStorePath)) {
            keyStore.load(in, keyStorePassword);
        }
        Collections.list(keyStore.aliases()).forEach(a -> UtilsCertificates.showKeyStoreEntry(keyStore, a, aliasAndPasswordsMap.get(a)));
    }

    private static void showKeyStoreEntry(KeyStore keyStore, String alias, String keyPassword) {
        try {
            System.out.printf("Alias: %s\n", alias);
            if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                System.out.println("Private Key entry info...");
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
                System.out.printf("Private key: %s\n", Base64.toBase64String(privateKeyEntry.getPrivateKey().getEncoded()));
                privateKeyEntry.getAttributes().forEach(a -> System.out.printf("Attribute: %s=%s\n", a.getName(), a.getValue()));
                Arrays.stream(privateKeyEntry.getCertificateChain())
                        .map(X509Certificate.class::cast)
                        .map(UtilsCertificates::printX509Certificate)
                        .forEach(System.out::println);
                System.out.println("\nEnd Private Key entry info.");
            }
            else if (keyStore.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
                System.out.println("Trusted certificate entry info...");
                KeyStore.TrustedCertificateEntry trustedCertificateEntry = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(alias, null);
                System.out.printf("X509 certificate: %s\n",
                        UtilsCertificates.printX509Certificate((X509Certificate) trustedCertificateEntry.getTrustedCertificate())
                );
                trustedCertificateEntry.getAttributes().forEach(a -> System.out.printf("Attribute: %s=%s\n", a.getName(), a.getValue()));
                System.out.println("\nEnd Trusted certificate entry info.");
            }
            else {
                System.out.println("Entry: not managed.");
            }
        }
        catch (UnrecoverableEntryException | NoSuchAlgorithmException | KeyStoreException ex) {
            throw new RuntimeException(ex);
        }
    }

}
