package com.malsolo.bcfipsin100.pbeks;

import com.malsolo.bcfipsin100.Setup;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeyStoreUtil {

    private static final String KEYSTORE_TYPE = "JKS"; //"BCFKS"
    private static final String KEYSTORE_TYPE_PKCS12 = "PKCS12"; //"BCFKS"

    public static void storeCertificate(X509Certificate certificate, String alias, Path storePath, char[] storePassword) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, Setup.PROVIDER);

        keyStore.load(null, null);

        keyStore.setCertificateEntry(alias, certificate);

        try (OutputStream outputStream = Files.newOutputStream(storePath)) {
            keyStore.store(outputStream, storePassword);
        }
    }

    public static void storePrivateKey(PrivateKey privateKey, X509Certificate[] certificateChain, String alias, Path storePath, char[] storePassword) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, Setup.PROVIDER);

        keyStore.load(null, null);

        keyStore.setKeyEntry(alias, privateKey, storePassword, certificateChain);

        try (OutputStream outputStream = Files.newOutputStream(storePath)) {
            keyStore.store(outputStream, storePassword);
        }
    }

    public static void storePrivateKeyPkcs12(PrivateKey privateKey, X509Certificate[] certificateChain, String alias, Path storePath, char[] storePassword) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12, Setup.PROVIDER);

        keyStore.load(null, null);

        keyStore.setKeyEntry(alias, privateKey, null, certificateChain);

        try (OutputStream outputStream = Files.newOutputStream(storePath)) {
            keyStore.store(outputStream, storePassword);
        }
    }
}
