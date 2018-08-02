package com.malsolo.crypto.tls;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static com.malsolo.crypto.tls.Utils2.*;

public class CreateKeyStores2 {

    public static void main(String[] args) throws OperatorCreationException, GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        // Basic Public Key Certificate
        KeyPair trustKp = kpGen.generateKeyPair();
        X509CertificateHolder trustCertHolder =
                createTrustAnchor(trustKp, "SHA256withECDSA");

        X509Certificate trustCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(trustCertHolder);

        writeCertificate(Paths.get("trustCert.cer"), trustCert.getEncoded());

        //CA Certificate with Extensions
        KeyPair caKp = kpGen.generateKeyPair();

        X509CertificateHolder caCertHolder =
                createIntermediateCertificate(trustCertHolder,
                        trustKp.getPrivate(),
                        "SHA256withECDSA", caKp.getPublic(), 0);

        X509Certificate caCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(caCertHolder);

        writeCertificate(Paths.get("caCert.cer"), caCert.getEncoded());

        //End Entity Certificate
        KeyPair endKp = kpGen.generateKeyPair();

        X509CertificateHolder endCertHolder =
                createEndEntity(caCertHolder, caKp.getPrivate(),
                        "SHA256withECDSA",
                        caKp.getPublic());

        X509Certificate endCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(endCertHolder);

        writeCertificate(Paths.get("endCert.cer"), endCert.getEncoded());

        // client credentials
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry(Utils2.CLIENT_NAME, endKp.getPrivate(), Utils2.CLIENT_PASSWORD,
                new java.security.cert.Certificate[] { endCert, caCert, trustCert });

        keyStore.store(new FileOutputStream(Utils2.CLIENT_NAME + ".p12"), Utils2.CLIENT_PASSWORD);

        // trust store for client
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry(Utils2.SERVER_NAME, trustCert);

        keyStore.store(new FileOutputStream(Utils2.TRUST_STORE_NAME + ".jks"), Utils2.TRUST_STORE_PASSWORD);

        // server credentials
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setKeyEntry(Utils2.SERVER_NAME, trustKp.getPrivate(), Utils2.SERVER_PASSWORD,
                new Certificate[] { trustCert });

        keyStore.store(new FileOutputStream(Utils2.SERVER_NAME + ".jks"), Utils2.SERVER_PASSWORD);
    }

}
