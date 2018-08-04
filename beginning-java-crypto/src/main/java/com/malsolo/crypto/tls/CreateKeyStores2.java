package com.malsolo.crypto.tls;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static com.malsolo.crypto.tls.Utils2.*;

public class CreateKeyStores2 {

    private static final String TRUST_CERT_NAME = "trustCert";
    private static final String CA_CERT_NAME = "caCert";

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

        writeCertificate(Paths.get(TRUST_CERT_NAME + ".cer"), trustCert.getEncoded());
        Utils2.createPemFile(trustCert, Paths.get(TRUST_CERT_NAME + ".pem"), "Trust PEM Public certificate");
        System.out.println("····· Trust certificate created");

        //CA Certificate with Extensions
        KeyPair caKp = kpGen.generateKeyPair();

        X509CertificateHolder caCertHolder =
                createIntermediateCertificate(trustCertHolder,
                        trustKp.getPrivate(),
                        "SHA256withECDSA", caKp.getPublic(), 0);

        X509Certificate caCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(caCertHolder);

        writeCertificate(Paths.get(CA_CERT_NAME + ".cer"), caCert.getEncoded());
        Utils2.createPemFile(trustCert, Paths.get(CA_CERT_NAME + ".pem"), "CA PEM Public certificate");
        System.out.println("····· CA certificate created");

        //End Entity Certificate
        KeyPair endKp = kpGen.generateKeyPair();

        X509CertificateHolder endCertHolder = createEndEntity(caCertHolder, caKp.getPrivate(), "SHA256withECDSA",
                        endKp.getPublic(), Utils2.END_ENTITY_CERTIFICATE_SUBJECT_DN);

        X509Certificate endCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(endCertHolder);

        //Certificate chain (array) for the client
        Certificate[] certificates4Client = {endCert, caCert, trustCert};

        writeCertificate(Paths.get(Utils2.CLIENT_NAME + ".cer"), endCert.getEncoded());
        Utils2.createPemFile(trustCert, Paths.get(Utils2.CLIENT_NAME + "_PK.pem"), "Client PEM Private Key");
        Utils2.createPemFile(Paths.get(Utils2.CLIENT_NAME + "_Certs.pem"), "Client PEM Public certificate", certificates4Client);
        System.out.println("····· Client certificate created");

        //Server Entity Certificate
        KeyPair serverKp = kpGen.generateKeyPair();

        X509CertificateHolder serverCertHolder = createEndEntity(caCertHolder, caKp.getPrivate(), "SHA256withECDSA",
                        serverKp.getPublic(), Utils2.END_SERVER_CERTIFICATE_SUBJECT_DN);

        X509Certificate serverCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(serverCertHolder);

        //Certificate chain (array) for the server
        Certificate[] certificates4Server = {serverCert, caCert, trustCert};

        writeCertificate(Paths.get(Utils2.SERVER_NAME + ".cer"), endCert.getEncoded());
        Utils2.createPemFile(trustCert, Paths.get(Utils2.SERVER_NAME + "_PK.pem"), "Server PEM Private Key");
        Utils2.createPemFile(Paths.get(Utils2.SERVER_NAME + "_Certs.pem"), "Server PEM Public certificate", certificates4Server);
        System.out.println("····· Server certificate created");

        //Write certificates and keystores

        // client credentials
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry(Utils2.CLIENT_NAME, endKp.getPrivate(), Utils2.CLIENT_PASSWORD, certificates4Client);

        Path clientP12Path = Paths.get(Utils2.CLIENT_NAME + ".p12");
        try(OutputStream outputStream = Files.newOutputStream(clientP12Path)) {
            keyStore.store(outputStream, Utils2.CLIENT_PASSWORD);
        }
        System.out.printf("····· PKCS12 client key store created: %s\n", clientP12Path.toString());

        // trust store
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry(Utils2.TRUST_STORE_NAME_ENTRY, trustCert);

        Path trustJksPath = Paths.get(Utils2.TRUST_STORE_NAME + ".jks");
        try(OutputStream outputStream = Files.newOutputStream(trustJksPath)) {
            keyStore.store(outputStream, Utils2.TRUST_STORE_PASSWORD);
        }
        System.out.printf("····· Trust store created: %s\n", trustJksPath.toString());

        // server credentials
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setKeyEntry(Utils2.SERVER_NAME, trustKp.getPrivate(), Utils2.SERVER_PASSWORD, certificates4Server);

        keyStore.store(new FileOutputStream(Utils2.SERVER_NAME + ".jks"), Utils2.SERVER_PASSWORD);
        Path serverJksPath = Paths.get(Utils2.SERVER_NAME + ".jks");
        try(OutputStream outputStream = Files.newOutputStream(serverJksPath)) {
            keyStore.store(outputStream, Utils2.SERVER_PASSWORD);
        }
        System.out.printf("····· Server store created: %s\n", serverJksPath.toString());
    }

}
