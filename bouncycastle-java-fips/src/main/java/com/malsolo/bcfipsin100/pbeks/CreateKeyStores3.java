package com.malsolo.bcfipsin100.pbeks;

import com.malsolo.bcfipsin100.Setup;
import com.malsolo.bcfipsin100.certs.CertificatesConstructor;
import com.malsolo.bcfipsin100.utilities.EC;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static com.malsolo.bcfipsin100.pbeks.KeyStoreUtil.storeCertificate;

@SuppressWarnings("WeakerAccess")
public class CreateKeyStores3 {

    private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";

    public static final String SERVER_STORE_NAME_JKS = "server3.jks";
    public static final String SERVER_STORE_NAME_P12 = "server3.p12";
    public static final char[] SERVER_STORE_PASSWORD = "serverPassword3".toCharArray();
    public static final String SERVER_STORE_NAME_ENTRY = "server3";

    public static final String CLIENT_STORE_NAME_P12 = "client3.p12";
    public static final String CLIENT_STORE_NAME_JKS = "client3.jks";
    public static final char[] CLIENT_STORE_PASSWORD = "clientPassword3".toCharArray();
    public static final String CLIENT_STORE_NAME_ENTRY = "client3";

    public static final String TRUST_CERTIFICATE_CER_FILE = "trust_cer3.cer";
    public static final String TRUST_CERTIFICATE_PEM_FILE = "trust_cer3.pem";
    public static final String TRUST_PRIVATE_KEY_PEM_FILE = "trust_key3.pem";
    public static final String TRUST_STORE_NAME = "trustStore3.jks";
    public static final char[] TRUST_STORE_PASSWORD = "trustPassword3".toCharArray();
    public static final String TRUST_STORE_NAME_ENTRY = "trust3";

    public static final String CA_CERTIFICATE_CER_FILE = "ca_cer3.cer";
    public static final String CA_CERTIFICATE_PEM_FILE = "ca_cer3.pem";
    public static final String CA_PRIVATE_KEY_PEM_FILE = "ca_key3.pem";

    public static final String END_SERVER_CERTIFICATE_CER_FILE = "server_cer3.cer";
    public static final String END_SERVER_CERTIFICATE_SUBJECT_DN = "localhost";
    public static final String END_SERVER_CERTIFICATE_PEM_FILE = "server_cer3.pem";
    public static final String END_SERVER_PRIVATE_KEY_PEM_FILE = "server_key3.pem";

    public static final String END_CLIENT_CERTIFICATE_CER_FILE = "client_cer3.cer";
    public static final String END_CLIENT_CERTIFICATE_SUBJECT_DN = "clienthost";
    public static final String END_CLIENT_CERTIFICATE_PEM_FILE = "client_cer3.pem";
    public static final String END_CLIENT_PRIVATE_KEY_PEM_FILE = "client_key3.pem";


    public static void main(String[] args) throws Exception {

        System.out.println(">>>>> Create keystores (part III)...");

        Setup.installProvider();

        KeyPair trustAuthorityKeyPair = EC.generateKeyPair();
        KeyPair certificateAuthorityKeyPair = EC.generateKeyPair();
        KeyPair serverKeyPair = EC.generateKeyPair();
        KeyPair clientKeyPair = EC.generateKeyPair();

        X509Certificate trustCertificate = CertificatesConstructor.makeV1Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "Unit Root")
                        .addRDN(BCStyle.CN, "Global Root CA")
                        .build(),
                trustAuthorityKeyPair,
                SIGNATURE_ALGORITHM
        );
        X509Certificate certificateAuthorityCertificate = CertificatesConstructor.makeV3Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "Unit Server CA")
                        .addRDN(BCStyle.CN, "Server CA")
                        .build(),
                trustCertificate,
                trustAuthorityKeyPair.getPrivate(),
                certificateAuthorityKeyPair.getPublic(),
                SIGNATURE_ALGORITHM,
                true
        );
        X509Certificate serverCertificate = CertificatesConstructor.makeV3Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "SERVER Unit End Entity")
                        .addRDN(BCStyle.CN, END_SERVER_CERTIFICATE_SUBJECT_DN)
                        .build(),
                certificateAuthorityCertificate,
                certificateAuthorityKeyPair.getPrivate(),
                serverKeyPair.getPublic(),
                SIGNATURE_ALGORITHM,
                false
        );
        X509Certificate clientCertificate = CertificatesConstructor.makeV3Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "CLIENT Unit End Entity")
                        .addRDN(BCStyle.CN, END_CLIENT_CERTIFICATE_SUBJECT_DN)
                        .build(),
                certificateAuthorityCertificate,
                certificateAuthorityKeyPair.getPrivate(),
                clientKeyPair.getPublic(),
                SIGNATURE_ALGORITHM,
                false
        );

        writePemFiles(
                trustAuthorityKeyPair, trustCertificate,
                certificateAuthorityKeyPair, certificateAuthorityCertificate,
                serverKeyPair, serverCertificate,
                clientKeyPair, clientCertificate
        );

        writeCertificates(trustCertificate, certificateAuthorityCertificate, serverCertificate, clientCertificate);

        createStores(
                trustCertificate, certificateAuthorityCertificate,
                serverKeyPair, serverCertificate,
                clientKeyPair, clientCertificate
        );

        System.out.println(">>>>> Create keystores (part III). Done.");
    }

    private static void writePemFiles(KeyPair trustAuthoritykeyPair, X509Certificate trustCertificate,
                                      KeyPair certificateAuthorityKeyPair, X509Certificate certificateAuthorityCertificate,
                                      KeyPair serverKeyPair, X509Certificate serverCertificate,
                                      KeyPair clientKeyPair, X509Certificate clientCertificate
    ) throws IOException {
        System.out.println("Write PEM Files...");

        writePemPrivateKey(trustAuthoritykeyPair.getPrivate(), Paths.get(TRUST_PRIVATE_KEY_PEM_FILE), "TRUST PRIVATE KEY");
        writePemCertificate(trustCertificate, Paths.get(TRUST_CERTIFICATE_PEM_FILE), "TRUST CERTIFICATE");

        writePemPrivateKey(certificateAuthorityKeyPair.getPrivate(), Paths.get(CA_PRIVATE_KEY_PEM_FILE), "CA PRIVATE KEY");
        writePemCertificate(certificateAuthorityCertificate, Paths.get(CA_CERTIFICATE_PEM_FILE), "CA CERTIFICATE");

        writePemPrivateKey(serverKeyPair.getPrivate(), Paths.get(END_SERVER_PRIVATE_KEY_PEM_FILE), "SERVER PRIVATE KEY");
        writePemCertificate(serverCertificate, Paths.get(END_SERVER_CERTIFICATE_PEM_FILE), "SERVER CERTIFICATE");

        writePemPrivateKey(clientKeyPair.getPrivate(), Paths.get(END_CLIENT_PRIVATE_KEY_PEM_FILE), "CLIENT PRIVATE KEY");
        writePemCertificate(clientCertificate, Paths.get(END_CLIENT_CERTIFICATE_PEM_FILE), "CLIENT CERTIFICATE");

        System.out.println("Write PEM Files. Done.");
    }

    private static void writePemPrivateKey(PrivateKey privateKey, Path privateKeyPath, String logMessage) throws IOException {
        String privateKeyPem = Pem.privateKeyToString(privateKey);
        Files.write(privateKeyPath, privateKeyPem.getBytes());
        System.out.printf("····· %s at %s ·····\n%s\n", logMessage, privateKeyPath.toString(), privateKeyPem);
    }

    private static void writePemCertificate(X509Certificate certificate, Path certificatePath, String logMessage) throws IOException {
        String certificatePem = Pem.certificateToString(certificate);
        Files.write(certificatePath, certificatePem.getBytes());
        System.out.printf("····· %s at %s ·····\n%s\n", logMessage, certificatePath.toString(), certificatePem);
    }

    private static void writeCertificates(
            X509Certificate trustCertificate,
            X509Certificate certificateAuthorityCertificate,
            X509Certificate serverCertificate,
            X509Certificate clientCertificate
    ) throws GeneralSecurityException, IOException {
        System.out.println("Write Certificates...");

        writeCertificate(trustCertificate, Paths.get(TRUST_CERTIFICATE_CER_FILE), "TRUST CERTIFICATE");
        writeCertificate(certificateAuthorityCertificate, Paths.get(CA_CERTIFICATE_CER_FILE), "CA CERTIFICATE");
        writeCertificate(serverCertificate, Paths.get(END_SERVER_CERTIFICATE_CER_FILE), "SERVER CERTIFICATE");
        writeCertificate(clientCertificate, Paths.get(END_CLIENT_CERTIFICATE_CER_FILE), "CLIENT CERTIFICATE");

        System.out.println("Write Certificates. Done.");
    }

    private static void writeCertificate(X509Certificate certificate,  Path certificatePath, String logMessage) throws CertificateEncodingException, IOException {
        Files.write(certificatePath, certificate.getEncoded());
        System.out.printf("····· %s at %s ·····\n", logMessage, certificatePath.toString());
    }

    private static void createStores(X509Certificate trustCertificate, X509Certificate certificateAuthorityCertificate, KeyPair serverKeyPair, X509Certificate serverCertificate, KeyPair clientKeyPair, X509Certificate clientCertificate) throws GeneralSecurityException, IOException {
        System.out.println("Create stores...");

        //Trust store
        Path trustJksPath = Paths.get(TRUST_STORE_NAME);
        storeCertificate(trustCertificate, TRUST_STORE_NAME_ENTRY, trustJksPath, TRUST_STORE_PASSWORD);
        System.out.printf("····· Trust store created: %s\n", trustJksPath.toString());

        //Server credentials
        Path serverJksPath = Paths.get(SERVER_STORE_NAME_JKS);
        X509Certificate[] serverCertificateChain = {serverCertificate, certificateAuthorityCertificate, trustCertificate};
        KeyStoreUtil.storePrivateKey(
                serverKeyPair.getPrivate(), serverCertificateChain,
                SERVER_STORE_NAME_ENTRY, serverJksPath, SERVER_STORE_PASSWORD
        );
        System.out.printf("····· Server store created in JKS: %s\n", serverJksPath.toString());

        Path serverP12Path = Paths.get(SERVER_STORE_NAME_P12);
        KeyStoreUtil.storePrivateKeyPkcs12(
                serverKeyPair.getPrivate(), serverCertificateChain,
                SERVER_STORE_NAME_ENTRY, serverP12Path, SERVER_STORE_PASSWORD
        );
        System.out.printf("····· Server store created in PKCS12: %s\n", serverP12Path.toString());

        //Client credentials
        X509Certificate[] clientCertificateChain = {clientCertificate, certificateAuthorityCertificate, trustCertificate};
        Path clientJksPath = Paths.get(CLIENT_STORE_NAME_JKS);
        KeyStoreUtil.storePrivateKey(
                clientKeyPair.getPrivate(), clientCertificateChain,
                CLIENT_STORE_NAME_ENTRY, clientJksPath, CLIENT_STORE_PASSWORD
        );
        System.out.printf("····· Client store created in JKS: %s\n", clientJksPath.toString());

        Path clientP12Path = Paths.get(CLIENT_STORE_NAME_P12);
        KeyStoreUtil.storePrivateKeyPkcs12(
                clientKeyPair.getPrivate(), clientCertificateChain,
                CLIENT_STORE_NAME_ENTRY, clientP12Path, CLIENT_STORE_PASSWORD
        );
        System.out.printf("····· Client store created in PKCS12: %s\n", clientP12Path.toString());

        System.out.println("Create stores. Done.");
    }

}
