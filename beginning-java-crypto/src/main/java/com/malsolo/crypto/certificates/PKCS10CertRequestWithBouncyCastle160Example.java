package com.malsolo.crypto.certificates;

import com.malsolo.crypto.book.tls.Utils2;
import com.malsolo.crypto.util.Utils;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static com.malsolo.crypto.book.tls.Utils2.*;

public class PKCS10CertRequestWithBouncyCastle160Example {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromCSR";

    public static PKCS10CertificationRequest clientCertificationRequest(KeyPair certPair) throws Exception {
        return PKCS10CertRequestExample.createPKCS10WithExtensions(certPair, "SHA256withRSA");
    }

    public static X509Certificate[] caBuildCertificateChainFromRequest(PKCS10CertificationRequest request, X509Certificate rootCert, String signatureAlgorithm, PrivateKey privateKey) throws Exception {
        // validate the certification request
        if (!isValidPKCS10Request(request)) {
            System.out.println("request failed to verify!");
            System.exit(1);
        }

        PublicKey requestPublicKey = new JcaPEMKeyConverter().getPublicKey(request.getSubjectPublicKeyInfo());

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                new JcaX509CertificateHolder(rootCert).getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                request.getSubject(),
                requestPublicKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certificateBuilder
                .addExtension(Extension.authorityKeyIdentifier,
                        false, extUtils.createAuthorityKeyIdentifier(rootCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(request.getSubjectPublicKeyInfo()))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature
                                | KeyUsage.keyCertSign
                                | KeyUsage.cRLSign));

        Consumer<Attribute> processExtensionRequest = (attribute) -> {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));

                Arrays.stream(extensions.getExtensionOIDs()).forEach(
                        asn1ObjectIdentifier -> {
                            Extension extension = extensions.getExtension(asn1ObjectIdentifier);
                            try {
                                certificateBuilder.addExtension(asn1ObjectIdentifier, extension.isCritical(), extension.getExtnValue().getOctets());
                            } catch (CertIOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
            }
        };
        Arrays.stream(request.getAttributes()).forEach(processExtensionRequest);

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(privateKey);

        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(signer);

        X509Certificate certificateFromRequest = new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);

        return new X509Certificate[]{certificateFromRequest, rootCert};
    }

    private static boolean isValidPKCS10Request(PKCS10CertificationRequest pkcs10Request)
            throws OperatorCreationException, PKCSException {
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(pkcs10Request.getSubjectPublicKeyInfo());

        return pkcs10Request.isSignatureValid(verifierProvider);
    }

    private static void caSendCertificateChainToClient(X509Certificate[] certificateChain) throws IOException {
        JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(System.out));

        final AtomicInteger i = new AtomicInteger(0);
        Arrays.stream(certificateChain).forEach(certificate -> {
            try {
                pemWriter.writeObject(certificate);
                writeCertificate(
                        Paths.get(String.format("%s/cert%d.cer", CERTS_PATH, i.getAndIncrement())),
                        certificate.getEncoded());
            } catch (IOException | CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        });

        pemWriter.close();
    }

    public static X509CertificateHolder createRootCertificate(KeyPair keyPair, String sigAlg)
            throws OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo")
                .addRDN(BCStyle.CN, "Root Certificate");

        X500Name name = x500NameBld.build();

        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                name,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(keyPair.getPrivate());

        return certBldr.build(signer);

    }

    private static void createKeyStores(X509Certificate[] buildChain, KeyPair certPair) throws Exception {
        // PKCS12 key store
        System.out.println("····· Creating PKCS12 key store...");

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry("server", certPair.getPrivate(), "password".toCharArray(), buildChain);

        Path keystorePkcs12 = Paths.get(CERTS_PATH, "keystore.p12");
        try(OutputStream outputStream = Files.newOutputStream(keystorePkcs12)) {
            keyStore.store(outputStream, "password".toCharArray());
        }

        keyStore.store(new FileOutputStream(CERTS_PATH + "/keystore.p12"), "password".toCharArray());

        System.out.printf("····· PKCS12 key store created: %s\n", keystorePkcs12.toString());

        // JKS key store
        System.out.println("····· Creating JKS key store...");

        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setKeyEntry("server", certPair.getPrivate(), "password".toCharArray(), buildChain);

        Path keystoreJks = Paths.get(CERTS_PATH, "keystore.jks");
        try(OutputStream outputStream = Files.newOutputStream(keystoreJks)) {
            keyStore.store(outputStream, "password".toCharArray());
        }

        System.out.printf("····· JKS key store created: %s\n", keystoreJks.toString());

        // trust store
        System.out.println("····· Creating JKS trust store...");

        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry("server", buildChain[buildChain.length - 1]);

        Path truststoreJks = Paths.get(CERTS_PATH, "truststore.jks");
        try(OutputStream outputStream = Files.newOutputStream(truststoreJks)) {
            keyStore.store(outputStream, "changeit".toCharArray());
        }

        System.out.printf("····· JKS trust store created: %s\n", truststoreJks.toString());

    }

    public static void main(String[] args) throws Exception {
        Utils.installBouncyCastleProvider();

        // create a root certificate
        KeyPair rootPair = Utils.generateRSAKeyPair();

        X509CertificateHolder certificateHolder = Utils2.createTrustAnchor(rootPair, "SHA256WithRSAEncryption");
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

        KeyPair certPair = Utils.generateRSAKeyPair();
        X509Certificate[] buildChain = caBuildCertificateChainFromRequest(clientCertificationRequest(certPair), rootCert, "SHA256WithRSAEncryption", rootPair.getPrivate());

        caSendCertificateChainToClient(buildChain);

        createKeyStores(buildChain, certPair);

    }

}
