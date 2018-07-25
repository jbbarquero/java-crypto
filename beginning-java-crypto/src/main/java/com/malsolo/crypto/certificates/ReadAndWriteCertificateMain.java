package com.malsolo.crypto.certificates;

import com.malsolo.crypto.util.Utils;
import org.bouncycastle.openssl.PEMWriter;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

public class ReadAndWriteCertificateMain {

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        Utils.installBouncyCastleProvider();

        System.out.println(">>>>> Read and write one certificate");
        readAndWriteOneCertificate();

        System.out.println(">>>>> Read and write multiple certificates");
        readAndWriteMultipleCertificates();
    }

    private static void readAndWriteOneCertificate() throws GeneralSecurityException, IOException {
        KeyPair keyPair = Utils.generateRSAKeyPair();

        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        X509Certificate x509Certificate = X509CertificateGenerator.generateV1Certificate(keyPair);

        bout.write(x509Certificate.getEncoded());

        bout.close();

        InputStream in = new ByteArrayInputStream(bout.toByteArray());

        CertificateFactory fact = CertificateFactory.getInstance("X509");

        X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(in);

        System.out.println("DER Certificate:");
        System.out.printf("[%s] issued by [%s]\n", x509Cert.getSubjectX500Principal(), x509Cert.getIssuerX500Principal());

        System.out.println("PEM Certificate:");
        bout = new ByteArrayOutputStream();
        PEMWriter pemWriter = new PEMWriter(new OutputStreamWriter(bout));
        pemWriter.writeObject(x509Certificate);
        pemWriter.close();
        bout.close();

        System.out.println(Utils.toString(bout.toByteArray()));
    }

    private static void readAndWriteMultipleCertificates() throws GeneralSecurityException, IOException {
        // create the keys
        KeyPair          pair = Utils.generateRSAKeyPair();

        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        X509Certificate x509Certificate1 = X509CertificateGenerator.generateV1Certificate(pair);
        X509Certificate x509Certificate3 = X509CertificateGenerator.generateV3Certificate(pair);

        bOut.write(x509Certificate1.getEncoded());
        bOut.write(x509Certificate3.getEncoded());

        bOut.close();

        InputStream in = new ByteArrayInputStream(bOut.toByteArray());

        // create the certificate factory
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");

        // read the certificates
        X509Certificate    x509Cert;
        Collection<X509Certificate> collection = new ArrayList<>();

        while((x509Cert = (X509Certificate)fact.generateCertificate(in)) != null) {
            collection.add(x509Cert);
        }

        collection.stream()
                .map(c -> String.format("version: %d", c.getVersion()))
                .forEach(System.out::println);

        InputStream in1 = new ByteArrayInputStream(bOut.toByteArray());
        System.out.println("Multiple in one line");
        fact.generateCertificates(in1).stream()
                .map(X509Certificate.class::cast)
                .map(x509 -> String.format("version: %d (serial: %s)", x509.getVersion(), x509.getSerialNumber().toString()))
                .forEach(System.out::println);
    }


}
