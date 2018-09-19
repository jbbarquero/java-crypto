package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ReadCertificate {

    public static void main(String[] args) throws IOException, CertificateException, NoSuchProviderException {
        Setup.installProvider();

        Path path = Paths.get("bouncycastle-java-fips/certsFromUtils3/client_cer3.cer");
        byte[] x509CertificateBytes = Files.readAllBytes(path);

        CertificateFactory factory = CertificateFactory.getInstance("X.509", Setup.PROVIDER);

        try (InputStream in = new ByteArrayInputStream(x509CertificateBytes)) {
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);

            System.out.println(certificate);
        }
    }
}
