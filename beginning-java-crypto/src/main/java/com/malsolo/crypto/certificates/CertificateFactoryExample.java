package com.malsolo.crypto.certificates;

import com.malsolo.crypto.util.Utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateFactoryExample {

    public static void main(String[] args) throws GeneralSecurityException {
        KeyPair keyPair = Utils.generateRSAKeyPair();
        X509Certificate x509Certificate = X509CertificateGenerator.generateV1Certificate(keyPair);
        byte[] x509CertificateEncoded = x509Certificate.getEncoded();

        InputStream in = new ByteArrayInputStream(x509CertificateEncoded);

        // create the certificate factory
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");

        // read the certificate
        X509Certificate x509Cert = (X509Certificate)fact.generateCertificate(in);

        System.out.println("issuer: " + x509Cert.getIssuerX500Principal());


    }

}
