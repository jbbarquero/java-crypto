package com.malsolo.bcfipsin100.pbeks;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Pem {

    @SuppressWarnings("Duplicates")
    public static String certificateToString(X509Certificate certificate) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);

        pemWriter.writeObject(certificate);
        pemWriter.close();

        return stringWriter.toString();
    }

    public static X509Certificate stringToCertificate(String pemEncoding) throws IOException, CertificateException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        X509CertificateHolder certHolder = (X509CertificateHolder)parser.readObject();

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    @SuppressWarnings("Duplicates")
    public static String privateKeyToString(PrivateKey privateKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);

        pemWriter.writeObject(privateKey);
        pemWriter.close();

        return stringWriter.toString();
    }

    public static PrivateKey stringToPrivateKey(String pemEncoding) throws IOException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();

        return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
    }

    public static PKCS10CertificationRequest certificationRequestToString(String pemEncoding) throws IOException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));

        PemObject pemObject = parser.readPemObject();

        return new PKCS10CertificationRequest(pemObject.getContent());
    }


}
