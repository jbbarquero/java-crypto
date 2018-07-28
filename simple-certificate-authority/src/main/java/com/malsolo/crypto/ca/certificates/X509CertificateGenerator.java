package com.malsolo.crypto.ca.certificates;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;

public class X509CertificateGenerator {

    //TODO create CertificateInfo with File for keystore and so on

    public static X509CertificateHolder createTrustAnchor() {
        return null;
    }

    public static X509CertificateHolder createIntermediateCertificate() {
        return null;
    }

    public static PKCS10CertificationRequest clientCertificationRequest() {
        return null;
    }

    public static X509CertificateHolder createEndEntity(PKCS10CertificationRequest csr) {
        return null;
    }


}
