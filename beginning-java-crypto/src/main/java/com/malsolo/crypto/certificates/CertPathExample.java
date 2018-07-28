package com.malsolo.crypto.certificates;

import com.malsolo.crypto.book.tls.Utils2;
import com.malsolo.crypto.util.Utils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static com.malsolo.crypto.certificates.PKCS10CertRequestWithBouncyCastle160Example.caBuildCertificateChainFromRequest;
import static com.malsolo.crypto.certificates.PKCS10CertRequestWithBouncyCastle160Example.clientCertificationRequest;

public class CertPathExample {

    public static void main(String[] args) throws Exception {
        Utils.installBouncyCastleProvider();

        /*
        X509Certificate[] chain = PKCS10CertCreateExample.buildChain();
Exception in thread "main" java.lang.IllegalArgumentException: unknown object in factory: org.bouncycastle.asn1.x509.Attribute
	at org.bouncycastle.asn1.pkcs.Attribute.getInstance(Unknown Source)
	at org.bouncycastle.asn1.pkcs.CertificationRequestInfo.validateAttributes(Unknown Source)
	at org.bouncycastle.asn1.pkcs.CertificationRequestInfo.<init>(Unknown Source)
	at org.bouncycastle.asn1.pkcs.CertificationRequestInfo.<init>(Unknown Source)
	at org.bouncycastle.jce.PKCS10CertificationRequest.<init>(Unknown Source)
	at org.bouncycastle.jce.PKCS10CertificationRequest.<init>(Unknown Source)
	at com.malsolo.crypto.certificates.PKCS10CertRequestExample.generateRequestWithExtensions(PKCS10CertRequestExample.java:94)
	at com.malsolo.crypto.certificates.PKCS10CertCreateExample.buildChain(PKCS10CertCreateExample.java:42)
	at com.malsolo.crypto.certificates.CertPathExample.main(CertPathExample.java:14)
        * */

        KeyPair rootPair = Utils.generateRSAKeyPair();

        X509Certificate rootCert = createRootCert(rootPair);
        X509Certificate[] chain = buildChain(rootCert, rootPair);

        // create the factory and path object
        CertificateFactory  fact = CertificateFactory.getInstance("X.509", "BC");
        CertPath certPath = fact.generateCertPath(Arrays.asList(chain));

        byte[] encoded = certPath.getEncoded("PEM");

        System.out.println(Utils.toString(encoded));

        // re-read the CertPath
        CertPath           newCertPath = fact.generateCertPath(new ByteArrayInputStream(encoded), "PEM");

        if (newCertPath.equals(certPath)) {
            System.out.println("CertPath recovered correctly");
        }

        validate(certPath, rootCert);
    }

    private static X509Certificate createRootCert(KeyPair rootPair) throws Exception {
        X509CertificateHolder certificateHolder = Utils2.createTrustAnchor(rootPair, "SHA256WithRSAEncryption");
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
    }

    private static X509Certificate[] buildChain(X509Certificate rootCert, KeyPair rootPair) throws Exception {
        KeyPair certPair = Utils.generateRSAKeyPair();
        return caBuildCertificateChainFromRequest(clientCertificationRequest(certPair), rootCert, "SHA256WithRSAEncryption", rootPair.getPrivate());
    }

    private static void validate(CertPath certPath, X509Certificate rootCert) throws Exception {

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(rootCert, null));

        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date());

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");

        try {
            PKIXCertPathValidatorResult result =
                    (PKIXCertPathValidatorResult)validator.validate(certPath, param);
            System.out.println("validated: " + result.getPublicKey());
        }
        catch (CertPathValidatorException e) {
            System.out.println("validation failed: index ("
                    + e.getIndex() + "), reason \"" + e.getMessage() + "\"");
        }
    }

}
