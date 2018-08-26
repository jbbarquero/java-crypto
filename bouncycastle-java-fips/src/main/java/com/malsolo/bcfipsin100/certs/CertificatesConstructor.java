package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

public class CertificatesConstructor {

    private static long serialNumberBase = System.currentTimeMillis();

    public static X509Certificate makeV1Certificate(X500Name issuer, KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, CertificateException {

        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                issuer,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(60),
                issuer,
                keyPair.getPublic());

        //SHA384withECDSA
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(Setup.PROVIDER).build(keyPair.getPrivate());

        X509CertificateHolder certHldr = certBldr.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider(Setup.PROVIDER)
                .getCertificate(certHldr);
    }

    public static X509Certificate makeV3Certificate(X500Name subject, X509Certificate caCertificate, PrivateKey caPrivateKey, PublicKey eePublicKey, String signatureAlgorithm) throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                new JcaX509CertificateHolder(caCertificate).getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(366),
                subject,
                eePublicKey);

        //
        // extensions
        //
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertBldr.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCertificate));

        v3CertBldr.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(eePublicKey));

        v3CertBldr.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false));

        //"SHA384withECDSA"
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(Setup.PROVIDER)
                .build(caPrivateKey);

        X509CertificateHolder certHldr = v3CertBldr.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider(Setup.PROVIDER)
                .getCertificate(certHldr);
    }

    private static BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }

    private static Date calculateDate(int daysInFuture) {
        return Date.from(LocalDateTime
                .now()
                .plus(daysInFuture, ChronoUnit.DAYS)
                .atZone(ZoneId.systemDefault())
                .toInstant()
        );
    }
}
