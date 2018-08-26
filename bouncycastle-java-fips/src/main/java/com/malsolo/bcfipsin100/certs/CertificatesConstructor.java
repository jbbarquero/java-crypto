package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class CertificatesConstructor {

    private static long serialNumberBase = System.currentTimeMillis();

    public static X509Certificate makeV1Certificate(KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, CertificateException {

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo")
                .addRDN(BCStyle.OU, "Unit 1")
                .addRDN(BCStyle.CN, "Root Certificate");

        X500Name name = x500NameBld.build();

        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(60),
                name,
                keyPair.getPublic());

        //SHA384withECDSA
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(Setup.PROVIDER).build(keyPair.getPrivate());

        X509CertificateHolder certHldr = certBldr.build(signer);

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
