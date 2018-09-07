package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;
import com.malsolo.bcfipsin100.pbeks.Pem;
import com.malsolo.bcfipsin100.utilities.EC;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class CertificatesConstructorMain {

    private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";

    public static void main(String[] args) throws GeneralSecurityException, OperatorCreationException, IOException {
        Setup.installProvider();

        KeyPair trustAuthoritykeyPair = EC.generateKeyPair();
        KeyPair certificateAuthorityKeyPair = EC.generateKeyPair();
        KeyPair endEntitykeyPair = EC.generateKeyPair();

        X509Certificate trustCertificate = CertificatesConstructor.makeV1Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "Unit 1")
                        .addRDN(BCStyle.CN, "Root Certificate")
                        .build(),
                trustAuthoritykeyPair,
                SIGNATURE_ALGORITHM
        );

        X509Certificate certificateAuthorityCertificate = CertificatesConstructor.makeV3Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "Unit 1")
                        .addRDN(BCStyle.CN, "CA Certificate")
                        .build(),
                trustCertificate,
                trustAuthoritykeyPair.getPrivate(),
                certificateAuthorityKeyPair.getPublic(),
                SIGNATURE_ALGORITHM,
                true
        );

        X509Certificate endEntityCertificate = CertificatesConstructor.makeV3Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "Unit 1")
                        .addRDN(BCStyle.CN, "EE Certificate")
                        .build(),
                certificateAuthorityCertificate,
                certificateAuthorityKeyPair.getPrivate(),
                endEntitykeyPair.getPublic(),
                SIGNATURE_ALGORITHM,
                false
        );

        // this will throw an exception in case of failure to verify
        endEntityCertificate.verify(certificateAuthorityCertificate.getPublicKey());

        System.out.println("\n> END ENTITY CERTIFICATE\n");
        System.out.println(Pem.certificateToString(endEntityCertificate));
        System.out.println("\n> CA CERTIFICATE\n");
        System.out.println(Pem.certificateToString(certificateAuthorityCertificate));
        System.out.println("\n> TRUST CERTIFICATE\n");
        System.out.println(Pem.certificateToString(trustCertificate));

        //Ignoring CRL
        //Ignoring OCSP

        System.out.println(CertPathValidation.validateCertPath(
                trustCertificate, certificateAuthorityCertificate, endEntityCertificate));

    }

}
