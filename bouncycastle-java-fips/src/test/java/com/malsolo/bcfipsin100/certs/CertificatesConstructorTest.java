package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class CertificatesConstructorTest {

    @BeforeClass
    public static void installProvider() {
        Setup.installProvider();
    }

    @Test
    public void makeV1CertificateTest() throws Exception {
        //Given
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", Setup.PROVIDER);
        KeyPair trustKp = kpGen.generateKeyPair();

        //And
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo")
                .addRDN(BCStyle.OU, "Unit 1")
                .addRDN(BCStyle.CN, "Root Certificate");
        X500Name name = x500NameBld.build();

        //When
        X509Certificate x509Certificate = CertificatesConstructor.makeV1Certificate(name, trustKp, "SHA256withECDSA");

        //Then
        assertThat(x509Certificate).isNotNull();
        x509Certificate.checkValidity(new Date());
        x509Certificate.verify(x509Certificate.getPublicKey());
    }

    @Test
    public void makeV3CertificateTest() throws Exception {
        //Given
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", Setup.PROVIDER);
        KeyPair endKp = kpGen.generateKeyPair();
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo")
                .addRDN(BCStyle.OU, "Unit 1")
                .addRDN(BCStyle.CN, "Root Certificate");
        X500Name name = x500NameBld.build();

        //And
        KeyPair trustKp = kpGen.generateKeyPair();
        X500NameBuilder trustX500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo")
                .addRDN(BCStyle.OU, "Unit 1")
                .addRDN(BCStyle.CN, "localhost");
        X500Name issuer = trustX500NameBld.build();
        X509Certificate rootCertificate = CertificatesConstructor.makeV1Certificate(issuer, trustKp, "SHA256withECDSA");

        //When
        X509Certificate x509Certificate = CertificatesConstructor.makeV3Certificate(name, rootCertificate, trustKp.getPrivate(), endKp.getPublic(), "SHA256withECDSA", false);

        //Then
        assertThat(x509Certificate).isNotNull();
        x509Certificate.checkValidity(new Date());
        x509Certificate.verify(rootCertificate.getPublicKey());
        byte[] basicConstrainsExtension = x509Certificate.getExtensionValue(Extension.basicConstraints.getId());
        assertThat(basicConstrainsExtension).isNotNull();
        //assertThat(basicConstrainsExtension).isEqualTo("false");
    }
}
