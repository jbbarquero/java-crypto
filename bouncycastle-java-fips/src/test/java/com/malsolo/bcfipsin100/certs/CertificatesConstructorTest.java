package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;
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

        //When
        X509Certificate x509Certificate = CertificatesConstructor.makeV1Certificate(trustKp, "SHA256withECDSA");

        //Then
        assertThat(x509Certificate).isNotNull();
        x509Certificate.checkValidity(new Date());
        x509Certificate.verify(x509Certificate.getPublicKey());
    }
}
