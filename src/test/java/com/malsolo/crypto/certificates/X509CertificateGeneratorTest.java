package com.malsolo.crypto.certificates;

import static org.assertj.core.api.Assertions.assertThat;

import com.malsolo.crypto.util.Utils;
import org.junit.Test;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509CertificateGeneratorTest {

    @Test
    public void testGenerateCertificate() throws GeneralSecurityException {
        //Given
        KeyPair keyPair = Utils.generateRSAKeyPair();

        //When
        X509Certificate cert = X509CertificateGenerator.generateCertificate(keyPair);

        // Then
        assertThat(cert).isNotNull();
        cert.checkValidity(new Date());
        cert.verify(cert.getPublicKey());
    }

}
