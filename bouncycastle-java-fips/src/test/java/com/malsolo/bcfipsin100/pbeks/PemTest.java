package com.malsolo.bcfipsin100.pbeks;

import com.malsolo.bcfipsin100.Setup;
import com.malsolo.bcfipsin100.certs.CertificatesConstructor;
import com.malsolo.bcfipsin100.utilities.EC;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;


public class PemTest {

    @BeforeClass
    public static void installProvider() {
        Setup.installProvider();
    }

    @Test
    public void testWriteAndReadCertificate() throws Exception {
        X509Certificate x509Certificate = CertificatesConstructor.makeV1Certificate(
                new X500NameBuilder(BCStyle.INSTANCE)
                        .addRDN(BCStyle.C, "ES")
                        .addRDN(BCStyle.ST, "Madrid")
                        .addRDN(BCStyle.L, "Mostoles")
                        .addRDN(BCStyle.O, "Malsolo")
                        .addRDN(BCStyle.OU, "Unit 1")
                        .addRDN(BCStyle.CN, "Root Certificate")
                        .build(),
                EC.generateKeyPair(),
                "SHA384withECDSA"
        );

        String pem = Pem.certificateToString(x509Certificate);
        System.out.println(pem);
        X509Certificate x509CertificateFromPem = Pem.stringToCertificate(pem);

        assertThat(x509CertificateFromPem).isNotNull();
        assertThat(x509CertificateFromPem.getSerialNumber().toString())
                .isEqualTo(x509Certificate.getSerialNumber().toString());
        String pemAgain = Pem.certificateToString(x509CertificateFromPem);
        assertThat(pemAgain).isEqualTo(pem);
    }

    @Test
    public void testWriteAndReadPrivateKey() throws Exception {

        KeyPair keyPair = EC.generateKeyPair();

        String pem = Pem.privateKeyToString(keyPair.getPrivate());
        System.out.println(pem);
        PrivateKey privateKeyFromPem = Pem.stringToPrivateKey(pem);

        assertThat(privateKeyFromPem).isNotNull();
        assertThat(Hex.toHexString(privateKeyFromPem.getEncoded()))
                .isEqualTo(Hex.toHexString(keyPair.getPrivate().getEncoded()));
        String pemAgain = Pem.privateKeyToString(privateKeyFromPem);
        assertThat(pemAgain).isEqualTo(pem);
    }

    @Test
    public void testCertificationRequestToString() throws Exception {
        /*
         * CSR created with OpenSSL:
         * openssl req -utf8 -sha256 -newkey rsa:4096 -keyout private.key -nodes -out cert.csr \
         * -subj "/O=Malsolo/OU=Unit/OU=Testing/OU=Application/CN=localhost"
         */
        String subject = "O=Malsolo,OU=Unit,OU=Testing,OU=Application,CN=localhost";

        URL csrPemUrl = getClass().getClassLoader().getResource("cert.csr");
        assertThat(csrPemUrl).isNotNull();

        String pem = new String(Files.readAllBytes(Paths.get(csrPemUrl.toURI())));
        assertThat(pem).isNotNull();
        assertThat(pem).isNotEmpty();

        System.out.println(pem);

        PKCS10CertificationRequest pkcs10CertificationRequest = Pem.certificationRequestToString(pem);
        assertThat(pkcs10CertificationRequest).isNotNull();

        System.out.printf("%s\n", pkcs10CertificationRequest.getSubject().toString());
        assertThat(pkcs10CertificationRequest.getSubject().toString()).isEqualTo(subject);
    }

}
