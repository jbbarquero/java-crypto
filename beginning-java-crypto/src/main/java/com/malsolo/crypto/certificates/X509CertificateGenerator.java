package com.malsolo.crypto.certificates;

import com.malsolo.crypto.util.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.Date;

public class X509CertificateGenerator {

    public static X509Certificate generateV1Certificate(KeyPair pair)
            throws InvalidKeyException, NoSuchProviderException, SignatureException {

        Utils.installBouncyCastleProvider();

        // generate the certificate
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=Test Certificate V1 Issuer"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X500Principal("CN=Test Certificate V1 Subject"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }

    /*
    public static X509Certificate generateCertificateV2(KeyPair pair) {
        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                new X500Name("CN=issuer"), new BigInteger("1"), new Date(
                System.currentTimeMillis()), new Date(
                System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
                        * 1000), pk10Holder.getSubject(), keyInfo);

        return null;
    }
    */

    public static X509Certificate generateV3Certificate(KeyPair pair) throws InvalidKeyException,
            NoSuchProviderException, SignatureException {
        // generate the certificate
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=Test Certificate V3 Issuer"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X500Principal("CN=Test Certificate V3 Subject"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));

        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }

    /**
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        // create the keys
        KeyPair         pair = Utils.generateRSAKeyPair();

        // generate the certificate
        X509Certificate cert = generateV1Certificate(pair);

        // show some basic validation
        cert.checkValidity(new Date());

        cert.verify(cert.getPublicKey());

        System.out.println("valid V1 certificate generated");

        //V3 certificate
        KeyPair pair4V3 = Utils.generateRSAKeyPair();
        X509Certificate certV3 = generateV3Certificate(pair);
        cert.checkValidity(new Date());
        cert.verify(certV3.getPublicKey());
        System.out.println("valid V3 certificate generated");

        byte[] usageExt = certV3.getExtensionValue(X509Extensions.KeyUsage.getId());
        System.out.println(usageExt == null ? "null" : new String(usageExt));
    }



    public static PKCS10CertificationRequest generateCertificateRequest(KeyPair pair) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        return new PKCS10CertificationRequest(
                "SHA256withRSA",
                new X500Principal("CN=Requested Test Certificate"),
                pair.getPublic(),
                null,
                pair.getPrivate());
    }

}
