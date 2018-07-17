package com.malsolo.crypto.certificates;

import com.malsolo.crypto.util.FixedRand;
import com.malsolo.crypto.util.Utils;
//import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class PKCS10CertRequestExample {

    public static org.bouncycastle.jce.PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception {
        /*
        When
                pemWrt.writeObject(request);
        Exception in thread "main" org.bouncycastle.util.io.pem.PemGenerationException: unknown object passed - can't encode.
	at org.bouncycastle.openssl.MiscPEMGenerator.createPemObject(Unknown Source)
	at org.bouncycastle.openssl.MiscPEMGenerator.generate(Unknown Source)
	at org.bouncycastle.util.io.pem.PemWriter.writeObject(Unknown Source)
	at org.bouncycastle.openssl.PEMWriter.writeObject(Unknown Source)
	at org.bouncycastle.openssl.PEMWriter.writeObject(Unknown Source)
	at com.malsolo.crypto.certificates.PKCS10CertRequestExample.main(PKCS10CertRequestExample.java:41)

	Due to org.bouncycastle.openssl.MiscPEMGenerator doesn't have org.bouncycastle.jce.PKCS10CertificationRequest in the if-elses,
	but

        * */
        return new org.bouncycastle.jce.PKCS10CertificationRequest(
                "SHA256withRSA",
                new X500Principal("CN=Requested Test Certificate"),
                pair.getPublic(),
                null,
                pair.getPrivate());
    }

    public static org.bouncycastle.jce.PKCS10CertificationRequest generateRequestWithExtensions(KeyPair pair) throws Exception {
        return null;
    }

    public static PKCS10CertificationRequest createPKCS10(KeyPair keyPair, String sigAlg) throws OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo");

        X500Name subject = x500NameBld.build();

        JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());

        return requestBuilder.build(signer);

    }

    public static void main(String[] args) throws Exception {
        Utils.installBouncyCastleProvider();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, FixedRand.createFixedRandom());

        KeyPair          pair = kpGen.generateKeyPair();

        //org.bouncycastle.jce.PKCS10CertificationRequest  request = generateRequest(pair);
        PKCS10CertificationRequest certificationRequest = createPKCS10(pair, "SHA256withRSA");

        PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));

        //pemWrt.writeObject(request);
        pemWrt.writeObject(certificationRequest);

        pemWrt.close();

    }

}
