package com.malsolo.crypto.certificates;

import com.malsolo.crypto.util.FixedRand;
import com.malsolo.crypto.util.Utils;
//import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Vector;

public class PKCS10CertRequestExample {

    /**
     * Generation of a basic PKCS #10 request.
     */
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

    /**
     * Generation of a basic PKCS #10 request with an extension.
     */
    public static org.bouncycastle.jce.PKCS10CertificationRequest generateRequestWithExtensions(KeyPair pair) throws Exception {
        /*
        Exception in thread "main" java.lang.IllegalArgumentException: unknown object in factory: org.bouncycastle.asn1.x509.Attribute
	at org.bouncycastle.asn1.pkcs.Attribute.getInstance(Unknown Source)
	at org.bouncycastle.asn1.pkcs.CertificationRequestInfo.validateAttributes(Unknown Source)
	at org.bouncycastle.asn1.pkcs.CertificationRequestInfo.<init>(Unknown Source)
	at org.bouncycastle.asn1.pkcs.CertificationRequestInfo.<init>(Unknown Source)
	at org.bouncycastle.jce.PKCS10CertificationRequest.<init>(Unknown Source)
	at org.bouncycastle.jce.PKCS10CertificationRequest.<init>(Unknown Source)
	at com.malsolo.crypto.certificates.PKCS10CertRequestExample.generateRequestWithExtensions(PKCS10CertRequestExample.java:74)
	at com.malsolo.crypto.certificates.PKCS10CertRequestExample.main(PKCS10CertRequestExample.java:104)
        * */
        // create a SubjectAlternativeName extension value
        GeneralNames subjectAltNames = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test"));

        // create the extensions object and add it as an attribute
        Vector<ASN1ObjectIdentifier> oids = new Vector<>();
        Vector<X509Extension>	values = new Vector<>();

        oids.add(X509Extensions.SubjectAlternativeName);
        values.add(new X509Extension(false, new DEROctetString(subjectAltNames)));

        X509Extensions	extensions = new X509Extensions(oids, values);

        Attribute attribute = new Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                new DERSet(extensions));

        return new org.bouncycastle.jce.PKCS10CertificationRequest(
                "SHA256withRSA",
                new X500Principal("CN=Requested Test Certificate"),
                pair.getPublic(),
                new DERSet(attribute),
                pair.getPrivate());
    }

    /**
     * Create a basic PKCS#10 request.
     *
     * @param keyPair the key pair the certification request is for.
     * @param sigAlg the signature algorithm to sign the PKCS#10 request with.
     * @return an object carrying the PKCS#10 request.
     * @throws OperatorCreationException in case the private key is
     * inappropriate for signature algorithm selected.
     */
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

    /**
     * Create a PKCS#10 request including an extension request detailing the
     * email address the CA should include in the subjectAltName extension.
     *
     * @param keyPair the key pair the certification request is for.
     * @param sigAlg the signature algorithm to sign the PKCS#10
     *
    request with.
     * @return an object carrying the PKCS#10 request.
     * @throws OperatorCreationException in case the private key is
     * inappropriate for signature algorithm selected.
     * @throws IOException on an ASN.1 encoding error.
     */
    public static PKCS10CertificationRequest createPKCS10WithExtensions(KeyPair keyPair, String sigAlg)
            throws OperatorCreationException, IOException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Mostoles")
                .addRDN(BCStyle.O, "Malsolo");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(
                        new GeneralName(
                                GeneralName.rfc822Name,
                                "its@me.es"
                        )
                )
        );

        Extensions extensions = extGen.generate();

        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(keyPair.getPrivate());

        return requestBuilder.build(signer);
    }

    public static void main(String[] args) throws Exception {
        Utils.installBouncyCastleProvider();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, FixedRand.createFixedRandom());

        KeyPair          pair = kpGen.generateKeyPair();

        //org.bouncycastle.jce.PKCS10CertificationRequest  certificationRequest = generateRequest(pair);
        //org.bouncycastle.jce.PKCS10CertificationRequest  certificationRequest = generateRequestWithExtensions(pair);
        //PKCS10CertificationRequest certificationRequest = createPKCS10(pair, "SHA256withRSA");
        PKCS10CertificationRequest certificationRequest = createPKCS10WithExtensions(pair, "SHA256withRSA");

        PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));

        //pemWrt.writeObject(request);
        pemWrt.writeObject(certificationRequest);

        pemWrt.close();
    }

}
