package com.malsolo.crypto.book.tls;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class Utils2 {

    public static final String SERVER_NAME = "server2";
    public static final char[] SERVER_PASSWORD = "serverPassword2".toCharArray();
    public static final String CLIENT_NAME = "client2";
    public static final char[] CLIENT_PASSWORD = "clientPassword2".toCharArray();
    public static final String TRUST_STORE_NAME = "trustStore2";
    public static final char[] TRUST_STORE_PASSWORD = "trustPassword2".toCharArray();

    private static long serialNumberBase = System.currentTimeMillis();

    /**
     * Calculate a date in seconds (suitable for the PKIX profile - RFC 5280)
     *
     * @param hoursInFuture hours ahead of now, may be negative.
     * @return a Date set to now + (hoursInFuture * 60 * 60) seconds
     */
    public static Date calculateDate(int hoursInFuture) {
        return Date.from(LocalDateTime
                .now()
                .plus(hoursInFuture, ChronoUnit.HOURS)
                .atZone(ZoneId.systemDefault())
                .toInstant()
        );
    }

    public static BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }

    /**
     * Build a sample self-signed V1 certificate to use as a trust anchor, or
     * root certificate.
     *
     * @param keyPair the key pair to use for signing and providing the
     *
    public key.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @return an X509CertificateHolder containing the V1 certificate.
     */
    public static X509CertificateHolder createTrustAnchor(KeyPair keyPair, String sigAlg)
            throws OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Las Rozas")
                .addRDN(BCStyle.O, "MALSOLO")
                .addRDN(BCStyle.CN, "Root Certificate");

        X500Name name = x500NameBld.build();

        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                name,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(keyPair.getPrivate());

        return certBldr.build(signer);

    }

    /**
     * Extract the DER encoded value octets of an extension from a JCA
     * X509Certificate.
     *
     * @param cert the certificate of interest.
     * @param extensionOID the OID associated with the extension of interest.
     * @return the DER encoding inside the extension, null if extension missing.
     */
    public static byte[] extractExtensionValue(
            X509Certificate cert,
            ASN1ObjectIdentifier extensionOID) {

        byte[] octString = cert.getExtensionValue(extensionOID.getId());

        if (octString == null) {
            return null;
        }

        return ASN1OctetString.getInstance(octString).getOctets();
    }

    /**
     * Build a sample V3 intermediate certificate that can be used as a CA
     * certificate.
     *
     * @param signerCert certificate carrying the public key that will later
     *
    be used to verify this certificate's signature.
     * @param signerKey private key used to generate the signature in the
     *
    certificate.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @param certKey public key to be installed in the certificate.
     * @param followingCACerts for creating CA=true object for the given path length constraint.
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createIntermediateCertificate(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey, int followingCACerts)
            throws CertIOException, GeneralSecurityException,
            OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Las Rozas")
                .addRDN(BCStyle.O, "MALSOLO")
                .addRDN(BCStyle.CN, "Intermediate Certificate");

        X500Name subject = x500NameBld.build();

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(
                                KeyUsage.digitalSignature
                                        | KeyUsage.keyCertSign
                                        | KeyUsage.cRLSign))
//                .addExtension(Extension.subjectAlternativeName, false,
//                        new GeneralNames(
//                                new GeneralName(
//                                        GeneralName.rfc822Name,
//                                        "feedback-crypto@malsolo.com")))
        ;

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);

        return certBldr.build(signer);
    }

    /**
     * Create a general end-entity certificate for use in verifying digital
     * signatures.
     *
     * @param signerCert certificate carrying the public key that will later
     *
    be used to verify this certificate's signature.
     * @param signerKey private key used to generate the signature in the
     *
    certificate.
     * @param sigAlg the signature algorithm to sign the certificate with.
     * @param certKey public key to be installed in the certificate.
     * @return an X509CertificateHolder containing the V3 certificate.
     */
    public static X509CertificateHolder createEndEntity(
            X509CertificateHolder signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey)
            throws CertIOException, GeneralSecurityException,
            OperatorCreationException {

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.ST, "Madrid")
                .addRDN(BCStyle.L, "Las Rozas")
                .addRDN(BCStyle.O, "MALSOLO")
                .addRDN(BCStyle.CN, "Server Certificate");

        X500Name subject = x500NameBld.build();

        X509v3CertificateBuilder
                certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubject(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBldr.addExtension(Extension.authorityKeyIdentifier,
                false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier,
                        false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);

        return certBldr.build(signer);
    }

    public static void writeCertificate(Path filePath, byte[] certificateBytes) throws IOException {
        Files.write(filePath, certificateBytes);
    }

}
