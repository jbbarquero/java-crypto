package com.malsolo.bcfipsin100.pbeks;

import org.bouncycastle.asn1.x509.Extension;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Stream;

import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.CLIENT_STORE_PASSWORD;

@SuppressWarnings("WeakerAccess")
public class ReadKeystores {

    /**
     * Tries to mimic openssl:
     * $ openssl pkcs12 -in client3.p12 -cacerts -nodes -nokeys -out client3_ca_certificates.pem -passin pass:clientPassword3
     * $ openssl pkcs12 -in client3.p12 -clcerts -nodes -nokeys -out client3_public_certificate.pem -passin pass:clientPassword3
     * $ openssl pkcs12 -in client3.p12 -nocerts -nodes -out client3_private_key.pem -passin pass:clientPassword3
     *
     * See
     *
     * https://stackoverflow.com/questions/9497719/extract-public-private-key-from-pkcs12-file-for-later-use-in-ssh-pk-authenticati/9516936
     * https://www.feistyduck.com/library/openssl-cookbook/online/ch-openssl.html#pkcs12-conversion
     * https://www.openssl.org/docs/man1.1.0/apps/openssl-pkcs12.html
     *
     * See also
     * https://www.sslshopper.com/article-most-common-openssl-commands.html
     * https://www.cloudera.com/documentation/enterprise/5-5-x/topics/cm_sg_openssl_jks.html
     *
     */
    public static void readPKCS12(File pkcs12File, char[] pkcs12Password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pkcs12File)) {
            keyStore.load(fis, pkcs12Password);
        }

        String alias = keyStore.aliases().nextElement();
        KeyStore.ProtectionParameter param = new KeyStore.PasswordProtection(pkcs12Password);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, param);

        System.out.println(Pem.privateKeyToString(privateKeyEntry.getPrivateKey()));

        Stream
                .of(privateKeyEntry.getCertificateChain())
                .map(X509Certificate.class::cast)
                .map(x509 -> certificateToPemString(x509, alias))
                .forEach(System.out::println);
    }

    private static String certificateToPemString(X509Certificate x509Certificate, String alias) {
        StringBuilder sb = new StringBuilder();
        try {
            //Wrong: we need to use:
            //https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/pkcs/PKCS12PfxPduBuilder.html
            //https://github.com/joschi/cryptoworkshop-bouncycastle/blob/master/src/main/java/cwguide/JcePKCS12Example.java
            sb.append("Bag Attributes")
                    .append("\n\tfriendlyName: ").append(alias)
                    .append("\n\tlocalKeyID: ")
                    .append(Arrays.toString(x509Certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId())))
                    .append("\nsubject=").append(x509Certificate.getSubjectX500Principal().toString())
                    .append("\nissuer=").append(x509Certificate.getIssuerX500Principal().toString())
                    .append("\n").append(Pem.certificateToString(x509Certificate));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Path path = Paths.get("bouncycastle-java-fips/certsFromUtils3/client3.p12");
        System.out.printf("%s exists? %b\n", path.toString(), path.toFile().exists());
        readPKCS12(path.toFile(), CLIENT_STORE_PASSWORD);
    }
}
