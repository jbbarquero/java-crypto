package com.malsolo.crypto.certificates;

import com.malsolo.crypto.tls.Utils2;
import com.malsolo.crypto.util.Utils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static com.malsolo.crypto.certificates.PKCS10CertRequestWithBouncyCastle160Example.caBuildCertificateChainFromRequest;
import static com.malsolo.crypto.certificates.PKCS10CertRequestWithBouncyCastle160Example.clientCertificationRequest;

public class CertStoreExample {

    public static void main(String[] args) throws Exception {
        Utils.installBouncyCastleProvider();

        X509Certificate[] chain = createBuildChain();

        // create the store
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(Arrays.asList(chain));
        CertStore store = CertStore.getInstance("Collection", params, "BC");

        // create the selector
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(new X500Principal("CN=End Certificate, O=Malsolo, L=Mostoles, ST=Madrid, C=ES").getEncoded());

        // print the subjects of the results
        store.getCertificates(selector).stream()
                .map(X509Certificate.class::cast)
                .map(X509Certificate::getSubjectX500Principal)
                .forEach(System.out::println);
    }

    private static X509Certificate[] createBuildChain() throws Exception {
        KeyPair rootPair = Utils.generateRSAKeyPair();
        X509CertificateHolder certificateHolder = Utils2.createTrustAnchor(rootPair, "SHA256WithRSAEncryption");
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        KeyPair certPair = Utils.generateRSAKeyPair();
        return caBuildCertificateChainFromRequest(clientCertificationRequest(certPair), rootCert, "SHA256WithRSAEncryption", rootPair.getPrivate());
    }

}
