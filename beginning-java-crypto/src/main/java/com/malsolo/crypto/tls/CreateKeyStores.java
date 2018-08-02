package com.malsolo.crypto.tls;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

public class CreateKeyStores {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        X500PrivateCredential rootCredential = Utils.createRootCredential();
        X500PrivateCredential interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());

        // client credentials
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry(Utils.CLIENT_NAME, endCredential.getPrivateKey(), Utils.CLIENT_PASSWORD,
                new Certificate[] { endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate() });

        Path clientKeystore = Paths.get(Utils.CLIENT_NAME + ".p12");
        keyStore.store(new FileOutputStream(clientKeystore.toFile()), Utils.CLIENT_PASSWORD);

        System.out.printf("Client credentials created at: %s\n", clientKeystore.toString());

        Utils2.createPemFile(endCredential.getPrivateKey(), Paths.get(Utils.CLIENT_NAME + "_PK.pem"), "Client PEM Private Key");
        Utils2.createPemFile(endCredential.getCertificate(), Paths.get(Utils.CLIENT_NAME + "_PC.pem"), "Client PEM Public Certificate");

        // trust store for client
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry(Utils.SERVER_NAME, rootCredential.getCertificate());

        Path clientTruststore = Paths.get(Utils.TRUST_STORE_NAME + ".jks");
        keyStore.store(new FileOutputStream(clientTruststore.toFile()), Utils.TRUST_STORE_PASSWORD);

        System.out.printf("Trust store created at: %s\n", clientKeystore.toString());

        Utils2.createPemFile(rootCredential.getCertificate(), Paths.get(Utils.TRUST_STORE_NAME + ".pem"), "Root PEM Public certificate");

        // server credentials
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setKeyEntry(Utils.SERVER_NAME, rootCredential.getPrivateKey(), Utils.SERVER_PASSWORD,
                new Certificate[] { rootCredential.getCertificate() });

        keyStore.store(new FileOutputStream(Utils.SERVER_NAME + ".jks"), Utils.SERVER_PASSWORD);

    }

}
