package com.malsolo.crypto.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class Utils {

    public static void installBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.printf("Installed provider: %s\n",
                    Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
        }
    }

    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair() throws GeneralSecurityException {

        installBouncyCastleProvider();

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, new SecureRandom());

        return kpGen.generateKeyPair();
    }
}
