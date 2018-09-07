package com.malsolo.bcfipsin100.utilities;

import com.malsolo.bcfipsin100.Setup;

import java.security.*;


public class EC {

    @SuppressWarnings("WeakerAccess")
    public final static String ALGORITHM = "EC";
    @SuppressWarnings("WeakerAccess")
    public final static int KEY_SIZE = 384;

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, Setup.PROVIDER);

        keyPairGenerator.initialize(KEY_SIZE);

        return keyPairGenerator.generateKeyPair();
    }

}
