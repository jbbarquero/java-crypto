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

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes  the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    private static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }

}
