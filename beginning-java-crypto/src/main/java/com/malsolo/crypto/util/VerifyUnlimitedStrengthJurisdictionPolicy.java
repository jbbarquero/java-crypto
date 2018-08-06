package com.malsolo.crypto.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.security.Security;

public class VerifyUnlimitedStrengthJurisdictionPolicy {

    /**
     * From https://golb.hplar.ch/2017/10/JCE-policy-changes-in-Java-SE-8u151-and-8u152.html
     * @param args args, ignored.
     * @throws Exception if something goes wrong.
     */
    public static void main(String[] args) throws Exception {
        int keySize = 256; //192; //128;

        Security.addProvider(new BouncyCastleProvider());

        byte[] input = "My super secret text".getBytes();
        System.out.printf("Plain text: %s\n", new String(input));

        long start = System.currentTimeMillis();

        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] cipherText = cipher.doFinal(input);
        System.out.printf("Encrypted text: %s\n", new String(cipherText));

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.printf("Decrypted text: %s\n", new String(plainText));

        long end = System.currentTimeMillis();

        System.out.printf("It took %d ms", end - start);

    }

}
