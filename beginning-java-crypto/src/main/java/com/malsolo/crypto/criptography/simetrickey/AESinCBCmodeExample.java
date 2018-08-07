package com.malsolo.crypto.criptography.simetrickey;

import com.malsolo.crypto.util.Utils;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * A simple example of AES in CBC mode, using an IV.
 */
public class AESinCBCmodeExample {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Utils.installBouncyCastleProvider();

        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");

        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        System.out.printf("input: %s\n", Hex.toHexString(input));

        // Hardcoded IV
        // byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");

        // Three ways from JCE to obtain an IV: 1st, use a SecureRandom.
        // SecureRandom random = new SecureRandom();
        // byte[] iv = new byte[cipher.getBlockSize()];
        // random.nextBytes(iv);

        // Three ways from JCE to obtain an IV: 2nd, use the Cipher.

        cipher.init(Cipher.ENCRYPT_MODE, key /*, new IvParameterSpec(iv)*/);

        // Three ways from JCE to obtain an IV: 3rd, use AlgorithmParameters.

        // byte[] iv = cipher.getIV();

        AlgorithmParameters ivParams = cipher.getParameters();

        byte[] output = cipher.doFinal(input);

        System.out.printf("encrypted: %s\n", Hex.toHexString(output));

        cipher.init(Cipher.DECRYPT_MODE, key, ivParams/*new IvParameterSpec(iv)*/);

        System.out.printf("decrypted: %s\n", Hex.toHexString(cipher.doFinal(output)));

    }


}
