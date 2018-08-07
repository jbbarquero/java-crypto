package com.malsolo.crypto.criptography.simetrickey;

import com.malsolo.crypto.util.Utils;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * A simple example of AES in ECB mode.
 */
public class AESinECBmodeExample {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Utils.installBouncyCastleProvider();

        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        System.out.printf("input: %s\n", Hex.toHexString(input));

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] output = cipher.doFinal(input);

        System.out.printf("encrypted: %s\n", Hex.toHexString(output));

        cipher.init(Cipher.DECRYPT_MODE, key);

        System.out.printf("decrypted: %s\n", Hex.toHexString(cipher.doFinal(output)));

    }
}
