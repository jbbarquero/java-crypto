package com.malsolo.crypto.criptography.simetrickey;

import com.malsolo.crypto.util.Utils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * A simple example of AES in CBC mode with block aligned padding.
 */
public class AESinCBCmodeWithPaddingExample {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ShortBufferException {

        Utils.installBouncyCastleProvider();

        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0");

        System.out.printf("input: %s\n", Hex.toHexString(input));

        byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] output  = new byte[cipher.getOutputSize(input.length)];

        int outLen = cipher.update(input, 0, input.length, output, 0);

        outLen += cipher.doFinal(output, outLen);

        System.out.printf("encrypted (%d bytes): %s\n", outLen, Hex.toHexString(Arrays.copyOfRange(output, 0, outLen)));

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];

        int len = cipher.update(output, 0, output.length, finalOutput, 0);

        len += cipher.doFinal(finalOutput, len);

        System.out.printf("decrypted (%d bytes): %s\n", len, Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)));
    }

}
