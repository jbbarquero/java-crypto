package com.malsolo.crypto;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class PolicyTest {

    @Test
    public void testMaxAllowedKeyLength() throws NoSuchAlgorithmException {
        int maxKeySize = Cipher.getMaxAllowedKeyLength("AES");
        assertEquals(2147483647, maxKeySize);
    }

    @Test
    public void testBytes() {
        byte[] bytes = "password".getBytes(StandardCharsets.UTF_8);
        System.out.println(bytes);
        System.out.println(Arrays.toString(bytes));
        byte[] data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        System.out.println(data);
        System.out.println(Arrays.toString(data));
    }

    @Test
    public void testKey64() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        //Given
        byte[] data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        SecretKeySpec key64 = new SecretKeySpec(
                new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
                "Blowfish");

        //When
        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);

        //Then
        System.out.println("64 bits test: passed");
    }

    @Test
    public void testKey192() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        //Given
        byte[] data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        SecretKeySpec key64 = new SecretKeySpec(
                new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
                "Blowfish");

        //When
        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);

        //Then
        System.out.println("192 bits test: passed");
    }
}
