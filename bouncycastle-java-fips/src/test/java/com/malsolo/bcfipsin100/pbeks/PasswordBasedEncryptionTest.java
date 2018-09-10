package com.malsolo.bcfipsin100.pbeks;

import com.malsolo.bcfipsin100.Setup;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class PasswordBasedEncryptionTest {

    @BeforeClass
    public static void installProvider() {
        Setup.installProvider();
    }

    @Test
    public void makePbeKeyJcePKCS5Scheme2Test1() throws GeneralSecurityException {
        SecretKey secretKey = PasswordBasedEncryption.makePbeKeyJcePKCS5Scheme2(
                "PBKDF2WithHmacSHA384",
                "password".toCharArray(),
                Hex.decode("0102030405060708090a0b0c0d0e0f10"),
                1024,
                "AES"
        );
        System.out.println(Hex.toHexString(secretKey.getEncoded()));
    }

    @Test
    public void makePbeKeyJcePKCS5Scheme2Test2() throws GeneralSecurityException {
        SecretKey secretKey = PasswordBasedEncryption.makePbeKeyJcePKCS5Scheme2(
                "PBKDF2WITHHMACSHA256",
                "password".toCharArray(),
                Hex.decode("0102030405060708090a0b0c0d0e0f10"),
                1024,
                "AES"
        );
        System.out.println(Hex.toHexString(secretKey.getEncoded()));
    }
}
