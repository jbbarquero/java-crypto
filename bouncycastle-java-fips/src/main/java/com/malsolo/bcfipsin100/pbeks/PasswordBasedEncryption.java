package com.malsolo.bcfipsin100.pbeks;

import com.malsolo.bcfipsin100.Setup;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class PasswordBasedEncryption {

    private static String ALGORITHM = "PBKDF2WITHHMACSHA256"; //"HmacSHA384"; //"PBKDF2WITHHMACSHA256"
    private static String SECRET_KEY_ALGORITHM = "AES";

    public static SecretKey makePbeKeyJcePKCS5Scheme2(String secretKeyAlgorithm, char[] password, byte[] salt, int iterationCount, String keyAlgorithm) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyAlgorithm, Setup.PROVIDER);

        SecretKey secretKey = factory.generateSecret(new PBEKeySpec(password, salt, iterationCount, 256));

        return new SecretKeySpec(secretKey.getEncoded(), keyAlgorithm);
    }

}
