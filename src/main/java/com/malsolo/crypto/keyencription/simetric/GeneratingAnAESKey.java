package com.malsolo.crypto.keyencription.simetric;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

import static com.malsolo.crypto.util.Utils.installBouncyCastleProvider;

public class GeneratingAnAESKey {

    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static void main(String[] args) throws GeneralSecurityException {
        installBouncyCastleProvider();
        SecretKey secretKey = generateKey();
        System.out.println(Base64.toBase64String(secretKey.getEncoded()));
    }

}
