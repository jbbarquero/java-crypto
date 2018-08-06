package com.malsolo.crypto.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class PolicyFileCheck {

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[32], "Blowfish"));
            System.out.print("true");
        }
        catch (NoSuchAlgorithmException e) {
            throw e;
        }
        catch (Exception e) {
            System.out.print("false");
        }
    }
}
