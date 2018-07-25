package com.malsolo.crypto;

import static org.assertj.core.api.Assertions.*;

import com.malsolo.crypto.util.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class ProviderTest {

    @BeforeClass
    public static void installBCProvider() {
        Utils.installBouncyCastleProvider();
    }

    @Test
    public void testPrecedence() throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        assertThat(cipher).isNotNull();
        assertThat(cipher.getProvider().getName()).contains("SunJCE"); //SunJCE version 1.8

        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
        assertThat(cipher).isNotNull();
        assertThat(cipher.getProvider().getName()).startsWith("BC"); //BC version 1.59
    }

}
