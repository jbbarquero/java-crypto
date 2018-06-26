package com.malsolo.crypto.util;

import org.junit.Test;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;

public class UtilsTest {

    @Test
    public void testGenerateRSAKeyPair() throws GeneralSecurityException {
        KeyPair keyPair = Utils.generateRSAKeyPair();
        assertThat(keyPair).isNotNull();
    }

}
