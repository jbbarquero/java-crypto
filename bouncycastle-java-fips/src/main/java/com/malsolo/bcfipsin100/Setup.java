package com.malsolo.bcfipsin100;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Setup {

    public static void installProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }
}
