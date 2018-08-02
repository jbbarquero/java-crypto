package com.malsolo.crypto.tls.https;

import lombok.Data;

import java.io.File;

@Data
public class SSLContextInfo {
    private final KeyStoreType keyStoreType;
    private final File keyStoreFile;
    private final char[] keyStorePassword;
    private final KeyStoreType trustStoreType;
    private final File trustStoreFile;
    private final char[] trustStorePassword;

}
