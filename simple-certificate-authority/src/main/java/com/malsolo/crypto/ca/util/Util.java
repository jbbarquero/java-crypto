package com.malsolo.crypto.ca.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Util {

    public static void writeCertificate(Path filePath, byte[] certificateBytes) throws IOException {
        Files.write(filePath, certificateBytes);
    }
}
