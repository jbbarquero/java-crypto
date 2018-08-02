package com.malsolo.crypto.tls;

public class TuttiUtil {
    /**
     * Convert the passed in String to a byte array by
     * taking the bottom 8 bits of each character it contains.
     * Chapter 3 Utils.
     *
     * @param string the string to be converted
     * @return a byte array representation
     */
    public static byte[] toByteArray(String string) {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte)chars[i];
        }

        return bytes;
    }

}
