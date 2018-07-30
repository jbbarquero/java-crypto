package com.malsolo.crypto.book.tls;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;

/**
 * Basic SSL Client - using the '!' protocol.
 * Usage:
 * java -Djavax.net.ssl.trustStorePassword=beginning-java-crypto/certsFromUtils/trustStore.jks com.malsolo.crypto.book.tls.SSLClientExample
 */
public class SSLClientExample {
    /**
     * Carry out the '!' protocol - client side.
     */
    static void doProtocol(Socket cSock) throws IOException {
        OutputStream out = cSock.getOutputStream();
        InputStream in = cSock.getInputStream();

        out.write(TuttiUtil.toByteArray("World"));
        out.write('!');

        int ch;
        while ((ch = in.read()) != '!') {
            System.out.print((char)ch);
        }

        System.out.println((char)ch);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("SSLClientExample");
        SSLSocketFactory fact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Constants.HOST, Constants.PORT_NO);

        //Arrays.stream(cSock.getEnabledCipherSuites()).forEach(System.out::println);
        UtilsCertificates.print("JKS", System.getProperty("javax.net.ssl.trustStore"), "trustPassword");

        System.out.println("SSLClientExample do protocol...");
        doProtocol(cSock);
    }
}
