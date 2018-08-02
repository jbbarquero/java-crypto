package com.malsolo.crypto.tls;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Basic SSL Server - using the '!' protocol.
 * Usage:
 * java -Djavax.net.ssl.keyStore=beginning-java-crypto/certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword com.malsolo.crypto.book.tls.SSLServerExample
 */
public class SSLServerExample {
    /**
     * Carry out the '!' protocol - server side.
     */
    static void doProtocol(Socket sSock) throws IOException {
        System.out.println("session started.");

        InputStream in = sSock.getInputStream();
        OutputStream out = sSock.getOutputStream();

        out.write(TuttiUtil.toByteArray("Hello "));

        int ch;
        while ((ch = in.read()) != '!') {
            out.write(ch);
        }

        out.write('!');

        sSock.close();

        System.out.println("session closed.");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("SSLServerExample");
        SSLServerSocketFactory fact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Constants.PORT_NO);

        //Arrays.stream(sSock.getEnabledCipherSuites()).forEach(System.out::println);
        UtilsCertificates.print("JKS", System.getProperty("javax.net.ssl.keyStore"), System.getProperty("javax.net.ssl.keyStorePassword"));

        SSLSocket sslSock = (SSLSocket)sSock.accept();

        System.out.println("SSLServerExample do protocol...");
        doProtocol(sslSock);
    }
}
