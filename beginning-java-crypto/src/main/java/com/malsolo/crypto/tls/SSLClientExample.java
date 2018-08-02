package com.malsolo.crypto.tls;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Basic SSL Client - using the '!' protocol.
 * Usage:
 * java -Djavax.net.ssl.trustStore=beginning-java-crypto/certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStorePassword=trustPassword com.malsolo.crypto.book.tls.SSLClientExample
 * According https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html (Creating an X509TrustManager)
 * "If the javax.net.ssl.trustStorePassword system property is also defined, then its value is used to check the integrity of the data in the truststore before opening it."
 * It seems there is no need to provide the password, but we are going to read it in order to print the store entries.
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
        UtilsCertificates.print("JKS", System.getProperty("javax.net.ssl.trustStore"), System.getProperty("javax.net.ssl.trustStorePassword"));

        System.out.println("SSLClientExample do protocol...");
        doProtocol(cSock);
    }
}
