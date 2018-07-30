package com.malsolo.crypto.book.tls;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;

/**
 * Basic SSL Server with client authentication.
 * Usage:
 * java -Djavax.net.ssl.keyStore=beginning-java-crypto/certsFromUtils/server.jks -Djavax.net.ssl.keyStorePassword=serverPassword -Djavax.net.ssl.trustStorePassword=beginning-java-crypto/certsFromUtils/trustStore.jks -Djavax.net.ssl.trustStore=trustPassword com.malsolo.crypto.book.tls.SSLServerWithClientAuthExample
 */
public class SSLServerWithClientAuthExample extends SSLServerExample {
    public static void main(String[] args) throws Exception {
        UtilsCertificates.print("JKS", System.getProperty("javax.net.ssl.keyStore"), System.getProperty("javax.net.ssl.keyStorePassword"));
        UtilsCertificates.print("JKS", System.getProperty("javax.net.ssl.trustStore"), System.getProperty("javax.net.ssl.trustStorePassword"));

        SSLServerSocketFactory fact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket        sSock = (SSLServerSocket)fact.createServerSocket(Constants.PORT_NO);

        sSock.setNeedClientAuth(true);

        SSLSocket sslSock = (SSLSocket)sSock.accept();

        doProtocol(sslSock);
    }
}
