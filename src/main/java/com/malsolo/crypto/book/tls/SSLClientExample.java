package com.malsolo.crypto.book.tls;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Basic SSL Client - using the '!' protocol.
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
        System.out.println("SSLServerExample");
        SSLSocketFactory fact = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket        cSock = (SSLSocket)fact.createSocket(Constants.HOST, Constants.PORT_NO);

        System.out.println("SSLServerExample do protocol...");
        doProtocol(cSock);
    }
}
