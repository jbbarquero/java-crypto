package com.malsolo.bcfipsin100.tls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.*;
import static com.malsolo.bcfipsin100.tls.HTTPSUtil.*;

@SuppressWarnings("InfiniteLoopStatement")
public class HTTPSServer {

    public static final int PORT = 9999;

    public static void main(String[] args) throws Exception {

        SSLContext sslServerContext = createSSLContext(
                Paths.get(CERTS_PATH + SERVER_STORE_NAME_P12).toFile(),
                SERVER_STORE_PASSWORD,
                "PKCS12",
                Paths.get(CERTS_PATH + "mini_" + TRUST_STORE_NAME).toFile(),
                TRUST_STORE_PASSWORD,
                "JKS"
        );

        SSLServerSocketFactory serverSocketFactory = sslServerContext.getServerSocketFactory();

        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);
        serverSocket.setNeedClientAuth(true);

        // Cipher suites
        System.out.println("***** SUPPORTED CIPHER SUITES *****");
        Stream.of(serverSocket.getSupportedCipherSuites()).forEach(System.out::println);

        System.out.println("***** ENABLED CIPHER SUITES *****");
        Stream.of(serverSocket.getEnabledCipherSuites()).forEach(System.out::println);

        System.out.println("\nSERVER: WAITING FOR CONNECTIONS...\n");

        while (true) {
            try (SSLSocket connection = (SSLSocket) serverSocket.accept()) {
                System.out.println("Server: start handshake");
                //connection.startHandshake();

                System.out.println("SERVER: view certificates");
                viewCertificates(connection.getSession());

                System.out.println("\nSERVER: exchange data");
                InputStream in = connection.getInputStream();
                OutputStream out = connection.getOutputStream();
                int c;
                while ((c = in.read()) != -1) {
                    System.out.print((char) c);
                    out.write(c);
                    out.flush();
                }
            }
            catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

}
