package com.malsolo.bcfipsin100.tls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.*;
import static com.malsolo.bcfipsin100.tls.HTTPSUtil.*;

public class HTTPSClient {

    private static final String DEFAULT_IP = "127.0.0.1";
    private static int DEFAULT_PORT = HTTPSServer.PORT;

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : DEFAULT_IP;
        int port;
        try {
            port = Integer.parseInt(args[1]);
        } catch (RuntimeException ex) {
            port = DEFAULT_PORT;
        }
        System.out.printf("HTTPS clientSocket to host %s and port %d \n", host, port);

        SSLContext sslClientContext = createSSLContext(
                Paths.get(CERTS_PATH + CLIENT_STORE_NAME_P12).toFile(),
                CLIENT_STORE_PASSWORD,
                "PKCS12",
                Paths.get(CERTS_PATH + TRUST_STORE_NAME).toFile(),
                TRUST_STORE_PASSWORD,
                "JKS"
        );

        SSLSocketFactory socketFactory = sslClientContext.getSocketFactory();

        System.out.println("\nCLIENT: ATTEMPT CONNECTION...\n");

        try (SSLSocket clientSocket = (SSLSocket) socketFactory.createSocket(host, port)) {

            System.out.println("CLIENT: start handshake");
            //clientSocket.startHandshake();

            // Cipher suites
            System.out.println("***** SUPPORTED CIPHER SUITES *****");
            Stream.of(clientSocket.getSupportedCipherSuites()).forEach(System.out::println);

            System.out.println("***** ENABLED CIPHER SUITES *****");
            Stream.of(clientSocket.getEnabledCipherSuites()).forEach(System.out::println);

            System.out.println("CLIENT: view certificates");
            viewCertificates(clientSocket.getSession());

            System.out.println("\nCLIENT: exchange data");
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

            String userInput;
            while ((userInput = stdIn.readLine()) != null) {
                out.println(userInput);
                System.out.printf("Client echo: %s\n", in.readLine());
            }

        }

    }

}
