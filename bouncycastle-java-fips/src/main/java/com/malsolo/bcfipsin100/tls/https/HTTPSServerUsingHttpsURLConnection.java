package com.malsolo.bcfipsin100.tls.https;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.*;
import static com.malsolo.bcfipsin100.tls.HTTPSUtil.createSSLContext;

@SuppressWarnings({"WeakerAccess", "InfiniteLoopStatement"})
public class HTTPSServerUsingHttpsURLConnection {

    private final int port;
    private final String certsPath;

    public HTTPSServerUsingHttpsURLConnection(int port, String certsPath) {
        this.port = port;
        this.certsPath = certsPath;
    }

    public void recevie() throws Exception {

        System.out.println("HTTPS Server: receive");

        SSLContext sslContext = createSSLContext(
                Paths.get(this.certsPath + SERVER_STORE_NAME_P12).toFile(),
                SERVER_STORE_PASSWORD,
                "PKCS12",
                Paths.get(certsPath + TRUST_STORE_NAME).toFile(),
                TRUST_STORE_PASSWORD,
                "JKS"
        );

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);
        sslServerSocket.setWantClientAuth(true);

        while (true) {
            try (SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept()) {

                printHandshakeResult(sslSocket.getSession());

                readRequest(sslSocket.getInputStream());

                sendResponse(sslSocket.getOutputStream());
            }
        }
    }

    private void printHandshakeResult(SSLSession sslSession) {
        if (sslSession.getLocalCertificates() != null) {
            System.out.println("Certificates sent by the server");
            Stream.of(sslSession.getLocalCertificates()).forEach(System.out::println);
        } else {
            System.out.println("No certificates were sent by the server");
        }

        try {
            System.out.println("Certificates sent by the client");
            Stream.of(sslSession.getPeerCertificates()).forEach(System.out::println);
        } catch (SSLPeerUnverifiedException e) {
            System.out.println("Client's identity has not been verified\n");
        }

    }

    private String readLine(InputStream in) throws IOException {
        StringBuilder bld = new StringBuilder();
        int ch;
        while ((ch = in.read()) >= 0 && (ch != '\n')) {
            if (ch != '\r')
                bld.append((char) ch);
        }
        return bld.toString();
    }

    private void readRequest(InputStream in) throws IOException {
        String line = readLine(in);
        while (line.length() != 0) {
            System.out.println("Request: " + line);
            line = readLine(in);
        }
    }

    private void sendResponse(OutputStream out) {
        PrintWriter pWrt = new PrintWriter(new OutputStreamWriter(out));
        pWrt.print("HTTP/1.1 200 OK\r\n");
        pWrt.print("Content-Type: application/json\r\n");
        pWrt.print("\r\n");
        pWrt.print("{\"Hello\": \"World\"}");
        pWrt.print("\r\n");
        pWrt.flush();
    }

    public static void main(String[] args) throws Exception {
        int port = 8888;
        String mainCertsPath = "bouncycastle-java-fips/certsFromUtils0/";

        HTTPSServerUsingHttpsURLConnection server =
                new HTTPSServerUsingHttpsURLConnection(port, mainCertsPath);

        server.recevie();

    }

}
