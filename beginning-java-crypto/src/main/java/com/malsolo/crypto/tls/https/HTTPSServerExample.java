package com.malsolo.crypto.tls.https;

import com.malsolo.crypto.tls.Constants;
import com.malsolo.crypto.tls.Utils;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Paths;
import java.security.Principal;

/**
 * Basic SSL Server with optional client authentication.
 */
public class HTTPSServerExample {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromUtils";

    /**
     * Read a HTTP request
     */
    private static void readRequest(InputStream in) throws IOException {
        System.out.print("Request: ");
        int ch;
        int lastCh = 0;
        while ((ch = in.read()) >= 0 && (ch != '\n' && lastCh != '\n')) {
            System.out.print((char)ch);
            if (ch != '\r')
                lastCh = ch;
        }

        System.out.println();
    }

    /**
     * Send a response
     */
    private static void sendResponse(OutputStream out) {
        PrintWriter pWrt = new PrintWriter(new OutputStreamWriter(out));
        pWrt.print("HTTP/1.1 200 OK\r\n");
        pWrt.print("Content-Type: text/html\r\n");
        pWrt.print("\r\n");
        pWrt.print("<html>\r\n");
        pWrt.print("<body>\r\n");
        pWrt.print("Hello World!\r\n");
        pWrt.print("</body>\r\n");
        pWrt.print("</html>\r\n");
        pWrt.flush();
    }

    public static void main(String[] args) throws Exception {
        SSLContext sslContext = SSLContextUtil.createSSLContext(
                new SSLContextInfo(
                        KeyStoreType.JKS,
                        Paths.get(CERTS_PATH + "/server.jks").toFile(),
                        Utils.SERVER_PASSWORD,
                        KeyStoreType.JKS,
                        Paths.get(CERTS_PATH + "/trustStore.jks").toFile(),
                        Utils.TRUST_STORE_PASSWORD
                )
        );

        SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
        SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(Constants.PORT_NO);

        // client authenticate where possible
        sSock.setWantClientAuth(true);

        for (;;) {
            SSLSocket sslSock = (SSLSocket)sSock.accept();

            try {
                sslSock.startHandshake();
            }
            catch (IOException e) {
                continue;
            }

            readRequest(sslSock.getInputStream());

            SSLSession session = sslSock.getSession();

            try {
                Principal clientID = session.getPeerPrincipal();

                System.out.println("client identified as: " + clientID);
            }
            catch (SSLPeerUnverifiedException e) {
                System.out.println("client not authenticated");
            }

            sendResponse(sslSock.getOutputStream());

            sslSock.close();
        }

    }
}
