package com.malsolo.crypto.tls.https;

import com.malsolo.crypto.tls.Constants;
import com.malsolo.crypto.tls.Utils;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Paths;

/**
 * SSL Client with client side authentication.
 */
public class HTTPSClientExample {

    private static final String CERTS_PATH = "beginning-java-crypto/certsFromUtils";

    /**
     * Verifier to check host has identified itself using "Test CA Certificate".
     */
    private static class Validator implements HostnameVerifier {
        public boolean verify(String hostName, SSLSession session) {
            try {
                X500Principal hostID = (X500Principal)session.getPeerPrincipal();

                return hostID.getName().equals("CN=Test CA Certificate");
            }
            catch (Exception e) {
                return false;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SSLContext sslContext = SSLContextUtil.createSSLContext(
                new SSLContextInfo(
                        KeyStoreType.PKCS12,
                        Paths.get(CERTS_PATH + "/client.p12").toFile(),
                        Utils.CLIENT_PASSWORD,
                        KeyStoreType.JKS,
                        Paths.get(CERTS_PATH + "/trustStore.jks").toFile(),
                        Utils.TRUST_STORE_PASSWORD
                )
        );

        SSLSocketFactory fact = sslContext.getSocketFactory();

        // specify the URL and connection attributes
        URL url = new URL("https://"+ Constants.HOST + ":" + Constants.PORT_NO);

        HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();

        connection.setSSLSocketFactory(fact);
        connection.setHostnameVerifier(new Validator());

        connection.connect();

        // read the response
        InputStream in = connection.getInputStream();

        int ch;
        while ((ch = in.read()) >= 0) {
            System.out.print((char)ch);
        }

    }

}
