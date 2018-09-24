package com.malsolo.bcfipsin100.tls.https;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.nio.file.Paths;

import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.*;
import static com.malsolo.bcfipsin100.tls.HTTPSUtil.createSSLContext;

@SuppressWarnings("WeakerAccess")
public class HTTPSClientUsingHttpsURLConnection {

    private final String host;
    private final int port;
    private final boolean https;
    private final String certsPath;

    public HTTPSClientUsingHttpsURLConnection(String host, int port, boolean https, String certsPath) {
        this.host = host;
        this.port = port;
        this.https = https;
        this.certsPath = certsPath;
    }

    /**
     * Invoke the endpoint for the configured host and port of the class.
     * @param endpoint should include the leading slash.
     * @return the response from the server as String.
     * @throws IOException if something went wrong.
     */
    public String invoke(String endpoint) throws Exception {


        String server = String.format("%s://%s:%d%s", https ? "https" : "http",
                host, port, endpoint);

        System.out.printf("Invoke server %s\n", server);

        SSLContext sslContext = createSSLContext(
                Paths.get(certsPath + CLIENT_STORE_NAME_P12).toFile(),
                CLIENT_STORE_PASSWORD,
                "PKCS12",
                Paths.get(certsPath + TRUST_STORE_NAME).toFile(),
                TRUST_STORE_PASSWORD,
                "JKS"
        );


        URL url = new URL(server);

        HttpsURLConnection httpsURLConnection = (HttpsURLConnection) url.openConnection();
        httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
        httpsURLConnection.setHostnameVerifier((host, sslSession) -> true);
        httpsURLConnection.connect();

        StringBuilder sb = new StringBuilder();
        try (InputStream bis = new BufferedInputStream(httpsURLConnection.getInputStream())) {
            Reader reader = new InputStreamReader(bis);
            int c;
            while ((c = reader.read()) != -1) {
                sb.append((char) c);
            }
        }

        System.out.printf("Response from server %s\n%s\n", server, sb.toString());

        return sb.toString();

    }

    public static void main(String[] args) throws Exception {
        int serverPort = 8888;//9020;
        String mainCertsPath = "bouncycastle-java-fips/certsFromUtils0/";

        HTTPSClientUsingHttpsURLConnection client =
                new HTTPSClientUsingHttpsURLConnection("localhost", serverPort,
                        true, mainCertsPath);

        System.out.println(client.invoke("/"));
    }

}
