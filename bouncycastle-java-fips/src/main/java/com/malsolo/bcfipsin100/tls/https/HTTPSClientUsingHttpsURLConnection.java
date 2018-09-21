package com.malsolo.bcfipsin100.tls.https;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class HTTPSClientUsingHttpsURLConnection {

    private final String host;
    private final int port;

    public HTTPSClientUsingHttpsURLConnection(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /**
     * Invoke the endpoint for the configured host and port of the class.
     * @param endpoint should include the leading slash.
     * @return the response from the server as String.
     * @throws IOException if something went wrong.
     */
    public String invoke(String endpoint) throws IOException {


        String server = String.format("http://%s:%d%s", host, port, endpoint);
        URL url = new URL(server);

        URLConnection urlConnection = url.openConnection();

        StringBuilder sb = new StringBuilder();
        try (InputStream bis = new BufferedInputStream(urlConnection.getInputStream())) {
            Reader reader = new InputStreamReader(bis);
            int c;
            while ((c = reader.read()) != -1) {
                sb.append((char) c);
            }
        }

        System.out.printf("Response from server %s\n%s\n", server, sb.toString());

        return sb.toString();

    }

}
