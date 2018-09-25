package com.malsolo.bcfipsin100.tls.https;

import com.github.tomakehurst.wiremock.WireMockServer;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.*;

@SuppressWarnings("WeakerAccess")
public class HTTPSServerUsingWiremock {

    private final int port;
    private final String certsPath;

    public HTTPSServerUsingWiremock(int port, String certsPath) {
        this.port = port;
        this.certsPath = certsPath;
    }

    public void receive() throws Exception {
        WireMockServer wireMockServer = new WireMockServer(
                options().dynamicPort() // No-args constructor defaults to port 8080
                        .httpsPort(this.port)
                        .keystorePath(this.certsPath + SERVER_STORE_NAME_JKS)
                        .keystorePassword(new String(SERVER_STORE_PASSWORD))
                        .keystoreType("JKS")
                        .trustStorePath(certsPath + TRUST_STORE_NAME)
                        .trustStorePassword(new String(TRUST_STORE_PASSWORD))
                        .trustStoreType("JKS")
                        .needClientAuth(true)
        );

        String resource = "/my/resource";

        wireMockServer.stubFor(get(urlEqualTo(resource))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-type", "application/json")
                        .withBody("{\"Hello\": \"World from Wiremock\"}")
                )
        );

        wireMockServer.start();

        HTTPSClientUsingHttpsURLConnection client =
                new HTTPSClientUsingHttpsURLConnection("localhost", this.port,
                        true, this.certsPath);

        System.out.println(client.invoke(resource));

        wireMockServer.stop();
    }

    public static void main(String[] args) throws Exception {
        int port = 8888;//9020;
        String certsPath = "bouncycastle-java-fips/certsFromUtils0/";

        HTTPSServerUsingWiremock server = new HTTPSServerUsingWiremock(port, certsPath);

        server.receive();
    }

}
