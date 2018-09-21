package com.malsolo.bcfipsin100.tls.tls;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.malsolo.bcfipsin100.tls.https.HTTPSClientUsingHttpsURLConnection;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;


public class WireMockTest {

    private static final int SERVER_PORT = 8089;

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig()
            .port(SERVER_PORT) // No-args constructor defaults to port 8080
            .dynamicHttpsPort()
    );

    @Test
    public void exampleTest() throws Exception {

        String endPoint = "/my/resource";

        stubFor(get(urlEqualTo(endPoint))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-type", "application/json")
                        .withBody("{\"Hello\": \"World\"}")
                )
        );

        System.out.printf("Dynamic HTTPs PORT %d\n", wireMockRule.httpsPort());

        HTTPSClientUsingHttpsURLConnection client =
                new HTTPSClientUsingHttpsURLConnection("localhost", SERVER_PORT);

        String response = client.invoke(endPoint);

        assertThat(response).isNotNull().isEqualTo("{\"Hello\": \"World\"}");

        verify(getRequestedFor(urlMatching(endPoint)));

    }
}
