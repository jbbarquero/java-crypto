package com.malsolo.bcfipsin100.tls.tls;

import com.github.tomakehurst.wiremock.junit.WireMockClassRule;
import com.malsolo.bcfipsin100.tls.https.HTTPSClientUsingHttpsURLConnection;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.malsolo.bcfipsin100.pbeks.CreateKeyStores3.*;
import static org.assertj.core.api.Assertions.assertThat;


public class WireMockTest {

    private static final String TEST_CERTS_PATH = "certsFromUtils0/";
    private static final String KEYSTORE_PATH = TEST_CERTS_PATH + CLIENT_STORE_NAME_P12;
    private static final String KEYSTORE_PASSWORD = new String(CLIENT_STORE_PASSWORD);
    private static final String TRUSTSTORE_PATH = TEST_CERTS_PATH + TRUST_STORE_NAME;
    private static final String TRUSTSTORE_PASSWORD = new String(TRUST_STORE_PASSWORD);

    @ClassRule //WireMock server continue to run between test cases
    public static WireMockClassRule wireMockClassRule = new WireMockClassRule(
            wireMockConfig()
                    .dynamicPort() // No-args constructor defaults to port 8080
                    .dynamicHttpsPort()
                    .keystorePath(KEYSTORE_PATH)
                    .keystorePassword(KEYSTORE_PASSWORD)
                    .keystoreType("PKCS12")
                    .trustStorePath(TRUSTSTORE_PATH)
                    .trustStorePassword(TRUSTSTORE_PASSWORD)
                    .trustStoreType("JKS")
    );

    @Rule
    public WireMockClassRule wireMockRule = wireMockClassRule;

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

        System.out.printf("HTTPS PORT: %d", wireMockRule.httpsPort());

        HTTPSClientUsingHttpsURLConnection client =
                new HTTPSClientUsingHttpsURLConnection("localhost", wireMockRule.port());

        String response = client.invoke(endPoint);

        assertThat(response).isNotNull().isEqualTo("{\"Hello\": \"World\"}");

        verify(getRequestedFor(urlMatching(endPoint)));

    }
}
