package com.malsolo.crypto.tls.https;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;

public class SSLContextUtil {

    public static SSLContext createSSLContext(SSLContextInfo sslContextInfo) throws Exception {
        // set up a key manager for local credentials
        KeyManagerFactory mgrFact = KeyManagerFactory.getInstance("SunX509");
        KeyStore clientStore = KeyStore.getInstance(sslContextInfo.getKeyStoreType().name());

        clientStore.load(
                new FileInputStream(sslContextInfo.getKeyStoreFile()),
                sslContextInfo.getKeyStorePassword()
        );

        mgrFact.init(clientStore, sslContextInfo.getKeyStorePassword());

        // set up a trust manager to recognize the server
        TrustManagerFactory trustFact = TrustManagerFactory.getInstance("SunX509");
        KeyStore            trustStore = KeyStore.getInstance(sslContextInfo.getTrustStoreType().name());

        trustStore.load(
                new FileInputStream(sslContextInfo.getTrustStoreFile()),
                sslContextInfo.getTrustStorePassword()
        );

        trustFact.init(trustStore);

        // create a context and set up a socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);

        return sslContext;

    }
}
