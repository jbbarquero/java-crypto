javax.net.ssl.SSLKeyException, "no cipher suites in common" or "Invalid signature on ECDH server key exchange message" with certificates created following the book.

Hello,

I'm trying to follow the examples from "Beginning Cryptography with Java" book using the code available in "Java Cryptography: Tools and Techniques", I want to create certificates, but the ones following the new book don't work.

My source code is available at https://github.com/jbbarquero/java-crypto/tree/master/beginning-java-crypto

The class CreateKeyStores (https://github.com/jbbarquero/java-crypto/blob/master/beginning-java-crypto/src/main/java/com/malsolo/crypto/tls/CreateKeyStores.java) creates the certificates as in the "Beginning Cryptography". I copied them to the https://github.com/jbbarquero/java-crypto/tree/master/beginning-java-crypto/certsFromUtils folder in order to use them from the classes SSLServerWithClientAuthIdExample and SSLClientWithClientAuthTrustExample (both available at https://github.com/jbbarquero/java-crypto/tree/master/beginning-java-crypto/src/main/java/com/malsolo/crypto/tls)

They work correctly.

But the class CreateKeyStores2 (https://github.com/jbbarquero/java-crypto/blob/master/beginning-java-crypto/src/main/java/com/malsolo/crypto/tls/CreateKeyStores2.java) tries to follow the new book without success. The generated certificates are located in https://github.com/jbbarquero/java-crypto/tree/mater/beginning-java-crypto/certsFromUtils2 and https://github.com/jbbarquero/java-crypto/tree/master/beginning-java-crypto/_certsFromUtils2_KeyPair_EC_SigAlg_SHA256withECDSA

The former ones where created with SHA256WithRSAEncryption (RSA pair generator) but they failed with "javax.net.ssl.SSLKeyException: Invalid signature on ECDH server key exchange message".

The later ones where created with  SHA256withECDSA (EC pair generator), as well as in the "Java Cryptography" book, but they failed with "SSL handshake failure: no cipher suites in common"

Thus, they don't work.

I had the "SSL handshake failure: no cipher suites in common" problem with a basic client and server where I failed with the "javax.net.ssl." system properties, but once I fixed it, everything worked.

I tried a lot with google, but I can't find a proper answer.

Can you help me with this problem?

Thank you very much in advance,
Javier.
