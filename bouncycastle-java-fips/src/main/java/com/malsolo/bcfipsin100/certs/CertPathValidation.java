package com.malsolo.bcfipsin100.certs;

import com.malsolo.bcfipsin100.Setup;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.*;

public class CertPathValidation {

    public static PKIXCertPathValidatorResult validateCertPath(X509Certificate taCert, X509Certificate caCert, X509Certificate eeCert) throws GeneralSecurityException {
        List<X509Certificate> certchain = new ArrayList<>();

        certchain.add(eeCert);
        certchain.add(caCert);

        CertPath certPath = CertificateFactory.getInstance("X.509", Setup.PROVIDER).generateCertPath(certchain);

        Set<TrustAnchor> trust = new HashSet<>();
        trust.add(new TrustAnchor(taCert, null));

        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", Setup.PROVIDER);

        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date());

        return (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, param);
    }

}