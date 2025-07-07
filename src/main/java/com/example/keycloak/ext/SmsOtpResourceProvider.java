package com.example.keycloak.ext;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.jboss.logging.Logger;

public class SmsOtpResourceProvider implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(SmsOtpResourceProvider.class);

    private final KeycloakSession session;

    public SmsOtpResourceProvider(KeycloakSession session) {
        LOG.info("SmsOtpResourceProvider: constructor called");
        this.session = session;
    }

    @Override
    public Object getResource() {
        LOG.info("getResource() called");
        return new SmsOtpEndpoint(session);
    }

    @Override
    public void close() {
        LOG.info("close() called");
    }
}
